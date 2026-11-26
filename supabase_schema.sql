
-- =====================================================
-- CRAZY GRAPHIX - DATABASE STARTER
-- Existing tasks.reward_paisa is preserved.
-- Reward values are treated as rupees, as in the app.
-- =====================================================

create extension if not exists pgcrypto;

-- 1. PROFILES
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  created_at timestamptz not null default now()
);

-- 2. TASKS
create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null unique,
  description text not null,
  reward integer not null check (reward > 0),
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Migrate the old tasks table safely.
alter table public.tasks
add column if not exists reward integer;

do $$
begin
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'tasks'
      and column_name = 'reward_paisa'
  ) then
    execute '
      update public.tasks
      set reward = reward_paisa
      where reward is null
    ';
  end if;
end $$;

-- Stop safely if any old task has no reward value.
do $$
begin
  if exists (
    select 1 from public.tasks where reward is null or reward <= 0
  ) then
    raise exception
      'Some existing tasks have missing or invalid rewards. Review tasks before continuing.';
  end if;
end $$;

alter table public.tasks
alter column reward set not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'cg_tasks_reward_positive'
      and conrelid = 'public.tasks'::regclass
  ) then
    alter table public.tasks
    add constraint cg_tasks_reward_positive check (reward > 0);
  end if;
end $$;

-- 3. SUBMISSIONS
create table if not exists public.submissions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  task_id uuid not null references public.tasks(id),
  proof text not null,
  status text not null default 'pending'
    check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz,
  unique (user_id, task_id)
);

-- 4. WALLET LEDGER
create table if not exists public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  amount integer not null check (amount <> 0),
  kind text not null,
  reference_id uuid,
  created_at timestamptz not null default now(),
  unique (kind, reference_id)
);

-- 5. WITHDRAWAL REQUESTS
create table if not exists public.withdrawal_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  amount integer not null check (amount >= 100),
  method text not null check (method in ('JazzCash','Easypaisa')),
  account_number text not null,
  status text not null default 'pending'
    check (status in ('pending','paid','rejected')),
  created_at timestamptz not null default now(),
  processed_at timestamptz
);

-- 6. CREATE PROFILE WHEN A USER SIGNS UP
create or replace function public.handle_cg_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'display_name', '')
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists cg_new_user on auth.users;

create trigger cg_new_user
after insert on auth.users
for each row
execute procedure public.handle_cg_new_user();

-- 7. ADMIN CHECK
create or replace function public.is_cg_admin()
returns boolean
language sql
stable
as $$
  select coalesce(
    auth.jwt()->'app_metadata'->>'role',
    ''
  ) = 'admin';
$$;

-- 8. ENABLE ROW LEVEL SECURITY
alter table public.profiles enable row level security;
alter table public.tasks enable row level security;
alter table public.submissions enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.withdrawal_requests enable row level security;

-- 9. PROFILE POLICIES
drop policy if exists cg_profile_select on public.profiles;
create policy cg_profile_select
on public.profiles
for select to authenticated
using (id = auth.uid() or public.is_cg_admin());

drop policy if exists cg_profile_update on public.profiles;
create policy cg_profile_update
on public.profiles
for update to authenticated
using (id = auth.uid())
with check (id = auth.uid());

-- 10. TASK POLICIES
drop policy if exists cg_tasks_read on public.tasks;
create policy cg_tasks_read
on public.tasks
for select to anon, authenticated
using (is_active or public.is_cg_admin());

drop policy if exists cg_tasks_admin on public.tasks;
create policy cg_tasks_admin
on public.tasks
for all to authenticated
using (public.is_cg_admin())
with check (public.is_cg_admin());

-- 11. SUBMISSION POLICIES
drop policy if exists cg_submissions_read on public.submissions;
create policy cg_submissions_read
on public.submissions
for select to authenticated
using (user_id = auth.uid() or public.is_cg_admin());

drop policy if exists cg_submissions_insert on public.submissions;
create policy cg_submissions_insert
on public.submissions
for insert to authenticated
with check (
  user_id = auth.uid()
  and status = 'pending'
);

-- 12. WALLET POLICIES
drop policy if exists cg_wallet_read on public.wallet_transactions;
create policy cg_wallet_read
on public.wallet_transactions
for select to authenticated
using (user_id = auth.uid() or public.is_cg_admin());

-- 13. WITHDRAWAL POLICIES
drop policy if exists cg_withdrawals_read on public.withdrawal_requests;
create policy cg_withdrawals_read
on public.withdrawal_requests
for select to authenticated
using (user_id = auth.uid() or public.is_cg_admin());

-- 14. REQUEST WITHDRAWAL
create or replace function public.request_withdrawal(
  p_amount integer,
  p_method text,
  p_account_number text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
  bal bigint;
  reserved bigint;
  rid uuid;
begin
  if uid is null then
    raise exception 'Login required';
  end if;

  if p_amount is null or p_amount < 100 then
    raise exception 'Minimum withdrawal is Rs 100';
  end if;

  if p_method not in ('JazzCash','Easypaisa') then
    raise exception 'Invalid payment method';
  end if;

  if p_account_number !~ '^03[0-9]{9}$' then
    raise exception 'Invalid Pakistani mobile number';
  end if;

  perform pg_advisory_xact_lock(hashtext(uid::text));

  select coalesce(sum(amount), 0)
  into bal
  from public.wallet_transactions
  where user_id = uid;

  select coalesce(sum(amount), 0)
  into reserved
  from public.withdrawal_requests
  where user_id = uid
    and status = 'pending';

  if p_amount > bal - reserved then
    raise exception 'Insufficient available balance';
  end if;

  insert into public.withdrawal_requests (
    user_id, amount, method, account_number
  )
  values (
    uid, p_amount, p_method, p_account_number
  )
  returning id into rid;

  return rid;
end;
$$;

-- 15. ADMIN APPROVES OR REJECTS A TASK
create or replace function public.admin_review_submission(
  p_submission_id uuid,
  p_approve boolean
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  s public.submissions%rowtype;
  r integer;
begin
  if not public.is_cg_admin() then
    raise exception 'Admin access required';
  end if;

  select *
  into s
  from public.submissions
  where id = p_submission_id
  for update;

  if not found or s.status <> 'pending' then
    raise exception 'Submission missing or already reviewed';
  end if;

  if p_approve then
    select reward
    into r
    from public.tasks
    where id = s.task_id;

    if r is null then
      raise exception 'Task reward not found';
    end if;

    update public.submissions
    set status = 'approved',
        reviewed_at = now()
    where id = s.id;

    insert into public.wallet_transactions (
      user_id, amount, kind, reference_id
    )
    values (
      s.user_id, r, 'task_reward', s.id
    );
  else
    update public.submissions
    set status = 'rejected',
        reviewed_at = now()
    where id = s.id;
  end if;
end;
$$;

-- 16. ADMIN PROCESSES WITHDRAWAL
create or replace function public.admin_process_withdrawal(
  p_withdrawal_id uuid,
  p_paid boolean
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  w public.withdrawal_requests%rowtype;
begin
  if not public.is_cg_admin() then
    raise exception 'Admin access required';
  end if;

  select *
  into w
  from public.withdrawal_requests
  where id = p_withdrawal_id
  for update;

  if not found or w.status <> 'pending' then
    raise exception 'Request missing or already processed';
  end if;

  if p_paid then
    -- Only call this after the external payment is actually sent.
    insert into public.wallet_transactions (
      user_id, amount, kind, reference_id
    )
    values (
      w.user_id, -w.amount, 'withdrawal_paid', w.id
    );

    update public.withdrawal_requests
    set status = 'paid',
        processed_at = now()
    where id = w.id;
  else
    update public.withdrawal_requests
    set status = 'rejected',
        processed_at = now()
    where id = w.id;
  end if;
end;
$$;

-- 17. FUNCTION PERMISSIONS
revoke all on function
  public.request_withdrawal(integer,text,text)
  from public;

revoke all on function
  public.admin_review_submission(uuid,boolean)
  from public;

revoke all on function
  public.admin_process_withdrawal(uuid,boolean)
  from public;

grant execute on function
  public.request_withdrawal(integer,text,text)
  to authenticated;

grant execute on function
  public.admin_review_submission(uuid,boolean)
  to authenticated;

grant execute on function
  public.admin_process_withdrawal(uuid,boolean)
  to authenticated;

-- 18. FOUR SAMPLE TASKS
insert into public.tasks (title, description, reward)
values
(
  'Poster Design Brief',
  'ایک فرضی کاروباری پوسٹر کے لیے 3 مختصر tagline تجاویز لکھیں۔',
  50
),
(
  'Product Description',
  'کسی عام اسٹیشنری آئٹم کی 60 الفاظ کی واضح تفصیل لکھیں۔',
  40
),
(
  'Logo Idea',
  'ایک فرضی بیکری کے لیے لوگو کا تخلیقی تصور بیان کریں۔',
  75
),
(
  'Data Entry Sample',
  'پانچ فرضی مصنوعات کے نام اور قیمتیں ایک فہرست میں لکھیں۔',
  30
)
on conflict (title) do nothing;

-- END OF CRAZY GRAPHIX DATABASE SETUP
