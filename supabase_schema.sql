
create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  contact text,
  created_at timestamptz default now()
);

create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text not null,
  reward_paisa integer not null check (reward_paisa >= 0),
  is_active boolean default true,
  created_at timestamptz default now()
);

create table public.submissions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  task_id uuid references public.tasks(id),
  proof_text text not null,
  status text default 'pending'
    check (status in ('pending','approved','rejected')),
  created_at timestamptz default now(),
  unique(user_id, task_id)
);

create table public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  amount_paisa integer not null,
  kind text not null,
  status text default 'pending',
  created_at timestamptz default now()
);

create table public.withdrawal_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  method text not null
    check (method in ('jazzcash','easypaisa')),
  account_last4 text not null,
  amount_paisa integer not null check (amount_paisa > 0),
  status text default 'pending',
  created_at timestamptz default now()
);

alter table public.profiles enable row level security;
alter table public.tasks enable row level security;
alter table public.submissions enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.withdrawal_requests enable row level security;

create policy "Read own profile"
on public.profiles for select
to authenticated
using (auth.uid() = id);

create policy "Insert own profile"
on public.profiles for insert
to authenticated
with check (auth.uid() = id);

create policy "Read active tasks"
on public.tasks for select
to authenticated
using (is_active = true);

create policy "Read own submissions"
on public.submissions for select
to authenticated
using (auth.uid() = user_id);

create policy "Submit own tasks"
on public.submissions for insert
to authenticated
with check (
  auth.uid() = user_id and status = 'pending'
);

create policy "Read own transactions"
on public.wallet_transactions for select
to authenticated
using (auth.uid() = user_id);

create policy "Read own withdrawals"
on public.withdrawal_requests for select
to authenticated
using (auth.uid() = user_id);

create policy "Request own withdrawals"
on public.withdrawal_requests for insert
to authenticated
with check (
  auth.uid() = user_id and status = 'pending'
);
