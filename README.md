# Crazy Graphix — MVP Starter

## Included
- `index.html`: responsive mobile/web demo with Home, Tasks, Wallet, Profile and Admin Preview.
- `supabase_schema.sql`: starter database schema and basic user-scoped Row Level Security policies.

## Run the demo
Open `index.html` in a browser. Demo data is saved in that browser's local storage.
The demo approval control is intentionally not secure and is only for preview/testing.

## Before a real public launch
1. Create a Supabase project and apply/review `supabase_schema.sql`.
2. Connect Supabase Auth and replace localStorage demo logic with authenticated database calls.
3. Implement task review, wallet crediting, and withdrawal approval in trusted server-side functions/Edge Functions.
4. Add verified admin roles, audit logs, rate limits, anti-fraud checks, privacy policy, terms, and support contact.
5. For JazzCash/Easypaisa, use the official merchant/payment onboarding process and approved API/integration. Do not collect or store MPIN, OTP, PIN, or passwords. A withdrawal request is not a payment.
6. Test with no real money first. Have a parent/guardian or qualified adult oversee payment-provider accounts and legal/compliance requirements.

## Important
This is a prototype, not a live earning service. The sample rewards are illustrative only. It does not connect to a bank, JazzCash, Easypaisa, or any real payment rail. Do not publish the demo Admin Preview as a secure admin panel.
