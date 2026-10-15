-- ============================================================
-- SHADS-ICTECH : Database Schema
-- ============================================================

create extension if not exists "pgcrypto";

-- ---------- LEADS (contact form submissions) ----------
create table if not exists public.leads (
  id           uuid primary key default gen_random_uuid(),
  full_name    text not null,
  phone        text not null,
  email        text,
  service      text,
  budget       text,
  message      text not null,
  status       text not null default 'new',   -- new | contacted | won | lost
  created_at   timestamptz not null default now()
);

create index if not exists leads_created_at_idx on public.leads (created_at desc);

alter table public.leads enable row level security;

-- Anyone (the public website) may SUBMIT a lead
drop policy if exists "public_can_insert_leads" on public.leads;
create policy "public_can_insert_leads"
  on public.leads for insert
  to anon
  with check (true);

-- Only logged-in admins may READ leads
drop policy if exists "admins_can_read_leads" on public.leads;
create policy "admins_can_read_leads"
  on public.leads for select
  to authenticated
  using (true);

-- Only admins may update / delete
drop policy if exists "admins_can_update_leads" on public.leads;
create policy "admins_can_update_leads"
  on public.leads for update
  to authenticated
  using (true) with check (true);

drop policy if exists "admins_can_delete_leads" on public.leads;
create policy "admins_can_delete_leads"
  on public.leads for delete
  to authenticated
  using (true);


-- ---------- NEWSLETTER (optional) ----------
create table if not exists public.subscribers (
  id         uuid primary key default gen_random_uuid(),
  email      text unique not null,
  created_at timestamptz not null default now()
);

alter table public.subscribers enable row level security;

drop policy if exists "public_can_subscribe" on public.subscribers;
create policy "public_can_subscribe"
  on public.subscribers for insert
  to anon
  with check (true);

drop policy if exists "admins_can_read_subscribers" on public.subscribers;
create policy "admins_can_read_subscribers"
  on public.subscribers for select
  to authenticated
  using (true);