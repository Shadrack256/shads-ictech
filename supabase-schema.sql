-- ============================================================
-- SHADS-ICTECH : Complete Database Schema
-- Project: dbhlbifxejffhlkudlxr
-- Safe to run multiple times (idempotent).
-- ============================================================
-- Contents:
--   1. Extensions
--   2. leads table (website contact form)
--   3. subscribers table (optional newsletter)
--   4. profiles table (linked to auth.users)
--   5. Grants for anon + authenticated
--   6. Row Level Security + policies
--   7. handle_new_user() trigger
--   8. Schema cache reload
--   9. Verification queries
-- ============================================================


-- ------------------------------------------------------------
-- 1. EXTENSIONS
-- ------------------------------------------------------------
create extension if not exists "pgcrypto";


-- ------------------------------------------------------------
-- 2. LEADS TABLE
-- Stores every submission from the public website form.
-- ------------------------------------------------------------
create table if not exists public.leads (
  id           uuid primary key default gen_random_uuid(),
  full_name    text,
  phone        text,
  email        text,
  service      text,
  budget       text,
  message      text,
  status       text default 'new',
  created_at   timestamptz default now()
);

-- Ensure every column exists (in case the table was created earlier)
alter table public.leads
  add column if not exists full_name  text,
  add column if not exists phone      text,
  add column if not exists email      text,
  add column if not exists service    text,
  add column if not exists budget     text,
  add column if not exists message    text,
  add column if not exists status     text default 'new',
  add column if not exists created_at timestamptz default now();

-- Set defaults
alter table public.leads
  alter column status     set default 'new',
  alter column created_at set default now();

-- Fix any NULLs before adding NOT NULL constraints
update public.leads
  set full_name = coalesce(nullif(full_name, ''), 'Unknown')
  where full_name is null or full_name = '';

update public.leads
  set phone = coalesce(nullif(phone, ''), '0000000000')
  where phone is null or phone = '';

update public.leads
  set message = coalesce(nullif(message, ''), '(no message)')
  where message is null or message = '';

-- Enforce required fields
alter table public.leads
  alter column full_name set not null,
  alter column phone     set not null,
  alter column message   set not null;

-- Status must be one of these four values
alter table public.leads drop constraint if exists leads_status_check;
alter table public.leads
  add constraint leads_status_check
  check (status in ('new', 'contacted', 'won', 'lost'));

-- Indexes for faster queries
create index if not exists leads_created_at_idx on public.leads (created_at desc);
create index if not exists leads_status_idx     on public.leads (status);


-- ------------------------------------------------------------
-- 3. SUBSCRIBERS TABLE (optional newsletter)
-- ------------------------------------------------------------
create table if not exists public.subscribers (
  id         uuid primary key default gen_random_uuid(),
  email      text unique not null,
  created_at timestamptz not null default now()
);


-- ------------------------------------------------------------
-- 4. PROFILES TABLE
-- Auto-created for every auth user via the trigger below.
-- ------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text,
  phone       text,
  role        text default 'youth',
  created_at  timestamptz default now(),
  updated_at  timestamptz default now()
);

alter table public.profiles
  add column if not exists full_name  text,
  add column if not exists phone      text,
  add column if not exists role       text default 'youth',
  add column if not exists created_at timestamptz default now(),
  add column if not exists updated_at timestamptz default now();


-- ------------------------------------------------------------
-- 5. TABLE-LEVEL GRANTS
-- Without these, the anon role gets "permission denied" even
-- if RLS policies are in place.
-- ------------------------------------------------------------
grant usage on schema public to anon, authenticated;

-- leads
grant select, insert, update, delete on public.leads to anon, authenticated;

-- subscribers
grant select, insert, update, delete on public.subscribers to anon, authenticated;

-- profiles
grant select, insert, update, delete on public.profiles to anon, authenticated;

-- sequences (needed for inserts)
grant usage, select on all sequences in schema public to anon, authenticated;


-- ------------------------------------------------------------
-- 6. ROW LEVEL SECURITY + POLICIES
-- ------------------------------------------------------------

-- ---------- leads ----------
alter table public.leads enable row level security;

drop policy if exists "public_can_insert_leads" on public.leads;
drop policy if exists "admins_can_read_leads"   on public.leads;
drop policy if exists "admins_can_update_leads" on public.leads;
drop policy if exists "admins_can_delete_leads" on public.leads;

-- Anyone (public site) may SUBMIT a lead
create policy "public_can_insert_leads"
  on public.leads for insert
  to anon, authenticated
  with check (true);

-- Only logged-in admins may READ leads
create policy "admins_can_read_leads"
  on public.leads for select
  to authenticated
  using (true);

-- Only logged-in admins may UPDATE leads
create policy "admins_can_update_leads"
  on public.leads for update
  to authenticated
  using (true)
  with check (true);

-- Only logged-in admins may DELETE leads
create policy "admins_can_delete_leads"
  on public.leads for delete
  to authenticated
  using (true);


-- ---------- subscribers ----------
alter table public.subscribers enable row level security;

drop policy if exists "public_can_subscribe"        on public.subscribers;
drop policy if exists "admins_can_read_subscribers" on public.subscribers;

create policy "public_can_subscribe"
  on public.subscribers for insert
  to anon, authenticated
  with check (true);

create policy "admins_can_read_subscribers"
  on public.subscribers for select
  to authenticated
  using (true);


-- ---------- profiles ----------
alter table public.profiles enable row level security;

drop policy if exists "users_read_own_profile"   on public.profiles;
drop policy if exists "users_update_own_profile" on public.profiles;
drop policy if exists "public_insert_profiles"   on public.profiles;

-- Users can read their own profile
create policy "users_read_own_profile"
  on public.profiles for select
  to authenticated
  using (auth.uid() = id);

-- Users can update their own profile
create policy "users_update_own_profile"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Allow inserts (needed by the trigger)
create policy "public_insert_profiles"
  on public.profiles for insert
  to anon, authenticated
  with check (true);


-- ------------------------------------------------------------
-- 7. HANDLE_NEW_USER() TRIGGER
-- Runs automatically when a new row is inserted into auth.users.
-- Uses SECURITY DEFINER so it can write to public.profiles.
-- Wrapped in exception handling so a profile failure never
-- blocks user creation.
-- ------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, phone, role)
  values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'New user'),
    coalesce(new.phone, new.raw_user_meta_data ->> 'phone'),
    coalesce(new.raw_user_meta_data ->> 'role', 'youth')
  )
  on conflict (id) do nothing;

  return new;
exception
  when others then
    -- Never let a profile-creation failure block user signup
    raise warning 'handle_new_user failed: %', sqlerrm;
    return new;
end;
$$;

-- Recreate the trigger on auth.users
drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row
  execute function public.handle_new_user();


-- ------------------------------------------------------------
-- 8. FORCE SCHEMA CACHE RELOAD
-- Makes Supabase's API see the new columns / policies instantly
-- without needing a project restart.
-- ------------------------------------------------------------
notify pgrst, 'reload schema';


-- ------------------------------------------------------------
-- 9. VERIFICATION
-- Run these to confirm everything is set up correctly.
-- ------------------------------------------------------------

-- 9a. Columns on leads
select
  column_name,
  data_type,
  is_nullable,
  column_default
from information_schema.columns
where table_schema = 'public'
  and table_name   = 'leads'
order by ordinal_position;

-- 9b. Policies on leads / profiles / subscribers
select
  tablename,
  policyname,
  roles,
  cmd
from pg_policies
where tablename in ('leads', 'profiles', 'subscribers')
order by tablename, policyname;

-- 9c. Grants to anon on the leads table
select
  grantee,
  privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name   = 'leads'
  and grantee      = 'anon'
order by privilege_type;

-- 9d. Confirm the handle_new_user trigger is registered
select
  trigger_name,
  event_manipulation,
  event_object_table,
  action_statement
from information_schema.triggers
where trigger_name = 'on_auth_user_created';
