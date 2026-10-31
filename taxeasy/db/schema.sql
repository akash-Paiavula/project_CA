create extension if not exists pgcrypto;
create table users(
  id uuid primary key default gen_random_uuid(),
  name text not null, email text unique not null, mobile text unique not null,
  auth_hash text not null, role text not null default 'employee',
  pubkey text, priv_wrapped_pw text, priv_wrapped_rec text,
  email_verified bool default false, mobile_verified bool default false,
  created_at timestamptz default now());
create table filings(
  id uuid primary key default gen_random_uuid(), user_id uuid references users(id),
  assessment_year text not null, status text not null default 'Registered',
  created_at timestamptz default now(), unique(user_id, assessment_year));
create table payments(
  id uuid primary key default gen_random_uuid(), filing_id uuid references filings(id),
  rzp_order_id text unique, rzp_payment_id text, amount_paise int not null,
  status text not null default 'created', created_at timestamptz default now());
create table files(
  id uuid primary key default gen_random_uuid(), filing_id uuid references filings(id),
  kind text not null, name text, path text not null, iv text, wkey text, size bigint,
  created_at timestamptz default now());
create table otps(
  id bigserial primary key, target text not null, hash text not null,
  attempts int default 0, used bool default false, expires_at timestamptz not null);
create table audit_log(
  id bigserial primary key, actor uuid, action text, target text, ip text, at timestamptz default now());
