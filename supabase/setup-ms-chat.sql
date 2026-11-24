-- MS Study hidden chat (Phase 5). One room per chat code (room_id = hash of code).
-- Max 2 members per room (enforced in the Edge Function). Messages delete both sides.
create table if not exists public.ms_chat_rooms (
  id text primary key,
  code_hash text not null,
  members jsonb not null default '[]'::jsonb,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists public.ms_chat_messages (
  id uuid primary key default gen_random_uuid(),
  room_id text not null references public.ms_chat_rooms (id) on delete cascade,
  sender_device text not null,
  body text not null,
  reply_to uuid references public.ms_chat_messages (id) on delete set null,
  created_at timestamptz default now()
);
create index if not exists ms_chat_messages_room_created_idx on public.ms_chat_messages (room_id, created_at);

create table if not exists public.ms_chat_presence (
  room_id text not null references public.ms_chat_rooms (id) on delete cascade,
  device_id text not null,
  last_seen timestamptz default now(),
  primary key (room_id, device_id)
);

alter table public.ms_chat_rooms enable row level security;
alter table public.ms_chat_messages enable row level security;
alter table public.ms_chat_presence enable row level security;

-- No anon/authenticated access: only the Edge Function (service_role) touches these.
grant select, insert, update, delete on public.ms_chat_rooms, public.ms_chat_messages, public.ms_chat_presence to service_role;
