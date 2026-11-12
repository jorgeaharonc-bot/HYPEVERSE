-- NEONVERSE · Supabase/PostgreSQL
create extension if not exists pgcrypto;
create type public.neon_role as enum ('member','moderator','admin');
create table public.profiles(
 id uuid primary key references auth.users(id) on delete cascade,
 username text not null unique check(char_length(username) between 2 and 24),
 avatar_url text,
 role public.neon_role not null default 'member',
 banned_until timestamptz,
 ban_reason text,
 created_at timestamptz not null default now()
);
create table public.content_votes(
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 content_title text not null,
 content_type text not null check(content_type in ('Videojuego','Película','Serie')),
 value smallint not null check(value between 1 and 5),
 updated_at timestamptz not null default now(),
 unique(user_id,content_title)
);
create table public.comments(
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 content_title text not null,
 content_type text not null check(content_type in ('Videojuego','Película','Serie')),
 body text not null check(char_length(body) between 1 and 1000),
 created_at timestamptz not null default now(),
 deleted_at timestamptz
);
create table public.comment_likes(
 user_id uuid not null references public.profiles(id) on delete cascade,
 comment_id uuid not null references public.comments(id) on delete cascade,
 created_at timestamptz not null default now(),
 primary key(user_id,comment_id)
);
create table public.reports(
 id uuid primary key default gen_random_uuid(),
 reporter_id uuid not null references public.profiles(id) on delete cascade,
 reported_user uuid not null references public.profiles(id) on delete cascade,
 comment_id uuid references public.comments(id) on delete set null,
 reason text not null check(reason in ('spam','harassment','inappropriate','other')),
 details text,
 status text not null default 'pending' check(status in ('pending','reviewed','dismissed')),
 reviewed_by uuid references public.profiles(id),
 reviewed_at timestamptz,
 created_at timestamptz not null default now(),
 check(reporter_id<>reported_user)
);
create table public.sanctions(
 id uuid primary key default gen_random_uuid(),
 target_user uuid not null references public.profiles(id) on delete cascade,
 issued_by uuid not null references public.profiles(id),
 reason text not null,
 ends_at timestamptz,
 revoked_at timestamptz,
 revoked_by uuid references public.profiles(id),
 created_at timestamptz not null default now()
);
create or replace function public.is_staff() returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from public.profiles where id=auth.uid() and role='admin')
$$;
create or replace function public.is_banned() returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from public.profiles where id=auth.uid() and banned_until is not null and banned_until>now())
$$;
create or replace function public.create_profile() returns trigger language plpgsql security definer set search_path=public as $$
 begin
 insert into public.profiles(id,username) values(new.id,coalesce(nullif(new.raw_user_meta_data->>'username',''),split_part(new.email,'@',1)));
 return new;
 end $$;
create trigger neon_user_profile after insert on auth.users for each row execute procedure public.create_profile();
alter table public.profiles enable row level security;
alter table public.content_votes enable row level security;
alter table public.comments enable row level security;
alter table public.comment_likes enable row level security;
alter table public.reports enable row level security;
alter table public.sanctions enable row level security;
create policy "profiles public read" on public.profiles for select using(true);
revoke update on public.profiles from authenticated;
grant update(username,avatar_url) on public.profiles to authenticated;
create policy "profile owner edit" on public.profiles for update using(auth.uid()=id) with check(auth.uid()=id and role=(select p.role from public.profiles p where p.id=auth.uid()));
create policy "staff profile update" on public.profiles for update using(public.is_staff()) with check(public.is_staff());
create policy "votes public read" on public.content_votes for select using(true);
create policy "vote owner insert" on public.content_votes for insert with check(auth.uid()=user_id and not public.is_banned());
create policy "vote owner update" on public.content_votes for update using(auth.uid()=user_id and not public.is_banned()) with check(auth.uid()=user_id);
create policy "comments visible" on public.comments for select using(deleted_at is null or public.is_staff());
create policy "comment owner insert" on public.comments for insert with check(auth.uid()=user_id and not public.is_banned());
create policy "comment owner or staff update" on public.comments for update using(auth.uid()=user_id or public.is_staff()) with check(auth.uid()=user_id or public.is_staff());
create policy "comment owner or staff delete" on public.comments for delete using(auth.uid()=user_id or public.is_staff());
create policy "likes read" on public.comment_likes for select using(true);
create policy "likes own insert" on public.comment_likes for insert with check(auth.uid()=user_id and not public.is_banned());
create policy "likes own delete" on public.comment_likes for delete using(auth.uid()=user_id);
create policy "report create" on public.reports for insert with check(auth.uid()=reporter_id and not public.is_banned());
create policy "report owner or staff read" on public.reports for select using(auth.uid()=reporter_id or public.is_staff());
create policy "staff report update" on public.reports for update using(public.is_staff()) with check(public.is_staff());
create policy "sanction staff or target read" on public.sanctions for select using(auth.uid()=target_user or public.is_staff());
create policy "staff sanction insert" on public.sanctions for insert with check(public.is_staff() and auth.uid()=issued_by);
create policy "staff sanction update" on public.sanctions for update using(public.is_staff()) with check(public.is_staff());
create or replace function public.admin_set_ban(target uuid, reason text, duration_hours integer default null)
returns void language plpgsql security definer set search_path=public as $$
declare finish_at timestamptz;
begin
 if not public.is_staff() then raise exception 'Staff role required'; end if;
 if target=auth.uid() then raise exception 'Cannot sanction yourself'; end if;
 if duration_hours is not null and duration_hours<1 then raise exception 'Duration must be positive'; end if;
 finish_at:=case when duration_hours is null then 'infinity'::timestamptz else now()+make_interval(hours=>duration_hours) end;
 update public.profiles set banned_until=finish_at,ban_reason=reason where id=target;
 if not found then raise exception 'Profile not found'; end if;
 insert into public.sanctions(target_user,issued_by,reason,ends_at) values(target,auth.uid(),reason,case when duration_hours is null then null else finish_at end);
end $$;
create or replace function public.admin_unban(target uuid, reason text default 'Sanction removed')
returns void language plpgsql security definer set search_path=public as $$
begin
 if not public.is_staff() then raise exception 'Staff role required'; end if;
 update public.profiles set banned_until=null,ban_reason=null where id=target;
 update public.sanctions set revoked_at=now(),revoked_by=auth.uid() where target_user=target and revoked_at is null;
end $$;
grant execute on function public.admin_set_ban(uuid,text,integer) to authenticated;
grant execute on function public.admin_unban(uuid,text) to authenticated;
create index comments_content_created on public.comments(content_title,created_at desc);
create index reports_status_created on public.reports(status,created_at desc);
create index votes_content on public.content_votes(content_title);
-- After registering, assign the first admin in the SQL Editor:
-- update public.profiles set role='admin' where username='YOUR_USERNAME';

-- Salas comunitarias
create table if not exists public.room_messages (
 id uuid primary key default gen_random_uuid(),
 room_key text not null check (room_key in ('games','movies','series')),
 user_id uuid not null references public.profiles(id) on delete cascade,
 body text not null check (char_length(body) between 1 and 1000),
 created_at timestamptz not null default now(),
 deleted_at timestamptz
);
alter table public.room_messages enable row level security;
drop policy if exists "room messages visible" on public.room_messages;
create policy "room messages visible" on public.room_messages for select using (deleted_at is null or public.is_staff());
drop policy if exists "members post in rooms" on public.room_messages;
create policy "members post in rooms" on public.room_messages for insert with check (auth.uid()=user_id and not public.is_banned());
drop policy if exists "authors or staff update room messages" on public.room_messages;
create policy "authors or staff update room messages" on public.room_messages for update using (auth.uid()=user_id or public.is_staff()) with check (auth.uid()=user_id or public.is_staff());
create index if not exists room_messages_recent on public.room_messages(room_key,created_at desc) where deleted_at is null;

-- Encuestas creadas por la comunidad, con publicación sujeta a moderación
create table if not exists public.community_polls (
 id uuid primary key default gen_random_uuid(),
 creator_id uuid not null references public.profiles(id) on delete cascade,
 question text not null check (char_length(question) between 8 and 150),
 options text[] not null check (cardinality(options) between 2 and 5),
 status text not null default 'pending' check (status in ('pending','approved','rejected')),
 created_at timestamptz not null default now(),
 reviewed_by uuid references public.profiles(id),
 reviewed_at timestamptz
);
create table if not exists public.community_poll_votes (
 poll_id uuid not null references public.community_polls(id) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 option_index smallint not null check (option_index between 0 and 4),
 created_at timestamptz not null default now(),
 primary key (poll_id,user_id)
);
alter table public.community_polls enable row level security;
alter table public.community_poll_votes enable row level security;
drop policy if exists "approved polls or own pending visible" on public.community_polls;
create policy "approved polls or own pending visible" on public.community_polls for select using (status='approved' or auth.uid()=creator_id or public.is_staff());
drop policy if exists "members submit pending polls" on public.community_polls;
create policy "members submit pending polls" on public.community_polls for insert with check (auth.uid()=creator_id and status='pending' and reviewed_by is null and not public.is_banned());
drop policy if exists "staff moderate polls" on public.community_polls;
create policy "staff moderate polls" on public.community_polls for update using (public.is_staff()) with check (public.is_staff() and (status='approved' or status='rejected') and reviewed_by=auth.uid());
drop policy if exists "community poll totals visible" on public.community_poll_votes;
create policy "community poll totals visible" on public.community_poll_votes for select using (true);
drop policy if exists "members vote once on approved polls" on public.community_poll_votes;
create policy "members vote once on approved polls" on public.community_poll_votes for insert with check (auth.uid()=user_id and not public.is_banned() and exists(select 1 from public.community_polls p where p.id=community_poll_votes.poll_id and p.status='approved' and community_poll_votes.option_index < cardinality(p.options)));
create index if not exists community_polls_status_created on public.community_polls(status,created_at desc);
create unique index if not exists community_polls_one_pending_per_creator on public.community_polls(creator_id) where status='pending';
create unique index if not exists community_polls_unique_active_question on public.community_polls(lower(trim(question))) where status in ('pending','approved');

-- Listas personales y elementos privados
create table if not exists public.user_lists (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 name text not null check (char_length(name) between 2 and 40),
 is_default boolean not null default false,
 created_at timestamptz not null default now(),
 unique(user_id,name)
);
create table if not exists public.list_entries (
 list_id uuid not null references public.user_lists(id) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 content_title text not null,
 content_type text not null check(content_type in ('Videojuego','Película','Serie')),
 added_at timestamptz not null default now(),
 primary key(list_id,content_title)
);
alter table public.user_lists enable row level security;
alter table public.list_entries enable row level security;
drop policy if exists "owners manage personal lists" on public.user_lists;
create policy "owners manage personal lists" on public.user_lists for all using(auth.uid()=user_id) with check(auth.uid()=user_id and not public.is_banned());
drop policy if exists "owners manage list entries" on public.list_entries;
create policy "owners manage list entries" on public.list_entries for all using(auth.uid()=user_id and exists(select 1 from public.user_lists l where l.id=list_id and l.user_id=auth.uid())) with check(auth.uid()=user_id and exists(select 1 from public.user_lists l where l.id=list_id and l.user_id=auth.uid()) and not public.is_banned());
create index if not exists list_entries_recent on public.list_entries(list_id,added_at desc);

-- Favoritos públicos en perfiles
alter table public.profiles add column if not exists favorite_titles text[] not null default '{}'::text[];
revoke update on public.profiles from authenticated;
grant update(username,avatar_url,favorite_titles) on public.profiles to authenticated;

-- Clubes de fans y publicaciones
create table if not exists public.fan_clubs (
 club_key text primary key,
 title text not null,
 description text not null,
 created_at timestamptz not null default now()
);
insert into public.fan_clubs(club_key,title,description) values
 ('gears','Gears of War','Debate campañas, personajes y el futuro de la saga.'),
 ('fortnite','Fortnite','Comparte estrategias, temporadas y momentos de escuadra.'),
 ('star-wars','Star Wars','Teorías, películas, series y galaxias muy lejanas.')
on conflict(club_key) do nothing;
create table if not exists public.fan_club_members (
 club_key text not null references public.fan_clubs(club_key) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 joined_at timestamptz not null default now(),
 primary key(club_key,user_id)
);
create table if not exists public.fan_club_posts (
 id uuid primary key default gen_random_uuid(),
 club_key text not null references public.fan_clubs(club_key) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 body text not null check(char_length(body) between 1 and 1000),
 created_at timestamptz not null default now(),
 deleted_at timestamptz
);
alter table public.fan_clubs enable row level security;
alter table public.fan_club_members enable row level security;
alter table public.fan_club_posts enable row level security;
drop policy if exists "fan clubs public read" on public.fan_clubs;
create policy "fan clubs public read" on public.fan_clubs for select using(true);
drop policy if exists "club membership public read" on public.fan_club_members;
create policy "club membership public read" on public.fan_club_members for select using(true);
drop policy if exists "join fan clubs" on public.fan_club_members;
create policy "join fan clubs" on public.fan_club_members for insert with check(auth.uid()=user_id and not public.is_banned());
drop policy if exists "leave fan clubs" on public.fan_club_members;
create policy "leave fan clubs" on public.fan_club_members for delete using(auth.uid()=user_id);
drop policy if exists "club posts public read" on public.fan_club_posts;
create policy "club posts public read" on public.fan_club_posts for select using(deleted_at is null or public.is_staff());
drop policy if exists "members post in clubs" on public.fan_club_posts;
create policy "members post in clubs" on public.fan_club_posts for insert with check(auth.uid()=user_id and not public.is_banned() and exists(select 1 from public.fan_club_members m where m.club_key=fan_club_posts.club_key and m.user_id=auth.uid()));
drop policy if exists "authors or staff moderate club posts" on public.fan_club_posts;
create policy "authors or staff moderate club posts" on public.fan_club_posts for update using(auth.uid()=user_id or public.is_staff()) with check(auth.uid()=user_id or public.is_staff());
create index if not exists fan_club_posts_recent on public.fan_club_posts(club_key,created_at desc) where deleted_at is null;
