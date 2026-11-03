-- =====================================================================
-- 직원 가입 신청 + 관리자 승인 (여러 번 실행해도 안전)
--  · /staff 에서 직원이 직접 가입 신청 → 승인 전(applicant)에는 아무 데이터도 볼 수 없음
--  · 관리자가 앱에서 승인하면 직원(staff), 거절하면 계정이 삭제됨
--  · 끄려면: update public.app_settings set value = 'off' where key = 'open_staff_signup';
-- add_trainer.sql 을 먼저 실행한 DB 에서 실행하세요 (handle_new_user 를 이어서 교체합니다).
-- =====================================================================
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('member','staff','admin','applicant'));

insert into public.app_settings(key, value) values ('open_staff_signup', 'on') on conflict (key) do nothing;
create or replace function public.open_staff_signup_on() returns boolean
  language sql stable security definer set search_path = public as
$$ select coalesce((select value = 'on' from public.app_settings where key = 'open_staff_signup'), false) $$;

create or replace function public.handle_new_user() returns trigger
  language plpgsql security definer set search_path = public as
$$
declare
  tok text := lower(coalesce(new.raw_user_meta_data->>'invite', ''));
  lid text := lower(coalesce(new.raw_user_meta_data->>'login_id', ''));
  nm  text := btrim(coalesce(new.raw_user_meta_data->>'name', ''));
  br  text := coalesce(new.raw_user_meta_data->>'branch', '');
  asf text := coalesce(new.raw_user_meta_data->>'as_staff', '');
  inv public.invites;
  tr  uuid;
begin
  if lid !~ '^[a-z][a-z0-9_-]{3,15}$' then raise exception 'invalid_login_id'; end if;
  if split_part(coalesce(new.email, ''), '@', 1) <> lid then raise exception 'login_id_mismatch'; end if;
  if tok <> '' then
    select * into inv from public.invites where token = tok for update;
    if not found or inv.used_by is not null or inv.used_at is not null then raise exception 'invalid_invite'; end if;
    tr := null;
    if inv.role = 'member' and inv.created_by is not null then
      select p.id into tr from public.profiles p where p.id = inv.created_by and p.role = 'staff' and p.branch = inv.branch;
    end if;
    insert into public.profiles(id, login_id, name, branch, role, trainer_id) values (new.id, lid, inv.name, inv.branch, inv.role, tr);
    update public.invites set used_by = new.id, used_at = now() where token = tok;
  elsif asf = '1' then
    if not public.open_staff_signup_on() then raise exception 'invalid_invite'; end if;
    if char_length(nm) < 1 or char_length(nm) > 20 then raise exception 'invalid_name'; end if;
    if br not in ('mangpo', 'seocheon') then raise exception 'invalid_branch'; end if;
    insert into public.profiles(id, login_id, name, branch, role) values (new.id, lid, nm, br, 'applicant');
  else
    if not public.open_signup_on() then raise exception 'invalid_invite'; end if;
    if char_length(nm) < 1 or char_length(nm) > 20 then raise exception 'invalid_name'; end if;
    if br not in ('mangpo', 'seocheon') then raise exception 'invalid_branch'; end if;
    insert into public.profiles(id, login_id, name, branch, role) values (new.id, lid, nm, br, 'member');
  end if;
  return new;
end
$$;

-- 관리자만: 승인(p_ok=true → 직원) / 거절(p_ok=false → 계정 삭제)
create or replace function public.review_staff(p_id uuid, p_ok boolean) returns void
  language plpgsql security definer set search_path = public, auth as
$$
declare me public.profiles; t public.profiles;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or me.role <> 'admin' then raise exception 'forbidden'; end if;
  select * into t from public.profiles where id = p_id;
  if t.id is null or t.role <> 'applicant' then raise exception 'invalid_applicant'; end if;
  if p_ok then update public.profiles set role = 'staff' where id = p_id;
  else delete from auth.users where id = p_id;
  end if;
end
$$;

revoke execute on function public.open_staff_signup_on() from public;
grant execute on function public.open_staff_signup_on() to anon, authenticated;
revoke execute on function public.review_staff(uuid, boolean) from public, anon;
grant execute on function public.review_staff(uuid, boolean) to authenticated;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
