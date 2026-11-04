-- Synthetic roles for the access inventory test (run as a superuser after postgresql.sql).
-- A group role with a member, a login account with a direct grant, a group without members.
CREATE ROLE crm_reader NOLOGIN;
GRANT SELECT ON customers TO crm_reader;
CREATE ROLE analyst1 LOGIN;            -- no password: the account cannot sign in
GRANT crm_reader TO analyst1;
CREATE ROLE app_user LOGIN;
GRANT SELECT ON customers TO app_user;
CREATE ROLE empty_group NOLOGIN;       -- no member: grants nothing to anyone
GRANT SELECT ON customers TO empty_group;
