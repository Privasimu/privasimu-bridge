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
-- Offboarding: a person's login role turned NOLOGIN and granted to a successor. It is a
-- group role now, and its name is a person's: it must not leave unless role_names is plain.
CREATE ROLE budi_santoso LOGIN;
GRANT SELECT ON customers TO budi_santoso;
ALTER ROLE budi_santoso NOLOGIN;
CREATE ROLE successor1 LOGIN;
GRANT budi_santoso TO successor1;
