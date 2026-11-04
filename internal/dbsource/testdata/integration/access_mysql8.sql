-- Synthetic roles for the access inventory test on MySQL 8.0.18+ (run as root after
-- mysql.sql; MariaDB uses access_mysql.sql). On MySQL a role is a locked account, and any
-- account can be granted to another like a role: only locked accounts may be named.
CREATE ROLE IF NOT EXISTS crm_reader;
GRANT SELECT ON bridge_it.customers TO crm_reader;
-- RANDOM PASSWORD: the accounts can sign in (they are not locked), but nobody knows how.
CREATE USER IF NOT EXISTS 'analyst1'@'%' IDENTIFIED BY RANDOM PASSWORD;
GRANT crm_reader TO 'analyst1'@'%';
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY RANDOM PASSWORD;
GRANT SELECT ON bridge_it.* TO 'app'@'%';
-- A person's account granted to another account: both are readers, neither is named.
CREATE USER IF NOT EXISTS 'budi.santoso'@'%' IDENTIFIED BY RANDOM PASSWORD;
GRANT SELECT ON bridge_it.customers TO 'budi.santoso'@'%';
CREATE USER IF NOT EXISTS 'intern1'@'%' IDENTIFIED BY RANDOM PASSWORD;
GRANT 'budi.santoso'@'%' TO 'intern1'@'%';
-- The account that may see the grants (BRIDGE_IT_MYSQL_ACCESS_USER), without password hashes:
-- CREATE USER 'bridge_grants'@'127.0.0.1' IDENTIFIED BY '<password>';
-- GRANT SELECT, SHOW VIEW ON bridge_it.* TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT ON mysql.db TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT ON mysql.tables_priv TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT ON mysql.role_edges TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT (Host, User, Select_priv, Super_priv, account_locked) ON mysql.user TO 'bridge_grants'@'127.0.0.1';
