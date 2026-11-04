-- Synthetic roles for the access inventory test (MariaDB 10.4+, run as root after mysql.sql;
-- MySQL 8 uses access_mysql8.sql). On MariaDB a role (is_role) can never sign in, and only
-- roles can be granted, so the locked test accounts below are still counted as readers.
CREATE ROLE IF NOT EXISTS crm_reader;
GRANT SELECT ON bridge_it.customers TO crm_reader;
CREATE USER IF NOT EXISTS 'analyst1'@'%' ACCOUNT LOCK;
GRANT crm_reader TO 'analyst1'@'%';
CREATE USER IF NOT EXISTS 'app'@'%' ACCOUNT LOCK;
GRANT SELECT ON bridge_it.* TO 'app'@'%';
-- The account that may see the grants (BRIDGE_IT_MYSQL_ACCESS_USER), without password hashes:
-- CREATE USER 'bridge_grants'@'127.0.0.1' IDENTIFIED BY '<password>';
-- GRANT SELECT, SHOW VIEW ON bridge_it.* TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT ON mysql.db TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT ON mysql.tables_priv TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT ON mysql.roles_mapping TO 'bridge_grants'@'127.0.0.1';
-- GRANT SELECT (Host, User, Select_priv, Super_priv, is_role) ON mysql.user TO 'bridge_grants'@'127.0.0.1';
