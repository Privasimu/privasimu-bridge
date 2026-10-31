-- Synthetic fixture for the integration tests (no real person). Run as the schema owner
-- the test connects to (or grant SELECT on CUSTOMERS to the bridge account and set
-- BRIDGE_IT_ORACLE_SCHEMA to the owner).
CREATE TABLE customers (
  id      NUMBER(10) PRIMARY KEY,
  nik     VARCHAR2(16),
  email   VARCHAR2(255),
  notes   CLOB,
  balance NUMBER(18, 2)
);
INSERT INTO customers VALUES (1, '3171012303900001', 'budi.contoh@example.co.id', 'telepon 0812-3456-7890 setelah jam 5', 1000);
INSERT INTO customers VALUES (2, '3171016303900002', 'sari.contoh@example.co.id', 'hubungi 0813-1111-2222', 2000);
INSERT INTO customers VALUES (3, '3273011505850003', 'andi.contoh@example.co.id', 'nomor lain 0857-2222-3333', 3000);
INSERT INTO customers VALUES (4, '3578014107920004', 'dewi.contoh@example.co.id', 'wa 0821-4444-5555', 4000);
INSERT INTO customers VALUES (5, '5171012001880005', 'eko.contoh@example.co.id', 'telp 0811-6666-7777', 5000);
COMMIT;
