-- Synthetic fixture for the integration tests (no real person). Run as an owner in the
-- test database, then: GRANT SELECT ON bridge_it.* TO bridge_ro;
CREATE TABLE IF NOT EXISTS customers (
  id      UInt32,
  nik     String,
  email   String,
  notes   String,
  balance Decimal(18, 2)
) ENGINE = MergeTree ORDER BY id;
INSERT INTO customers VALUES
  (1, '3171012303900001', 'budi.contoh@example.co.id', 'telepon 0812-3456-7890 setelah jam 5', 1000),
  (2, '3171016303900002', 'sari.contoh@example.co.id', 'hubungi 0813-1111-2222', 2000),
  (3, '3273011505850003', 'andi.contoh@example.co.id', 'nomor lain 0857-2222-3333', 3000),
  (4, '3578014107920004', 'dewi.contoh@example.co.id', 'wa 0821-4444-5555', 4000),
  (5, '5171012001880005', 'eko.contoh@example.co.id', 'telp 0811-6666-7777', 5000);
