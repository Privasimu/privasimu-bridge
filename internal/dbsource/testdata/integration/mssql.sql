-- Synthetic fixture for the integration tests (no real person).
-- CREATE USER bridge_ro FOR LOGIN bridge_ro; ALTER ROLE db_datareader ADD MEMBER bridge_ro;
IF OBJECT_ID('dbo.customers') IS NULL
CREATE TABLE dbo.customers (
  id      INT PRIMARY KEY,
  nik     VARCHAR(16),
  email   NVARCHAR(255),
  notes   NVARCHAR(MAX),
  balance DECIMAL(18, 2)
);
INSERT INTO dbo.customers SELECT * FROM (VALUES
  (1, '3171012303900001', N'budi.contoh@example.co.id', N'telepon 0812-3456-7890 setelah jam 5', 1000),
  (2, '3171016303900002', N'sari.contoh@example.co.id', N'hubungi 0813-1111-2222', 2000),
  (3, '3273011505850003', N'andi.contoh@example.co.id', N'nomor lain 0857-2222-3333', 3000),
  (4, '3578014107920004', N'dewi.contoh@example.co.id', N'wa 0821-4444-5555', 4000),
  (5, '5171012001880005', N'eko.contoh@example.co.id', N'telp 0811-6666-7777', 5000)
) v(id, nik, email, notes, balance) WHERE NOT EXISTS (SELECT 1 FROM dbo.customers);
