// Synthetic fixture for the integration tests (no real person). mongosh <db> mongodb.js
db.customers.insertMany([
  { nik: "3171012303900001", email: "budi.contoh@example.co.id", notes: "telepon 0812-3456-7890 setelah jam 5" },
  { nik: "3171016303900002", email: "sari.contoh@example.co.id", notes: "hubungi 0813-1111-2222" },
  { nik: "3273011505850003", email: "andi.contoh@example.co.id", notes: "nomor lain 0857-2222-3333" },
  { nik: "3578014107920004", email: "dewi.contoh@example.co.id", notes: "wa 0821-4444-5555" },
  { nik: "5171012001880005", email: "eko.contoh@example.co.id", notes: "telp 0811-6666-7777" }
]);
