require("dotenv").config();


const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();

const app = express();

const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";

const DB_FILE =
  path.join(__dirname, "localstore.db");

const UPLOAD_DIR =
  path.join(__dirname, "uploads");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin: process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(",").map(x => x.trim())
      : true
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/uploads", express.static(UPLOAD_DIR));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/", limiter);

// ============================================================
// DATABASE
// ============================================================

const db = new sqlite3.Database(DB_FILE);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);

      resolve({
        id: this.lastID,
        changes: this.changes
      });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function transaction(callback) {
  return new Promise(async (resolve, reject) => {
    try {
      await run("BEGIN TRANSACTION");

      const result = await callback();

      await run("COMMIT");

      resolve(result);
    } catch (error) {
      try {
        await run("ROLLBACK");
      } catch (_) {}

      reject(error);
    }
  });
}

// ============================================================
// DATABASE INIT
// ============================================================

async function initDatabase() {
  await run("PRAGMA foreign_keys = ON");

  await run(`
    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mobile TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      pin_hash TEXT NOT NULL,
      mobile_verified INTEGER DEFAULT 0,
      blocked INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS stores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id TEXT UNIQUE NOT NULL,
      store_name TEXT NOT NULL,
      owner_name TEXT,
      mobile TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      mobile_verified INTEGER DEFAULT 0,
      status TEXT DEFAULT 'ON',
      blocked INTEGER DEFAULT 0,
      rent_amount REAL DEFAULT 500,
      rent_expiry TEXT,
      commission_rate REAL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS store_admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id TEXT NOT NULL,
      name TEXT NOT NULL,
      mobile TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'STORE_ADMIN',
      active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(store_id, mobile)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id TEXT NOT NULL,
      name TEXT NOT NULL,
      mobile TEXT,
      role TEXT DEFAULT 'STAFF',
      salary REAL DEFAULT 0,
      active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      staff_id INTEGER NOT NULL,
      store_id TEXT NOT NULL,
      date TEXT NOT NULL,
      check_in TEXT,
      check_out TEXT,
      status TEXT DEFAULT 'PRESENT',
      UNIQUE(staff_id, date)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id TEXT NOT NULL,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      stock REAL DEFAULT 0,
      unit TEXT DEFAULT 'piece',
      image TEXT DEFAULT '',
      active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_no TEXT UNIQUE NOT NULL,
      customer_id INTEGER NOT NULL,
      store_id TEXT NOT NULL,
      payment_method TEXT DEFAULT 'COD',
      payment_status TEXT DEFAULT 'PENDING',
      status TEXT DEFAULT 'PENDING',
      total REAL NOT NULL,
      cancel_reason TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      item_id INTEGER,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      quantity REAL NOT NULL,
      unit TEXT
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS khata (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id TEXT NOT NULL,
      customer_mobile TEXT NOT NULL,
      customer_name TEXT,
      amount REAL NOT NULL,
      type TEXT NOT NULL,
      note TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id TEXT NOT NULL,
      title TEXT NOT NULL,
      amount REAL NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS rent_payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id TEXT NOT NULL,
      amount REAL NOT NULL,
      days INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mobile TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT DEFAULT 'SUPER_ADMIN',
      blocked INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS system_settings (
      id INTEGER PRIMARY KEY,
      admin_upi TEXT DEFAULT '',
      commission_rate REAL DEFAULT 0,
      default_rent REAL DEFAULT 500
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mobile TEXT NOT NULL,
      purpose TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      attempts INTEGER DEFAULT 0,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_type TEXT NOT NULL,
      user_id TEXT NOT NULL,
      title TEXT,
      message TEXT,
      read_status INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    INSERT OR IGNORE INTO system_settings
    (id, admin_upi, commission_rate, default_rent)
    VALUES (1, '', 0, 500)
  `);
}

// ============================================================
// HELPERS
// ============================================================

function mobile(value) {
  return String(value || "")
    .replace(/\D/g, "")
    .slice(-10);
}

function money(value) {
  const n = Number(value);

  if (!Number.isFinite(n) || n < 0) {
    return null;
  }

  return n;
}

function orderNumber() {
  return (
    "LS-" +
    Date.now().toString(36).toUpperCase() +
    "-" +
    crypto.randomBytes(3).toString("hex").toUpperCase()
  );
}

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES || "7d"
  });
}

// ============================================================
// AUTH
// ============================================================

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const token = header.slice(7);

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function role(...allowed) {
  return (req, res, next) => {
    if (!req.user || !allowed.includes(req.user.role)) {
      return res.status(403).json({
        error: "Permission denied"
      });
    }

    next();
  };
}

// ============================================================
// OTP
// ============================================================

async function sendOTP(mobileNumber, purpose) {
  const otp =
    process.env.NODE_ENV === "production"
      ? String(Math.floor(100000 + Math.random() * 900000))
      : "123456";

  const hash = await bcrypt.hash(otp, 10);

  await run(
    `
    UPDATE otp_codes
    SET used=1
    WHERE mobile=? AND purpose=? AND used=0
    `,
    [mobileNumber, purpose]
  );

  await run(
    `
    INSERT INTO otp_codes
    (mobile, purpose, otp_hash, expires_at)
    VALUES (?, ?, ?, ?)
    `,
    [
      mobileNumber,
      purpose,
      hash,
      Date.now() + 5 * 60 * 1000
    ]
  );

  // Production SMS provider goes here.
  // Twilio / MSG91 / Fast2SMS can be connected here.

  console.log(
    `[OTP] ${mobileNumber} / ${purpose}: ${otp}`
  );

  return {
    success: true,
    message: "OTP sent"
  };
}

async function verifyOTP(
  mobileNumber,
  purpose,
  otp
) {
  const row = await get(
    `
    SELECT *
    FROM otp_codes
    WHERE mobile=?
      AND purpose=?
      AND used=0
    ORDER BY id DESC
    LIMIT 1
    `,
    [mobileNumber, purpose]
  );

  if (!row) {
    return {
      success: false,
      error: "OTP not found"
    };
  }

  if (Date.now() > row.expires_at) {
    return {
      success: false,
      error: "OTP expired"
    };
  }

  if (row.attempts >= 5) {
    return {
      success: false,
      error: "Too many attempts"
    };
  }

  const valid = await bcrypt.compare(
    String(otp),
    row.otp_hash
  );

  if (!valid) {
    await run(
      `
      UPDATE otp_codes
      SET attempts=attempts+1
      WHERE id=?
      `,
      [row.id]
    );

    return {
      success: false,
      error: "Invalid OTP"
    };
  }

  await run(
    `
    UPDATE otp_codes
    SET used=1
    WHERE id=?
    `,
    [row.id]
  );

  return {
    success: true
  };
}

// ============================================================
// UPLOAD
// ============================================================

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,

    filename: (req, file, cb) => {
      const ext =
        path.extname(file.originalname).toLowerCase();

      cb(
        null,
        Date.now() +
          "-" +
          crypto.randomBytes(8).toString("hex") +
          ext
      );
    }
  }),

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const ok =
      /^image\/(jpeg|jpg|png|webp)$/i.test(
        file.mimetype
      );

    cb(
      ok
        ? null
        : new Error(
            "Only JPG, PNG and WEBP images allowed"
          ),
      ok
    );
  }
});

// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "LocalStore Backend",
    version: "3.0.0",
    onlinePayment: false,
    time: new Date().toISOString()
  });
});

// ============================================================
// CUSTOMER REGISTER
// ============================================================

app.post(
  "/api/customer/send-otp",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);

      if (!/^\d{10}$/.test(m)) {
        return res.status(400).json({
          error: "Valid 10 digit mobile required"
        });
      }

      await sendOTP(m, "CUSTOMER_REGISTER");

      res.json({
        message: "OTP sent"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

app.post(
  "/api/customer/register",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);
      const name = String(req.body.name || "").trim();
      const pin = String(req.body.pin || "");
      const otp = String(req.body.otp || "");

      if (
        !/^\d{10}$/.test(m) ||
        !name ||
        !/^\d{4,8}$/.test(pin) ||
        !/^\d{6}$/.test(otp)
      ) {
        return res.status(400).json({
          error:
            "Mobile, name, PIN and OTP required"
        });
      }

      const verified = await verifyOTP(
        m,
        "CUSTOMER_REGISTER",
        otp
      );

      if (!verified.success) {
        return res.status(400).json(verified);
      }

      const exists = await get(
        "SELECT id FROM customers WHERE mobile=?",
        [m]
      );

      if (exists) {
        return res.status(409).json({
          error: "Customer already exists"
        });
      }

      const hash = await bcrypt.hash(pin, 12);

      const result = await run(
        `
        INSERT INTO customers
        (mobile,name,pin_hash,mobile_verified)
        VALUES (?,?,?,1)
        `,
        [m, name, hash]
      );

      const customer = await get(
        `
        SELECT id,mobile,name,blocked,mobile_verified,created_at
        FROM customers
        WHERE id=?
        `,
        [result.id]
      );

      const token = createToken({
        id: customer.id,
        mobile: customer.mobile,
        role: "CUSTOMER",
        type: "customer"
      });

      res.status(201).json({
        customer,
        token
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// CUSTOMER LOGIN
// ============================================================

app.post(
  "/api/customer/login",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);
      const pin = String(req.body.pin || "");

      const customer = await get(
        "SELECT * FROM customers WHERE mobile=?",
        [m]
      );

      if (
        !customer ||
        !(await bcrypt.compare(
          pin,
          customer.pin_hash
        ))
      ) {
        return res.status(401).json({
          error: "Invalid mobile or PIN"
        });
      }

      if (customer.blocked) {
        return res.status(403).json({
          error: "Customer blocked"
        });
      }

      const token = createToken({
        id: customer.id,
        mobile: customer.mobile,
        role: "CUSTOMER",
        type: "customer"
      });

      res.json({
        customer: {
          id: customer.id,
          mobile: customer.mobile,
          name: customer.name
        },
        token
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// CUSTOMER FORGOT PIN
// ============================================================

app.post(
  "/api/customer/forgot-password",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);

      const customer = await get(
        "SELECT id FROM customers WHERE mobile=?",
        [m]
      );

      if (!customer) {
        return res.status(404).json({
          error: "Customer not found"
        });
      }

      await sendOTP(m, "CUSTOMER_RESET");

      res.json({
        message: "Reset OTP sent"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

app.post(
  "/api/customer/reset-password",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);
      const otp = String(req.body.otp || "");
      const newPin = String(req.body.newPin || "");

      if (
        !/^\d{6}$/.test(otp) ||
        !/^\d{4,8}$/.test(newPin)
      ) {
        return res.status(400).json({
          error:
            "Valid OTP and new PIN required"
        });
      }

      const verified = await verifyOTP(
        m,
        "CUSTOMER_RESET",
        otp
      );

      if (!verified.success) {
        return res.status(400).json(verified);
      }

      const hash = await bcrypt.hash(
        newPin,
        12
      );

      const result = await run(
        `
        UPDATE customers
        SET pin_hash=?
        WHERE mobile=?
        `,
        [hash, m]
      );

      if (!result.changes) {
        return res.status(404).json({
          error: "Customer not found"
        });
      }

      res.json({
        message: "PIN reset successful"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// CUSTOMER PROFILE
// ============================================================

app.get(
  "/api/customer/profile",
  auth,
  role("CUSTOMER"),
  async (req, res) => {
    const customer = await get(
      `
      SELECT id,name,mobile,mobile_verified,created_at
      FROM customers
      WHERE id=?
      `,
      [req.user.id]
    );

    res.json({
      customer
    });
  }
);

// ============================================================
// STORE REGISTER OTP
// ============================================================

app.post(
  "/api/store/send-otp",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);

      if (!/^\d{10}$/.test(m)) {
        return res.status(400).json({
          error: "Valid mobile required"
        });
      }

      await sendOTP(m, "STORE_REGISTER");

      res.json({
        message: "OTP sent"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE REGISTER
// ============================================================

app.post(
  "/api/store/register",
  async (req, res) => {
    try {
      const storeId =
        String(req.body.storeId || "").trim();

      const storeName =
        String(req.body.storeName || "").trim();

      const ownerName =
        String(req.body.ownerName || "").trim();

      const m = mobile(req.body.mobile);

      const password =
        String(req.body.password || "");

      const otp =
        String(req.body.otp || "");

      if (
        !storeId ||
        !storeName ||
        !/^\d{10}$/.test(m) ||
        password.length < 6 ||
        !/^\d{6}$/.test(otp)
      ) {
        return res.status(400).json({
          error:
            "Store details, mobile, password and OTP required"
        });
      }
      const verified = await verifyOTP(
        m,
        "STORE_REGISTER",
        otp
      );

      if (!verified.success) {
        return res.status(400).json(verified);
      }

      const exists = await get(
        `
        SELECT id
        FROM stores
        WHERE store_id=? OR mobile=?
        `,
        [storeId, m]
      );

      if (exists) {
        return res.status(409).json({
          error:
            "Store ID or mobile already exists"
        });
      }

      const settings = await get(
        "SELECT * FROM system_settings WHERE id=1"
      );

      const hash = await bcrypt.hash(
        password,
        12
      );

      const result = await run(
        `
        INSERT INTO stores
        (
          store_id,
          store_name,
          owner_name,
          mobile,
          password_hash,
          mobile_verified,
          status,
          rent_amount,
          commission_rate
        )
        VALUES (?,?,?,?,?,1,'ON',?,?)
        `,
        [
          storeId,
          storeName,
          ownerName,
          m,
          hash,
          settings.default_rent,
          settings.commission_rate
        ]
      );

      await run(
        `
        INSERT INTO store_admins
        (store_id,name,mobile,password_hash)
        VALUES (?,?,?,?)
        `,
        [
          storeId,
          ownerName || storeName,
          m,
          hash
        ]
      );

      const store = await get(
        `
        SELECT
          id,store_id,store_name,owner_name,
          mobile,status,rent_amount,
          rent_expiry,commission_rate
        FROM stores
        WHERE id=?
        `,
        [result.id]
      );

      res.status(201).json({
        message:
          "Store and Store Admin created",
        store
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE LOGIN
// ============================================================

app.post(
  "/api/store/login",
  async (req, res) => {
    try {
      const storeId =
        String(req.body.storeId || "").trim();

      const password =
        String(req.body.password || "");

      const store = await get(
        "SELECT * FROM stores WHERE store_id=?",
        [storeId]
      );

      if (
        !store ||
        !(await bcrypt.compare(
          password,
          store.password_hash
        ))
      ) {
        return res.status(401).json({
          error:
            "Invalid Store ID or password"
        });
      }

      if (store.blocked) {
        return res.status(403).json({
          error: "Store blocked"
        });
      }

      if (store.status !== "ON") {
        return res.status(403).json({
          error: "Store is OFF"
        });
      }

      const token = createToken({
        id: store.id,
        mobile: store.mobile,
        role: "STORE",
        type: "store",
        storeId: store.store_id
      });

      res.json({
        store: {
          id: store.id,
          store_id: store.store_id,
          store_name: store.store_name,
          owner_name: store.owner_name,
          mobile: store.mobile,
          status: store.status,
          rent_amount: store.rent_amount,
          rent_expiry: store.rent_expiry
        },
        token
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE ADMIN LOGIN
// ============================================================

app.post(
  "/api/store-admin/login",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);

      const password =
        String(req.body.password || "");

      const admin = await get(
        `
        SELECT *
        FROM store_admins
        WHERE mobile=?
          AND active=1
        LIMIT 1
        `,
        [m]
      );

      if (
        !admin ||
        !(await bcrypt.compare(
          password,
          admin.password_hash
        ))
      ) {
        return res.status(401).json({
          error: "Invalid Store Admin login"
        });
      }

      const store = await get(
        "SELECT * FROM stores WHERE store_id=?",
        [admin.store_id]
      );

      if (!store || store.blocked) {
        return res.status(403).json({
          error: "Store unavailable"
        });
      }

      const token = createToken({
        id: admin.id,
        mobile: admin.mobile,
        role: "STORE_ADMIN",
        type: "store_admin",
        storeId: admin.store_id
      });

      res.json({
        admin: {
          id: admin.id,
          name: admin.name,
          mobile: admin.mobile,
          storeId: admin.store_id
        },
        token
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE SEARCH
// ============================================================

app.get(
  "/api/store/search/:storeId",
  async (req, res) => {
    try {
      const store = await get(
        `
        SELECT
          store_id,
          store_name,
          owner_name,
          status,
          blocked
        FROM stores
        WHERE store_id=?
        `,
        [req.params.storeId]
      );

      if (!store) {
        return res.status(404).json({
          error: "Store not found"
        });
      }

      res.json({
        store
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// PUBLIC PRODUCTS
// ============================================================

app.get(
  "/api/store/:storeId/items",
  async (req, res) => {
    try {
      const store = await get(
        `
        SELECT
          store_id,
          store_name,
          status,
          blocked
        FROM stores
        WHERE store_id=?
        `,
        [req.params.storeId]
      );

      if (!store) {
        return res.status(404).json({
          error: "Store not found"
        });
      }

      const items = await all(
        `
        SELECT *
        FROM items
        WHERE store_id=?
          AND active=1
        ORDER BY id DESC
        `,
        [req.params.storeId]
      );

      res.json({
        store,
        items
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADD PRODUCT
// ============================================================

app.post(
  "/api/store/item",
  auth,
  role("STORE", "STORE_ADMIN"),
  upload.single("image"),
  async (req, res) => {
    try {
      const name =
        String(req.body.name || "").trim();

      const price = money(req.body.price);
      const stock = money(req.body.stock);

      const unit =
        String(req.body.unit || "piece");

      if (
        !name ||
        price === null ||
        stock === null
      ) {
        return res.status(400).json({
          error:
            "Name, price and stock required"
        });
      }

      const image = req.file
        ? `/uploads/${req.file.filename}`
        : "";

      const result = await run(
        `
        INSERT INTO items
        (store_id,name,price,stock,unit,image)
        VALUES (?,?,?,?,?,?)
        `,
        [
          req.user.storeId,
          name,
          price,
          stock,
          unit,
          image
        ]
      );

      const item = await get(
        "SELECT * FROM items WHERE id=?",
        [result.id]
      );

      res.status(201).json({
        item
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// UPDATE PRODUCT
// ============================================================

app.put(
  "/api/store/item/:id",
  auth,
  role("STORE", "STORE_ADMIN"),
  upload.single("image"),
  async (req, res) => {
    try {
      const item = await get(
        "SELECT * FROM items WHERE id=?",
        [req.params.id]
      );

      if (!item) {
        return res.status(404).json({
          error: "Item not found"
        });
      }

      if (
        item.store_id !==
        req.user.storeId
      ) {
        return res.status(403).json({
          error: "Permission denied"
        });
      }

      const name =
        String(
          req.body.name ?? item.name
        ).trim();

      const price =
        money(
          req.body.price ?? item.price
        );

      const stock =
        money(
          req.body.stock ?? item.stock
        );

      const unit =
        String(
          req.body.unit ?? item.unit
        );

      const image = req.file
        ? `/uploads/${req.file.filename}`
        : item.image;

      await run(
        `
        UPDATE items
        SET name=?,price=?,stock=?,unit=?,image=?
        WHERE id=?
        `,
        [
          name,
          price,
          stock,
          unit,
          image,
          item.id
        ]
      );

      res.json({
        item: await get(
          "SELECT * FROM items WHERE id=?",
          [item.id]
        )
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// DELETE PRODUCT
// ============================================================

app.delete(
  "/api/store/item/:id",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const item = await get(
        "SELECT * FROM items WHERE id=?",
        [req.params.id]
      );

      if (!item) {
        return res.status(404).json({
          error: "Item not found"
        });
      }

      if (
        item.store_id !==
        req.user.storeId
      ) {
        return res.status(403).json({
          error: "Permission denied"
        });
      }

      await run(
        "UPDATE items SET active=0 WHERE id=?",
        [item.id]
      );

      res.json({
        message: "Item deleted"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// CUSTOMER CREATE COD ORDER
// ============================================================

app.post(
  "/api/order/create",
  auth,
  role("CUSTOMER"),
  async (req, res) => {
    try {
      const storeId =
        String(req.body.storeId || "").trim();

      const items =
        Array.isArray(req.body.items)
          ? req.body.items
          : [];

      if (!storeId || !items.length) {
        return res.status(400).json({
          error:
            "Store and items required"
        });
      }

      const store = await get(
        `
        SELECT *
        FROM stores
        WHERE store_id=?
          AND status='ON'
          AND blocked=0
        `,
        [storeId]
      );

      if (!store) {
        return res.status(400).json({
          error: "Store unavailable"
        });
      }

      const result = await transaction(
        async () => {
          let total = 0;
          const normalized = [];

          for (const cartItem of items) {
            const item = await get(
              `
              SELECT *
              FROM items
              WHERE id=?
                AND store_id=?
                AND active=1
              `,
              [
                Number(
                  cartItem.itemId ||
                  cartItem.id
                ),
                storeId
              ]
            );

            const quantity =
              Number(cartItem.quantity);

            if (!item) {
              throw new Error(
                "Item unavailable"
              );
            }

            if (
              !Number.isFinite(quantity) ||
              quantity <= 0
            ) {
              throw new Error(
                "Invalid quantity"
              );
            }

            if (
              quantity >
              Number(item.stock)
            ) {
              throw new Error(
                `${item.name}: stock only ${item.stock}`
              );
            }

            total +=
              Number(item.price) *
              quantity;

            normalized.push({
              item,
              quantity
            });
          }

          const orderNo =
            orderNumber();

          const order = await run(
            `
            INSERT INTO orders
            (
              order_no,
              customer_id,
              store_id,
              payment_method,
              payment_status,
              status,
              total
            )
            VALUES (?,?,?,'COD','NOT_REQUIRED','PENDING',?)
            `,
            [
              orderNo,
              req.user.id,
              storeId,
              total
            ]
          );

          for (const x of normalized) {
            await run(
              `
              INSERT INTO order_items
              (
                order_id,
                item_id,
                name,
                price,
                quantity,
                unit
              )
              VALUES (?,?,?,?,?,?)
              `,
              [
                order.id,
                x.item.id,
                x.item.name,
                x.item.price,
                x.quantity,
                x.item.unit
              ]
            );

            const updated = await run(
              `
              UPDATE items
              SET stock=stock-?
              WHERE id=?
                AND stock>=?
              `,
              [
                x.quantity,
                x.item.id,
                x.quantity
              ]
            );

            if (!updated.changes) {
              throw new Error(
                "Stock changed. Please try again."
              );
            }
          }

          return {
            id: order.id,
            orderNo
          };
        }
      );

      res.status(201).json({
        message: "COD order created",
        order: await get(
          "SELECT * FROM orders WHERE id=?",
          [result.id]
        )
      });
    } catch (e) {
      res.status(400).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// CUSTOMER ORDER HISTORY
// ============================================================

app.get(
  "/api/customer/orders",
  auth,
  role("CUSTOMER"),
  async (req, res) => {
    try {
      const orders = await all(
        `
        SELECT
          o.*,
          s.store_name
        FROM orders o
        LEFT JOIN stores s
          ON s.store_id=o.store_id
        WHERE o.customer_id=?
        ORDER BY o.id DESC
        `,
        [req.user.id]
      );

      res.json({
        orders
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ORDER DETAILS
// ============================================================

app.get(
  "/api/order/:orderNo",
  auth,
  async (req, res) => {
    try {
      const order = await get(
        `
        SELECT *
        FROM orders
        WHERE order_no=?
        `,
        [req.params.orderNo]
      );

      if (!order) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      if (
        req.user.role === "CUSTOMER" &&
        Number(order.customer_id) !==
          Number(req.user.id)
      ) {
        return res.status(403).json({
          error: "Permission denied"
        });
      }

      if (
        req.user.storeId &&
        req.user.storeId !==
          order.store_id
      ) {
        return res.status(403).json({
          error: "Permission denied"
        });
      }

      const items = await all(
        `
        SELECT *
        FROM order_items
        WHERE order_id=?
        `,
        [order.id]
      );

      res.json({
        order,
        items
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE ORDERS
// ============================================================

app.get(
  "/api/store/orders",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const orders = await all(
        `
        SELECT
          o.*,
          c.name customer_name,
          c.mobile customer_mobile
        FROM orders o
        LEFT JOIN customers c
          ON c.id=o.customer_id
        WHERE o.store_id=?
        ORDER BY o.id DESC
        `,
        [req.user.storeId]
      );

      res.json({
        orders
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// APPROVE ORDER
// ============================================================

app.post(
  "/api/order/:orderNo/approve",
  auth,
  role(
    "STORE",
    "STORE_ADMIN",
    "SUPER_ADMIN"
  ),
  async (req, res) => {
    try {
      const order = await get(
        "SELECT * FROM orders WHERE order_no=?",
        [req.params.orderNo]
      );

      if (!order) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      if (
        req.user.storeId &&
        req.user.storeId !==
          order.store_id
      ) {
        return res.status(403).json({
          error: "Permission denied"
        });
      }

      if (
        order.status !== "PENDING"
      ) {
        return res.status(400).json({
          error:
            "Only pending order can be approved"
        });
      }

      await run(
        `
        UPDATE orders
        SET status='APPROVED'
        WHERE order_no=?
        `,
        [order.order_no]
      );

      res.json({
        message: "Order approved"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// CANCEL ORDER
// ============================================================

app.post(
  "/api/order/:orderNo/cancel",
  auth,
  async (req, res) => {
    try {
      const order = await get(
        "SELECT * FROM orders WHERE order_no=?",
        [req.params.orderNo]
      );

      if (!order) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      if (
        req.user.role === "CUSTOMER" &&
        Number(req.user.id) !==
          Number(order.customer_id)
      ) {
        return res.status(403).json({
          error: "Permission denied"
        });
      }

      if (
        req.user.storeId &&
        req.user.storeId !==
          order.store_id
      ) {
        return res.status(403).json({
          error: "Permission denied"
        });
      }

      if (
        order.status === "CANCELLED"
      ) {
        return res.status(400).json({
          error: "Already cancelled"
        });
      }

      await transaction(
        async () => {
          const rows = await all(
            `
            SELECT item_id,quantity
            FROM order_items
            WHERE order_id=?
            `,
            [order.id]
          );

          for (const row of rows) {
            if (row.item_id) {
              await run(
                `
                UPDATE items
                SET stock=stock+?
                WHERE id=?
                `,
                [
                  row.quantity,
                  row.item_id
                ]
              );
            }
          }

          await run(
            `
            UPDATE orders
            SET
              status='CANCELLED',
              cancel_reason=?
            WHERE id=?
            `,
            [
              String(
                req.body.reason ||
                "Cancelled"
              ),
              order.id
            ]
          );
        }
      );

      res.json({
        message:
          "Order cancelled and stock restored"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE KHATA ADD
// ============================================================

app.post(
  "/api/store/khata",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const cm =
        mobile(req.body.customerMobile);

      const name =
        String(
          req.body.customerName || ""
        ).trim();

      const amount =
        money(req.body.amount);

      const type =
        String(
          req.body.type || "DUE"
        ).toUpperCase();

      if (
        !/^\d{10}$/.test(cm) ||
        amount === null ||
        !["DUE", "PAYMENT"].includes(type)
      ) {
        return res.status(400).json({
          error: "Invalid Khata data"
        });
      }

      const result = await run(
        `
        INSERT INTO khata
        (
          store_id,
          customer_mobile,
          customer_name,
          amount,
          type,
          note
        )
        VALUES (?,?,?,?,?,?)
        `,
        [
          req.user.storeId,
          cm,
          name,
          amount,
          type,
          String(req.body.note || "")
        ]
      );

      res.status(201).json({
        khata: await get(
          "SELECT * FROM khata WHERE id=?",
          [result.id]
        )
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// CUSTOMER BAKI / KHATA
// ============================================================

app.get(
  "/api/customer/khata",
  auth,
  role("CUSTOMER"),
  async (req, res) => {
    try {
      const rows = await all(
        `
        SELECT
          k.*,
          s.store_name
        FROM khata k
        LEFT JOIN stores s
          ON s.store_id=k.store_id
        WHERE k.customer_mobile=?
        ORDER BY k.id DESC
        `,
        [req.user.mobile]
      );

      let totalDue = 0;

      for (const row of rows) {
        if (row.type === "DUE") {
          totalDue += Number(row.amount);
        } else {
          totalDue -= Number(row.amount);
        }
      }

      res.json({
        totalDue,
        entries: rows
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE KHATA
// ============================================================

app.get(
  "/api/store/khata",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const rows = await all(
        `
        SELECT *
        FROM khata
        WHERE store_id=?
        ORDER BY id DESC
        `,
        [req.user.storeId]
      );

      let due = 0;

      for (const row of rows) {
        if (row.type === "DUE") {
          due += Number(row.amount);
        } else {
          due -= Number(row.amount);
        }
      }

      res.json({
        totalDue: due,
        khata: rows
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// EXPENSE
// ============================================================

app.post(
  "/api/store/expense",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const title =
        String(req.body.title || "").trim();

      const amount =
        money(req.body.amount);

      if (!title || amount === null) {
        return res.status(400).json({
          error:
            "Title and amount required"
        });
      }

      const result = await run(
        `
        INSERT INTO expenses
        (store_id,title,amount)
        VALUES (?,?,?)
        `,
        [
          req.user.storeId,
          title,
          amount
        ]
      );

      res.status(201).json({
        expense: await get(
          "SELECT * FROM expenses WHERE id=?",
          [result.id]
        )
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

app.get(
  "/api/store/expenses",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    const expenses = await all(
      `
      SELECT *
      FROM expenses
      WHERE store_id=?
      ORDER BY id DESC
      `,
      [req.user.storeId]
    );

    res.json({
      expenses
    });
  }
);

// ============================================================
// STAFF ADD
// ============================================================

app.post(
  "/api/store/staff",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const name =
        String(req.body.name || "").trim();

      if (!name) {
        return res.status(400).json({
          error: "Staff name required"
        });
      }

      const result = await run(
        `
        INSERT INTO staff
        (
          store_id,
          name,
          mobile,
          role,
          salary
        )
        VALUES (?,?,?,?,?)
        `,
        [
          req.user.storeId,
          name,
          mobile(req.body.mobile),
          String(
            req.body.role || "STAFF"
          ),
          Number(req.body.salary || 0)
        ]
      );

res.status(201).json({
        staff: await get(
          "SELECT * FROM staff WHERE id=?",
          [result.id]
        )
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STAFF LIST
// ============================================================

app.get(
  "/api/store/staff",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    const staff = await all(
      `
      SELECT *
      FROM staff
      WHERE store_id=?
      ORDER BY id DESC
      `,
      [req.user.storeId]
    );

    res.json({
      staff
    });
  }
);

// ============================================================
// STAFF ATTENDANCE
// ============================================================

app.post(
  "/api/store/attendance",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const staffId =
        Number(req.body.staffId);

      const date =
        String(
          req.body.date ||
          new Date()
            .toISOString()
            .slice(0, 10)
        );

      const staff = await get(
        `
        SELECT *
        FROM staff
        WHERE id=?
          AND store_id=?
        `,
        [
          staffId,
          req.user.storeId
        ]
      );

      if (!staff) {
        return res.status(404).json({
          error: "Staff not found"
        });
      }

      const existing = await get(
        `
        SELECT *
        FROM attendance
        WHERE staff_id=?
          AND date=?
        `,
        [
          staffId,
          date
        ]
      );

      if (existing) {
        if (existing.check_out) {
          return res.status(400).json({
            error:
              "Attendance already completed"
          });
        }

        await run(
          `
          UPDATE attendance
          SET check_out=CURRENT_TIMESTAMP
          WHERE id=?
          `,
          [existing.id]
        );

        return res.json({
          message:
            "Check-out recorded"
        });
      }

      await run(
        `
        INSERT INTO attendance
        (
          staff_id,
          store_id,
          date,
          check_in,
          status
        )
        VALUES (?,?,?,CURRENT_TIMESTAMP,'PRESENT')
        `,
        [
          staffId,
          req.user.storeId,
          date
        ]
      );

      res.json({
        message:
          "Check-in recorded"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

app.get(
  "/api/store/attendance",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    const rows = await all(
      `
      SELECT
        a.*,
        s.name staff_name,
        s.mobile
      FROM attendance a
      JOIN staff s
        ON s.id=a.staff_id
      WHERE a.store_id=?
      ORDER BY a.id DESC
      `,
      [req.user.storeId]
    );

    res.json({
      attendance: rows
    });
  }
);

// ============================================================
// STORE DASHBOARD
// ============================================================

app.get(
  "/api/store/dashboard",
  auth,
  role("STORE", "STORE_ADMIN"),
  async (req, res) => {
    try {
      const storeId = req.user.storeId;

      const sales = await get(
        `
        SELECT COALESCE(SUM(total),0) total
        FROM orders
        WHERE store_id=?
          AND status!='CANCELLED'
        `,
        [storeId]
      );

      const orders = await get(
        `
        SELECT COUNT(*) total
        FROM orders
        WHERE store_id=?
        `,
        [storeId]
      );

      const products = await get(
        `
        SELECT COUNT(*) total
        FROM items
        WHERE store_id=?
          AND active=1
        `,
        [storeId]
      );

      const expenses = await get(
        `
        SELECT COALESCE(SUM(amount),0) total
        FROM expenses
        WHERE store_id=?
        `,
        [storeId]
      );

      const khata = await get(
        `
        SELECT
          COALESCE(
            SUM(
              CASE
                WHEN type='DUE'
                THEN amount
                ELSE -amount
              END
            ),
            0
          ) total
        FROM khata
        WHERE store_id=?
        `,
        [storeId]
      );

      res.json({
        totalSales: sales.total,
        totalOrders: orders.total,
        totalProducts: products.total,
        totalExpenses: expenses.total,
        totalKhataDue: khata.total,
        netIncome:
          Number(sales.total) -
          Number(expenses.total)
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// MULTI STORE ADD
// ============================================================

app.post(
  "/api/store-admin/add-store",
  auth,
  role("STORE_ADMIN"),
  async (req, res) => {
    try {
      const storeId =
        String(req.body.storeId || "").trim();

      const admin = await get(
        `
        SELECT *
        FROM store_admins
        WHERE id=?
        `,
        [req.user.id]
      );

      if (!admin) {
        return res.status(404).json({
          error: "Admin not found"
        });
      }

      const store = await get(
        "SELECT * FROM stores WHERE store_id=?",
        [storeId]
      );

      if (!store) {
        return res.status(404).json({
          error: "Store not found"
        });
      }

      await run(
        `
        INSERT OR IGNORE INTO store_admins
        (
          store_id,
          name,
          mobile,
          password_hash,
          role
        )
        VALUES (?,?,?,?,?)
        `,
        [
          storeId,
          admin.name,
          admin.mobile,
          admin.password_hash,
          "STORE_ADMIN"
        ]
      );

      res.json({
        message:
          "Store added to admin account",
        store
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

app.get(
  "/api/store-admin/stores",
  auth,
  role("STORE_ADMIN"),
  async (req, res) => {
    try {
      const admin = await get(
        `
        SELECT mobile
        FROM store_admins
        WHERE id=?
        `,
        [req.user.id]
      );

      const stores = await all(
        `
        SELECT
          s.*
        FROM stores s
        JOIN store_admins sa
          ON sa.store_id=s.store_id
        WHERE sa.mobile=?
          AND sa.active=1
        ORDER BY s.id DESC
        `,
        [admin.mobile]
      );

      res.json({
        stores
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// STORE ADMIN CHANGE PASSWORD
// ============================================================

app.post(
  "/api/store-admin/change-password",
  auth,
  role("STORE_ADMIN"),
  async (req, res) => {
    try {
      const oldPassword =
        String(req.body.oldPassword || "");

      const newPassword =
        String(req.body.newPassword || "");

      if (newPassword.length < 6) {
        return res.status(400).json({
          error:
            "New password must be at least 6 characters"
        });
      }

      const admin = await get(
        "SELECT * FROM store_admins WHERE id=?",
        [req.user.id]
      );

      if (
        !admin ||
        !(await bcrypt.compare(
          oldPassword,
          admin.password_hash
        ))
      ) {
        return res.status(401).json({
          error: "Old password incorrect"
        });
      }

      const hash =
        await bcrypt.hash(
          newPassword,
          12
        );

      await run(
        `
        UPDATE store_admins
        SET password_hash=?
        WHERE id=?
        `,
        [
          hash,
          admin.id
        ]
      );

      res.json({
        message:
          "Password changed successfully"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN LOGIN
// ============================================================

app.post(
  "/api/main-admin/login",
  async (req, res) => {
    try {
      const m = mobile(req.body.mobile);

      const password =
        String(req.body.password || "");

      const admin = await get(
        "SELECT * FROM admins WHERE mobile=?",
        [m]
      );

      if (
        !admin ||
        !(await bcrypt.compare(
          password,
          admin.password_hash
        ))
      ) {
        return res.status(401).json({
          error:
            "Invalid Main Admin credentials"
        });
      }

      if (admin.blocked) {
        return res.status(403).json({
          error: "Admin blocked"
        });
      }

      const token = createToken({
        id: admin.id,
        mobile: admin.mobile,
        role: admin.role,
        type: "admin"
      });

      res.json({
        admin: {
          id: admin.id,
          mobile: admin.mobile,
          name: admin.name,
          role: admin.role
        },
        token
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN DASHBOARD
// ============================================================

app.get(
  "/api/main-admin/dashboard",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const stores = await get(
        "SELECT COUNT(*) n FROM stores"
      );

      const customers = await get(
        "SELECT COUNT(*) n FROM customers"
      );

      const orders = await get(
        "SELECT COUNT(*) n FROM orders"
      );

      const sales = await get(
        `
        SELECT COALESCE(SUM(total),0) n
        FROM orders
        WHERE status!='CANCELLED'
        `
      );

      const cash = await get(
        `
        SELECT COALESCE(SUM(total),0) n
        FROM orders
        WHERE payment_method='COD'
          AND status!='CANCELLED'
        `
      );

      const commission = await get(
        `
        SELECT COALESCE(
          SUM(
            o.total *
            s.commission_rate /
            100
          ),
          0
        ) n
        FROM orders o
        JOIN stores s
          ON s.store_id=o.store_id
        WHERE o.status!='CANCELLED'
        `
      );

      res.json({
        totalStores: stores.n,
        totalCustomers: customers.n,
        totalOrders: orders.n,
        totalSales: sales.n,
        cashSales: cash.n,
        commission: commission.n
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN STORES
// ============================================================

app.get(
  "/api/main-admin/stores",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const stores = await all(
        `
        SELECT
          s.*,
          COALESCE(
            (
              SELECT SUM(o.total)
              FROM orders o
              WHERE o.store_id=s.store_id
                AND o.status!='CANCELLED'
            ),
            0
          ) total_sales
        FROM stores s
        ORDER BY s.id DESC
        `
      );

      res.json({
        stores
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN STORE STATUS
// ============================================================

app.post(
  "/api/main-admin/store/:storeId/status",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const status =
        ["ON", "OFF", "BLOCKED"].includes(
          req.body.status
        )
          ? req.body.status
          : null;

      if (!status) {
        return res.status(400).json({
          error:
            "Status must be ON, OFF or BLOCKED"
        });
      }

      const result = await run(
        `
        UPDATE stores
        SET
          status=?,
          blocked=?
        WHERE store_id=?
        `,
        [
          status,
          status === "BLOCKED" ? 1 : 0,
          req.params.storeId
        ]
      );

      if (!result.changes) {
        return res.status(404).json({
          error: "Store not found"
        });
      }

      res.json({
        message:
          "Store status updated"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN CUSTOMERS
// ============================================================

app.get(
  "/api/main-admin/customers",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const customers = await all(
        `
        SELECT
          c.id,
          c.name,
          c.mobile,
          c.blocked,
          c.mobile_verified,
          c.created_at,
          COUNT(o.id) orders,
          COALESCE(
            SUM(
              CASE
                WHEN o.status!='CANCELLED'
                THEN o.total
                ELSE 0
              END
            ),
            0
          ) total_spent
        FROM customers c
        LEFT JOIN orders o
          ON o.customer_id=c.id
        GROUP BY c.id
        ORDER BY c.id DESC
        `
      );

      res.json({
        customers
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN BLOCK CUSTOMER
// ============================================================

app.post(
  "/api/main-admin/customer/:id/status",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const blocked =
        req.body.blocked ? 1 : 0;

      const result = await run(
        `
        UPDATE customers
        SET blocked=?
        WHERE id=?
        `,
        [
          blocked,
          req.params.id
        ]
      );

      if (!result.changes) {
        return res.status(404).json({
          error: "Customer not found"
        });
      }

      res.json({
        message:
          "Customer status updated"
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN ORDERS
// ============================================================

app.get(
  "/api/main-admin/orders",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const orders = await all(
        `
        SELECT
          o.*,
          c.name customer_name,
          c.mobile customer_mobile,
          s.store_name
        FROM orders o
        LEFT JOIN customers c
          ON c.id=o.customer_id
        LEFT JOIN stores s
          ON s.store_id=o.store_id
        ORDER BY o.id DESC
        `
      );

      res.json({
        orders
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN RENT
// ============================================================

app.post(
  "/api/main-admin/rent",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const storeId =
        String(req.body.storeId || "").trim();

      const amount =
        money(req.body.amount);

      const days = Math.max(
        1,
        Number(req.body.days || 30)
      );

      if (amount === null) {
        return res.status(400).json({
          error: "Valid rent amount required"
        });
      }

      const store = await get(
        "SELECT * FROM stores WHERE store_id=?",
        [storeId]
      );

      if (!store) {
        return res.status(404).json({
          error: "Store not found"
        });
      }

      const expiry = new Date();

      expiry.setDate(
        expiry.getDate() + days
      );

      const expiryDate =
        expiry.toISOString().slice(0, 10);

      await transaction(async () => {
        await run(
          `
          INSERT INTO rent_payments
          (store_id,amount,days)
          VALUES (?,?,?)
          `,
          [
            storeId,
            amount,
            days
          ]
        );

        await run(
          `
          UPDATE stores
          SET
            rent_amount=?,
            rent_expiry=?
          WHERE store_id=?
          `,
          [
            amount,
            expiryDate,
            storeId
          ]
        );
      });

      res.json({
        message: "Rent updated",
        expiry: expiryDate
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN REPORTS
// ============================================================

app.get(
  "/api/main-admin/reports",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const today = await get(
        `
        SELECT COALESCE(SUM(total),0) total
        FROM orders
        WHERE date(created_at)=date('now')
          AND status!='CANCELLED'
        `
      );

      const month = await get(
        `
        SELECT COALESCE(SUM(total),0) total
        FROM orders
        WHERE strftime('%Y-%m',created_at)
            = strftime('%Y-%m','now')
          AND status!='CANCELLED'
        `
      );

      const total = await get(
        `
        SELECT COALESCE(SUM(total),0) total
        FROM orders
        WHERE status!='CANCELLED'
        `
      );

      res.json({
        today: today.total,
        month: month.total,
        totalSales: total.total
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN SETTINGS
// ============================================================

app.get(
  "/api/main-admin/settings",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    const settings = await get(
      "SELECT * FROM system_settings WHERE id=1"
    );

    res.json({
      settings
    });
  }
);

app.put(
  "/api/main-admin/settings",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const current = await get(
        "SELECT * FROM system_settings WHERE id=1"
      );

      const commission = Number(
        req.body.commission_rate ??
        current.commission_rate
      );

      const rent = Number(
        req.body.default_rent ??
        current.default_rent
      );

      const adminUpi = String(
        req.body.admin_upi ??
        current.admin_upi
      );

      if (
        commission < 0 ||
        commission > 100
      ) {
        return res.status(400).json({
          error: "Invalid commission"
        });
      }

      if (!Number.isFinite(rent) || rent < 0) {
        return res.status(400).json({
          error: "Invalid rent"
        });
      }

      await run(
        `
        UPDATE system_settings
        SET
          admin_upi=?,
          commission_rate=?,
          default_rent=?
        WHERE id=1
        `,
        [
          adminUpi,
          commission,
          rent
        ]
      );

      await run(
        `
        UPDATE stores
        SET commission_rate=?
        `,
        [commission]
      );

      res.json({
        settings: await get(
          "SELECT * FROM system_settings WHERE id=1"
        )
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// ADMIN STORE ADMINS
// ============================================================

app.get(
  "/api/main-admin/store-admins",
  auth,
  role("SUPER_ADMIN"),
  async (req, res) => {
    try {
      const admins = await all(
        `
        SELECT
          id,
          store_id,
          name,
          mobile,
          role,
          active,
          created_at
        FROM store_admins
        ORDER BY id DESC
        `
      );

      res.json({
        admins
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// NOTIFICATIONS
// ============================================================

app.get(
  "/api/notifications",
  auth,
  async (req, res) => {
    try {
      const notifications = await all(
        `
        SELECT *
        FROM notifications
        WHERE user_type=?
          AND user_id=?
        ORDER BY id DESC
        `,
        [
          req.user.role,
          String(req.user.id)
        ]
      );

      res.json({
        notifications
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "API endpoint not found"
    });
  }
);

// ============================================================
// ERROR
// ============================================================

app.use(
  (error, req, res, next) => {
    console.error(error);

    if (
      error instanceof multer.MulterError
    ) {
      return res.status(400).json({
        error: error.message
      });
    }

    res.status(500).json({
      error:
        error.message ||
        "Server error"
    });
  }
);

// ============================================================
// START
// ============================================================

async function start() {
  try {
    await initDatabase();

    const adminMobile = mobile(
      process.env.MAIN_ADMIN_MOBILE ||
      "9999999999"
    );

    const adminPassword =
      process.env.MAIN_ADMIN_PASSWORD ||
      "ChangeMe123!";

    const adminName =
      process.env.MAIN_ADMIN_NAME ||
      "Main Admin";

    const exists = await get(
      "SELECT id FROM admins WHERE mobile=?",
      [adminMobile]
    );

    if (!exists) {
      const hash =
        await bcrypt.hash(
          adminPassword,
          12
        );

      await run(
        `
        INSERT INTO admins
        (
          mobile,
          password_hash,
          name,
          role
        )
        VALUES (?,?,?,'SUPER_ADMIN')
        `,
        [
          adminMobile,
          hash,
          adminName
        ]
      );

      console.log(
        "Main Admin created"
      );
    }

    app.listen(
      PORT,
      () => {
        console.log("");
        console.log(
          "======================================"
        );
        console.log(
          " LOCALSTORE BACKEND RUNNING"
        );
        console.log(
          ` http://localhost:${PORT}`
        );
        console.log(
          ` http://localhost:${PORT}/api/health`
        );
        console.log(
          " Online UPI: DISABLED"
        );
        console.log(
          " UTR: DISABLED"
        );
        console.log(
          " Screenshot Payment: DISABLED"
        );
        console.log(
          "======================================"
        );
        console.log("");
      }
    );
  } catch (error) {
    console.error(
      "Backend startup failed:",
      error
    );

    process.exit(1);
  }
}

start();
