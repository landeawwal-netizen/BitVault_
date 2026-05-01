const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");

loadLocalEnv(path.join(__dirname, ".env"));

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";
const APP_DIR = __dirname;
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_RENDER = Boolean(process.env.RENDER);
const LEGACY_DATA_FILE = path.join(APP_DIR, "backend", "data", "store.json");
const RENDER_DATA_FILE = "/var/data/bitvault/store.json";
const DATA_FILE = process.env.BITVAULT_DATA_FILE
  ? path.resolve(process.env.BITVAULT_DATA_FILE)
  : IS_RENDER
    ? RENDER_DATA_FILE
    : LEGACY_DATA_FILE;
const ALLOW_JSON_STORAGE = process.env.ALLOW_JSON_STORAGE === "true" || NODE_ENV !== "production";
const MONGODB_DB = process.env.MONGODB_DB || "bitvault";
const USE_MONGODB = Boolean(process.env.MONGODB_URI);
const POSTGRES_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS bitvault_users (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS bitvault_sessions (
  token TEXT PRIMARY KEY,
  data JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS bitvault_transactions (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL
);
`;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const WALLET_KEYS = ["mainWallet", "wallet"];
const WALLET_LABELS = {
  mainWallet: "Main Wallet",
  wallet: "Wallet"
};
const WITHDRAWAL_METHODS = ["Cash App", "PayPal"];
const MARKET_IDS = ["bitcoin", "ethereum", "binancecoin", "solana", "ripple"];
const BTC_PER_USD = 0.00001357015;
const BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const FIXED_WALLET_ADDRESS = "bc1qu4m7pty92dmwvgyx7unc5ph5f47sau6fgn9lln";

let marketCache = {
  fetchedAt: 0,
  data: null
};

let storage = null;

function loadLocalEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");

    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    let value = trimmed.slice(separatorIndex + 1).trim();

    if (!key || process.env[key] !== undefined) {
      continue;
    }

    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    process.env[key] = value;
  }
}

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  firstName: {
    type: String,
    default: ""
  },
  lastName: {
    type: String,
    default: ""
  },
  role: {
    type: String,
    default: "user"
  },
  cashWallets: {
    type: Object,
    default: () => ({ mainWallet: 0, wallet: 0 })
  },
  mainWallet: {
    type: Object,
    default: () => ({ balance: 0 })
  },
  wallet: {
    type: Object,
    default: () => ({ balance: 0 })
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { versionKey: false });

userSchema.pre("save", async function hashPassword() {
  if (!this.isModified("password")) {
    return;
  }

  this.password = await bcrypt.hash(this.password, 10);
});

const sessionSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
  }
}, { versionKey: false });

const User = mongoose.model("User", userSchema);
const Session = mongoose.model("Session", sessionSchema);

app.use(cors());
app.use(express.json());
app.use(express.static(APP_DIR));

let storageReadyPromise = null;

app.use(async (req, res, next) => {
  try {
    await ensureStorageReady();
    next();
  } catch (error) {
    next(error);
  }
});

function envStatus(name) {
  return process.env[name] ? "set" : "missing";
}

function getStorageStatus() {
  const usesPersistentDb = Boolean(process.env.MONGODB_URI);
  const dataFileExists = fs.existsSync(DATA_FILE);
  let dataFileUserCount = null;
  let dataFileReadable = false;
  let dataFileError = null;

  if (dataFileExists) {
    try {
      const fileDb = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      dataFileReadable = true;
      dataFileUserCount = Array.isArray(fileDb.users) ? fileDb.users.length : 0;
    } catch (error) {
      dataFileError = error.message;
    }
  }

  return {
    mode: usesPersistentDb ? "mongodb" : "json-file",
    mongodbUri: envStatus("MONGODB_URI"),
    bitvaultDataFile: envStatus("BITVAULT_DATA_FILE"),
    dataFile: DATA_FILE,
    legacyDataFile: LEGACY_DATA_FILE,
    renderDefaultDataFile: RENDER_DATA_FILE,
    render: IS_RENDER,
    dataFileExists,
    dataFileReadable,
    dataFileUserCount,
    dataFileError
  };
}

function logStorageStatus(context) {
  console.log(`[storage:${context}]`, JSON.stringify(getStorageStatus()));
}

async function connectMongoDb() {
  if (!USE_MONGODB) {
    if (NODE_ENV === "production") {
      throw new Error("MONGODB_URI is required in production; refusing to use JSON file storage.");
    }
    console.warn("MONGODB_URI missing; using JSON file storage fallback for local development.");
    return;
  }

  try {
    await mongoose.connect(process.env.MONGODB_URI);
    await User.init();
    console.log("MongoDB connected successfully");
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    throw error;
  }
}

async function importJsonUsersIntoMongoDb() {
  const source = safeReadJson(LEGACY_DATA_FILE);
  const users = Array.isArray(source?.users) ? source.users : [];

  if (!users.length) {
    console.log(`[storage:mongodb-import] no JSON users found at ${LEGACY_DATA_FILE}`);
    return;
  }

  let imported = 0;
  let skipped = 0;

  for (const legacyUser of users) {
    const email = normalizeEmail(legacyUser.email);
    const password = legacyUser.passwordHash || legacyUser.password;

    if (!email || !password) {
      skipped += 1;
      continue;
    }

    const result = await User.updateOne(
      { email },
      {
        $setOnInsert: {
          email,
          password,
          firstName: legacyUser.firstName || "",
          lastName: legacyUser.lastName || "",
          role: legacyUser.role || "user",
          cashWallets: legacyUser.cashWallets || { mainWallet: 0, wallet: 0 },
          mainWallet: legacyUser.mainWallet || { balance: 0 },
          wallet: legacyUser.wallet || { balance: 0 },
          createdAt: legacyUser.createdAt ? new Date(legacyUser.createdAt) : new Date()
        }
      },
      { upsert: true }
    );

    if (result.upsertedCount) {
      imported += 1;
    } else {
      skipped += 1;
    }
  }

  const count = await User.countDocuments();
  console.log(`[storage:mongodb-import] imported=${imported} skipped=${skipped} mongoUsers=${count} source=${LEGACY_DATA_FILE}`);
}

function ensureDb() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`[storage:ensureDb] created data directory ${dir}`);
  }

  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], sessions: [], transactions: [] }, null, 2));
    console.warn(`[storage:ensureDb] created new empty data file at ${DATA_FILE}`);
  }
}

function emptyDb() {
  return { users: [], sessions: [], transactions: [] };
}

function safeReadJson(file) {
  if (!fs.existsSync(file)) {
    return null;
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch (error) {
    console.warn(`[storage:recover] skipped unreadable JSON file ${file}: ${error.message}`);
    return null;
  }
}

function normalizeDbShape(db) {
  return {
    users: Array.isArray(db?.users) ? db.users : [],
    sessions: Array.isArray(db?.sessions) ? db.sessions : [],
    transactions: Array.isArray(db?.transactions) ? db.transactions : []
  };
}

function mergeByKey(targetItems, sourceItems, keyFor) {
  let added = 0;
  const seen = new Set(targetItems.map(keyFor).filter(Boolean));

  sourceItems.forEach((item) => {
    const key = keyFor(item);
    if (!key || seen.has(key)) {
      return;
    }

    targetItems.push(item);
    seen.add(key);
    added += 1;
  });

  return added;
}

function backupDataFile(file, reason) {
  if (!fs.existsSync(file)) {
    return null;
  }

  const backupFile = `${file}.${reason}.${new Date().toISOString().replace(/[:.]/g, "-")}.bak`;
  fs.copyFileSync(file, backupFile);
  return backupFile;
}

function recoverDataFiles() {
  ensureDb();

  const candidateFiles = [
    DATA_FILE,
    LEGACY_DATA_FILE,
    path.join(process.cwd(), "backend", "data", "store.json")
  ];

  if (process.env.BITVAULT_RECOVERY_FILES) {
    candidateFiles.push(...process.env.BITVAULT_RECOVERY_FILES.split(path.delimiter));
  }

  const uniqueFiles = [...new Set(candidateFiles.map((file) => path.resolve(file)))];
  const target = normalizeDbShape(safeReadJson(DATA_FILE) || emptyDb());
  const before = {
    users: target.users.length,
    sessions: target.sessions.length,
    transactions: target.transactions.length
  };
  const added = { users: 0, sessions: 0, transactions: 0 };

  uniqueFiles
    .filter((file) => file !== path.resolve(DATA_FILE))
    .forEach((file) => {
      const source = normalizeDbShape(safeReadJson(file));
      if (!source.users.length && !source.sessions.length && !source.transactions.length) {
        return;
      }

      const sourceAdded = {
        users: mergeByKey(target.users, source.users, (user) => normalizeEmail(user.email) || user.id),
        sessions: mergeByKey(target.sessions, source.sessions, (session) => session.token),
        transactions: mergeByKey(target.transactions, source.transactions, (transaction) => transaction.id || transaction.receiptId)
      };

      added.users += sourceAdded.users;
      added.sessions += sourceAdded.sessions;
      added.transactions += sourceAdded.transactions;
      console.log(`[storage:recover] merged ${JSON.stringify(sourceAdded)} from ${file}`);
    });

  if (added.users || added.sessions || added.transactions) {
    const backupFile = backupDataFile(DATA_FILE, "pre-recovery");
    fs.writeFileSync(DATA_FILE, JSON.stringify(target, null, 2));
    console.log(`[storage:recover] wrote ${DATA_FILE}; before=${JSON.stringify(before)} added=${JSON.stringify(added)} backup=${backupFile || "none"}`);
  }
}

function readDb() {
  ensureDb();
  const db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  let changed = false;
  db.users = Array.isArray(db.users) ? db.users : [];
  if (!Array.isArray(db.sessions)) {
    db.sessions = [];
    changed = true;
  }
  if (!Array.isArray(db.transactions)) {
    db.transactions = [];
    changed = true;
  }

  db.transactions = db.transactions.map((transaction) => {
    const normalized = { ...transaction };
    if (!normalized.id) {
      normalized.id = crypto.randomUUID();
      changed = true;
    }
    if (!normalized.createdAt) {
      normalized.createdAt = normalized.timestamp || new Date().toISOString();
      changed = true;
    }
    if (!normalized.timestamp) {
      normalized.timestamp = normalized.createdAt;
      changed = true;
    }
    if (!normalized.receiptId) {
      normalized.receiptId = makeReceipt();
      changed = true;
    }
    if (!normalized.status) {
      normalized.status = "confirmed";
      changed = true;
    }
    if (!normalized.assetSymbol) {
      normalized.assetSymbol = normalized.type === "sell" ? "BTC" : normalized.type === "withdrawal" ? "USD" : "BTC";
      changed = true;
    }
    if (!normalized.assetName) {
      normalized.assetName = normalized.assetSymbol === "BTC" ? "Bitcoin" : normalized.assetSymbol === "ETH" ? "Ethereum" : normalized.assetSymbol === "BNB" ? "BNB" : normalized.assetSymbol === "USDT" ? "Tether" : normalized.assetSymbol === "USD" ? "US Dollar" : normalized.assetSymbol;
      changed = true;
    }
    if (typeof normalized.amount !== "number") {
      normalized.amount = Number(normalized.amount || 0);
      changed = true;
    }
    if (typeof normalized.fiatValue !== "number") {
      normalized.fiatValue = Number(normalized.fiatValue ?? normalized.amount ?? 0);
      changed = true;
    }
    if (typeof normalized.fee !== "number") {
      normalized.fee = Number(normalized.fee || 0);
      changed = true;
    }
    if (typeof normalized.confirmations !== "number") {
      normalized.confirmations = Number(normalized.confirmations || 0);
      changed = true;
    }
    if (!normalized.senderAddress) {
      normalized.senderAddress = normalized.fromLabel || "";
      changed = true;
    }
    if (!normalized.receiverAddress) {
      normalized.receiverAddress = normalized.toLabel || "";
      changed = true;
    }
    if (!normalized.txHash) {
      normalized.txHash = normalized.receiptId;
      changed = true;
    }
    if (!normalized.network) {
      normalized.network = normalized.type === "send" ? "Bitcoin" : normalized.type === "sell" ? "Bitcoin" : normalized.type === "withdrawal" ? String(normalized.toLabel || "Cash App") : "Bitcoin";
      changed = true;
    }
    return normalized;
  });

  db.users.forEach((user) => {
    if (ensureWalletAccounts(user)) {
      changed = true;
    }
    if (!user.cashWallets) {
      user.cashWallets = { mainWallet: 0, wallet: 0 };
      changed = true;
    }
    WALLET_KEYS.forEach((key) => {
      const normalized = Number(user.cashWallets[key] || 0);
      if (user.cashWallets[key] !== normalized) {
        user.cashWallets[key] = normalized;
        changed = true;
      }
    });
  });

  if (changed) {
    writeDb(db);
  }

  return db;
}

function writeDb(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validPassword(value) {
  return typeof value === "string" && value.length === 8;
}

function isWalletKey(value) {
  return WALLET_KEYS.includes(value);
}

function makeWalletAddress(seed, walletKey) {
  const hash = crypto.createHash("sha256").update(`${seed}:${walletKey}`).digest();
  let encoded = "";
  for (const byte of hash) {
    encoded += BECH32_CHARS[byte % BECH32_CHARS.length];
  }
  return `bc1${encoded.slice(0, 39)}`;
}

function ensureWalletAccounts(user) {
  let changed = false;

  if (!user.cashWallets) {
    user.cashWallets = { mainWallet: 0, wallet: 0 };
    changed = true;
  }

  if (!user.mainWallet || typeof user.mainWallet !== "object") {
    user.mainWallet = {};
    changed = true;
  }

  if (!user.wallet || typeof user.wallet !== "object") {
    user.wallet = {};
    changed = true;
  }

  if (!user.mainWallet.address) {
    user.mainWallet.address = makeWalletAddress(user.id || user.email || "bitvault", "mainWallet");
    changed = true;
  }

  if (user.wallet.address !== FIXED_WALLET_ADDRESS) {
    user.wallet.address = FIXED_WALLET_ADDRESS;
    changed = true;
  }

  const mainBalance = Number(user.cashWallets.mainWallet ?? user.mainWallet.balance ?? 0);
  const walletBalance = Number(user.cashWallets.wallet ?? user.wallet.balance ?? 0);

  if (user.cashWallets.mainWallet !== mainBalance) {
    user.cashWallets.mainWallet = mainBalance;
    changed = true;
  }
  if (user.cashWallets.wallet !== walletBalance) {
    user.cashWallets.wallet = walletBalance;
    changed = true;
  }
  if (user.mainWallet.balance !== mainBalance) {
    user.mainWallet.balance = mainBalance;
    changed = true;
  }
  if (user.wallet.balance !== walletBalance) {
    user.wallet.balance = walletBalance;
    changed = true;
  }

  return changed;
}

function publicUser(user) {
  const raw = typeof user.toObject === "function" ? user.toObject() : user;
  return {
    id: raw.id || raw._id?.toString(),
    firstName: raw.firstName,
    lastName: raw.lastName,
    email: raw.email,
    cashWallets: raw.cashWallets,
    mainWallet: raw.mainWallet,
    wallet: raw.wallet,
    createdAt: raw.createdAt instanceof Date ? raw.createdAt.toISOString() : raw.createdAt
  };
}

function walletCodeFor(user, walletKey) {
  const target = walletKey === "wallet" ? user.wallet : user.mainWallet;
  return target?.address || "";
}

function findUserByRecipient(db, recipientValue) {
  const value = normalizeEmail(recipientValue);
  if (!value) return null;

  const direct = db.users.find((user) => user.email === value);
  if (direct) return direct;

  const byCode = db.users.find((user) =>
    walletCodeFor(user, "mainWallet").toLowerCase() === value ||
    walletCodeFor(user, "wallet").toLowerCase() === value
  );
  return byCode || null;
}

async function createSession(userId) {
  if (USE_MONGODB) {
    const token = crypto.randomBytes(32).toString("hex");
    await Session.deleteMany({ expiresAt: { $lte: new Date() } });
    await Session.create({
      token,
      userId,
      expiresAt: new Date(Date.now() + SESSION_TTL_MS)
    });
    return token;
  }

  const db = readDb();
  const token = crypto.randomBytes(32).toString("hex");
  db.sessions = db.sessions.filter((session) => new Date(session.expiresAt).getTime() > Date.now());
  db.sessions.push({
    token,
    userId,
    expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString()
  });
  writeDb(db);
  return token;
}

async function getAuthUser(req) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) {
    return null;
  }

  if (USE_MONGODB) {
    const session = await Session.findOne({ token });
    if (!session) {
      return null;
    }

    if (session.expiresAt.getTime() <= Date.now()) {
      await Session.deleteOne({ token });
      return null;
    }

    return User.findById(session.userId);
  }

  const db = readDb();
  const session = db.sessions.find((item) => item.token === token);
  if (!session) {
    return null;
  }

  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    db.sessions = db.sessions.filter((item) => item.token !== token);
    writeDb(db);
    return null;
  }

  return db.users.find((user) => user.id === session.userId) || null;
}

async function authRequired(req, res, next) {
  try {
    const user = await getAuthUser(req);
    if (!user) {
      return res.status(401).json({ message: "Authentication required." });
    }
    req.user = user;
    return next();
  } catch (error) {
    return res.status(500).json({ message: "Unable to validate authentication." });
  }
}

function makeReceipt(prefix = "BV") {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

function makeTxHash() {
  return crypto.randomBytes(32).toString("hex");
}

function btcToUsd(btcAmount) {
  return Number((Number(btcAmount || 0) / BTC_PER_USD).toFixed(2));
}

function setWalletBalance(user, walletKey, balance) {
  const nextBalance = Number(Number(balance || 0).toFixed(2));
  if (!user.cashWallets) {
    user.cashWallets = { mainWallet: 0, wallet: 0 };
  }
  if (!user[walletKey] || typeof user[walletKey] !== "object") {
    user[walletKey] = {};
  }
  user.cashWallets[walletKey] = nextBalance;
  user[walletKey].balance = nextBalance;
  return nextBalance;
}

function moneyFormat(value) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD"
  }).format(Number(value || 0));
}

function addTransaction(db, payload) {
  db.transactions.push({
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    receiptId: payload.receiptId || makeReceipt(),
    ...payload
  });
}

function totalWalletSum(users, walletKey) {
  return users.reduce((sum, user) => sum + Number(user.cashWallets?.[walletKey] || 0), 0);
}

function normalizeMarkets(markets) {
  return markets.map((coin) => ({
    id: coin.id,
    symbol: coin.symbol,
    name: coin.name,
    image: coin.image,
    current_price: Number(coin.current_price || 0),
    price_change_percentage_24h: Number(coin.price_change_percentage_24h || 0),
    market_cap_rank: coin.market_cap_rank || null,
    high_24h: Number(coin.high_24h || 0),
    low_24h: Number(coin.low_24h || 0),
    last_updated: coin.last_updated || new Date().toISOString(),
    sparkline: Array.isArray(coin.sparkline_in_7d?.price) ? coin.sparkline_in_7d.price.map((value) => Number(value || 0)) : []
  }));
}

async function fetchMarkets(force = false) {
  if (!force && marketCache.data && Date.now() - marketCache.fetchedAt < 60 * 1000) {
    return marketCache.data;
  }

  const url = new URL("https://api.coingecko.com/api/v3/coins/markets");
  url.searchParams.set("vs_currency", "usd");
  url.searchParams.set("ids", MARKET_IDS.join(","));
  url.searchParams.set("price_change_percentage", "24h");
  url.searchParams.set("sparkline", "true");
  url.searchParams.set("precision", "2");
  url.searchParams.set("locale", "en");

  const response = await fetch(url, {
    headers: {
      accept: "application/json"
    }
  });

  if (!response.ok) {
    throw new Error(`Market data request failed with status ${response.status}`);
  }

  const markets = normalizeMarkets(await response.json());
  marketCache = {
    fetchedAt: Date.now(),
    data: markets
  };
  return markets;
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/config", (req, res) => {
  res.json({
    walletLabels: WALLET_LABELS,
    withdrawalMethods: WITHDRAWAL_METHODS
  });
});

app.get("/api/markets", async (req, res) => {
  try {
    const markets = await fetchMarkets(Boolean(req.query.refresh));
    res.json({ markets, source: "coingecko", updatedAt: new Date(marketCache.fetchedAt).toISOString() });
  } catch (error) {
    if (marketCache.data) {
      return res.json({
        markets: marketCache.data,
        source: "cache",
        updatedAt: new Date(marketCache.fetchedAt).toISOString(),
        warning: "Live market fetch failed, showing cached data."
      });
    }

    return res.status(502).json({
      message: "Unable to load live market data."
    });
  }
});

async function registerUser(req, res) {
  const firstName = String(req.body?.firstName || "").trim();
  const lastName = String(req.body?.lastName || "").trim();
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");

  if (!email || !validPassword(password)) {
    return res.status(400).json({ message: "Enter your email and an 8-character password." });
  }

  if (USE_MONGODB) {
    try {
      const user = new User({
        firstName,
        lastName,
        email,
        password,
        cashWallets: {
          mainWallet: 0,
          wallet: 0
        },
        mainWallet: {
          balance: 0,
          address: makeWalletAddress(email || "bitvault", "mainWallet")
        },
        wallet: {
          balance: 0,
          address: FIXED_WALLET_ADDRESS
        },
        createdAt: new Date()
      });

      await user.save();
      console.log(`[auth:register] created user=${user.email} storage=mongodb`);
      const token = await createSession(user._id);
      return res.status(201).json({
        message: "BitVault wallet created successfully.",
        token,
        user: publicUser(user)
      });
    } catch (error) {
      if (error?.code === 11000) {
        return res.status(409).json({ message: "This email already has a wallet. Login instead." });
      }
      console.error("Registration failed:", error);
      return res.status(500).json({ message: "Unable to create account." });
    }
  }

  const db = readDb();
  if (db.users.some((user) => user.email === email)) {
    return res.status(409).json({ message: "This email already has a wallet. Login instead." });
  }

  const user = {
    id: crypto.randomUUID(),
    firstName,
    lastName,
    email,
    passwordHash: await bcrypt.hash(password, 10),
    cashWallets: {
      mainWallet: 0,
      wallet: 0
    },
    mainWallet: {
      balance: 0,
      address: makeWalletAddress(email || "bitvault", "mainWallet")
    },
    wallet: {
      balance: 0,
      address: FIXED_WALLET_ADDRESS
    },
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  console.log(`[auth:register] created user=${user.email} storage=json-file dataFile=${DATA_FILE}`);
  addTransaction(db, {
    type: "account_created",
    amount: 0,
    sourceWallet: "mainWallet",
    destinationWallet: "mainWallet",
    fromLabel: "BitVault",
    toUserId: user.id,
    toLabel: `${user.firstName} ${user.lastName}`,
    note: "BitVault account created with zero balances."
  });
  writeDb(db);

  const token = await createSession(user.id);
  return res.status(201).json({
    message: "BitVault wallet created successfully.",
    token,
    user: publicUser(user)
  });
}

async function loginUser(req, res) {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");

  if (USE_MONGODB) {
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: "Invalid email or password." });
      }

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(401).json({ message: "Invalid email or password." });
      }

      const token = await createSession(user._id);
      return res.json({
        message: "Login successful.",
        token,
        user: publicUser(user)
      });
    } catch (error) {
      console.error("Login failed:", error);
      return res.status(500).json({ message: "Unable to login." });
    }
  }

  const db = readDb();
  const user = db.users.find((item) => item.email === email);

  if (!user) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const token = await createSession(user.id);
  return res.json({
    message: "Login successful.",
    token,
    user: publicUser(user)
  });
}

app.post("/api/register", registerUser);
app.post("/api/auth/signup", registerUser);
app.post("/api/login", loginUser);
app.post("/api/auth/login", loginUser);

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.get("/api/wallet/transactions", authRequired, (req, res) => {
  const db = readDb();
  const transactions = db.transactions
    .filter((item) => (item.toUserId === req.user.id || item.fromUserId === req.user.id) && item.type !== "account_created")
    .sort((a, b) => new Date(b.timestamp || b.createdAt).getTime() - new Date(a.timestamp || a.createdAt).getTime());
  res.json({ transactions });
});

app.post("/api/wallet/send", authRequired, (req, res) => {
  const recipientValue = String(req.body?.recipientAddress || req.body?.recipientEmail || "");
  const sourceWallet = String(req.body?.sourceWallet || "");
  const destinationWallet = String(req.body?.destinationWallet || "mainWallet");
  const amount = Number(req.body?.amount);
  const note = String(req.body?.note || "").trim();
  const fiatValue = btcToUsd(amount);
  const fee = 119.5;

  if (!isWalletKey(sourceWallet) || !isWalletKey(destinationWallet)) {
    return res.status(400).json({ message: "Invalid wallet selected." });
  }

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ message: "Amount must be greater than zero." });
  }

  const db = readDb();
  const sender = db.users.find((item) => item.id === req.user.id);
  const recipient = findUserByRecipient(db, recipientValue);

  if (!recipient) {
    return res.status(404).json({ message: "Recipient not found." });
  }

  if (recipient.id === sender.id) {
    return res.status(400).json({ message: "You cannot send money to yourself." });
  }

  if (Number(sender.cashWallets[sourceWallet] || 0) < fiatValue + fee) {
    return res.status(400).json({ message: "Insufficient balance." });
  }

  setWalletBalance(sender, sourceWallet, Number((sender.cashWallets[sourceWallet] - fiatValue - fee).toFixed(2)));
  setWalletBalance(recipient, destinationWallet, Number((recipient.cashWallets[destinationWallet] + fiatValue).toFixed(2)));

  const receiptId = makeReceipt("SEND");
  addTransaction(db, {
    receiptId,
    type: "send",
    status: "confirmed",
    assetSymbol: "BTC",
    assetName: "Bitcoin",
    amount,
    fiatValue,
    fee,
    network: "Bitcoin",
    confirmations: 3,
    sourceWallet,
    destinationWallet,
    fromUserId: sender.id,
    fromLabel: `${sender.firstName} ${sender.lastName}`,
    senderAddress: walletCodeFor(sender, sourceWallet),
    toUserId: recipient.id,
    toLabel: `${recipient.firstName} ${recipient.lastName}`,
    receiverAddress: walletCodeFor(recipient, destinationWallet),
    txHash: makeTxHash(),
    timestamp: new Date().toISOString(),
    note: note || `${WALLET_LABELS[sourceWallet]} sent to ${recipient.email} into ${WALLET_LABELS[destinationWallet]}.`
  });
  writeDb(db);

  return res.json({
    message: "Transfer completed successfully.",
    receiptId
  });
});

app.post("/api/wallet/withdraw", authRequired, (req, res) => {
  const sourceWallet = String(req.body?.sourceWallet || "");
  const method = String(req.body?.method || "");
  const destination = String(req.body?.destination || "").trim();
  const amount = Number(req.body?.amount);
  const fee = 119.5;

  if (sourceWallet !== "mainWallet") {
    return res.status(400).json({ message: "Withdrawals can only come from Main Wallet." });
  }

  if (!WITHDRAWAL_METHODS.includes(method)) {
    return res.status(400).json({ message: "Invalid withdrawal method." });
  }

  if (!destination) {
    return res.status(400).json({ message: "Enter your Cash App or PayPal destination." });
  }

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ message: "Amount must be greater than zero." });
  }

  const db = readDb();
  const user = db.users.find((item) => item.id === req.user.id);

  if (Number(user.cashWallets[sourceWallet] || 0) < amount + fee) {
    return res.status(400).json({ message: "Insufficient balance." });
  }

  setWalletBalance(user, sourceWallet, Number((user.cashWallets[sourceWallet] - amount - fee).toFixed(2)));
  const receiptId = makeReceipt("WD");
  addTransaction(db, {
    receiptId,
    type: "withdrawal",
    status: "pending",
    assetSymbol: "USD",
    assetName: "US Dollar",
    amount,
    fiatValue: amount,
    fee,
    network: method,
    confirmations: 0,
    sourceWallet,
    destinationWallet: null,
    fromUserId: user.id,
    fromLabel: `${user.firstName} ${user.lastName}`,
    senderAddress: walletCodeFor(user, sourceWallet),
    receiverAddress: destination,
    txHash: makeTxHash(),
    timestamp: new Date().toISOString(),
    toLabel: `${method} ${destination}`,
    note: `Withdrawal requested from ${WALLET_LABELS[sourceWallet]} to ${method}.`
  });
  writeDb(db);

  return res.json({
    message: `Withdrawal queued to ${method}.`,
    receiptId
  });
});

app.post("/api/wallet/sell", authRequired, async (req, res) => {
  const coinId = String(req.body?.coinId || "").trim();
  const amount = Number(req.body?.amount);
  const wallet = String(req.body?.wallet || "");

  if (wallet !== "wallet") {
    return res.status(400).json({ message: "Crypto sells must come from Wallet." });
  }

  if (!coinId) {
    return res.status(400).json({ message: "Select a coin to sell." });
  }

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ message: "Amount must be greater than zero." });
  }

  try {
    const markets = await fetchMarkets();
    const coin = markets.find((item) => item.id === coinId);

    if (!coin) {
      return res.status(400).json({ message: "Selected coin is not available." });
    }

    const usdValue = Number((Number(amount) * Number(coin.current_price || 0)).toFixed(2));
    const db = readDb();
    const user = db.users.find((item) => item.id === req.user.id);

    if (Number(user.cashWallets.wallet || 0) < usdValue) {
      return res.status(400).json({ message: "Insufficient Wallet balance to sell this amount." });
    }

    setWalletBalance(user, "wallet", Number((user.cashWallets.wallet - usdValue).toFixed(2)));
    setWalletBalance(user, "mainWallet", Number((user.cashWallets.mainWallet + usdValue).toFixed(2)));

    const receiptId = makeReceipt("SELL");
    addTransaction(db, {
      receiptId,
      type: "sell",
      status: "confirmed",
      assetSymbol: coin.symbol.toUpperCase(),
      assetName: coin.name,
      amount,
      fiatValue: usdValue,
      fee: 119.5,
      network: "Bitcoin",
      confirmations: 3,
      sourceWallet: "wallet",
      destinationWallet: "mainWallet",
      fromUserId: user.id,
      fromLabel: `${user.firstName} ${user.lastName}`,
      senderAddress: walletCodeFor(user, "wallet"),
      toUserId: user.id,
      toLabel: `${user.firstName} ${user.lastName}`,
      receiverAddress: walletCodeFor(user, "mainWallet"),
      txHash: makeTxHash(),
      timestamp: new Date().toISOString(),
      note: `Sold ${amount} ${coin.symbol.toUpperCase()} at ${moneyFormat(coin.current_price)} into Main Wallet.`
    });
    writeDb(db);

    return res.json({
      message: `Sold ${amount} ${coin.symbol.toUpperCase()} for ${moneyFormat(usdValue)}.`,
      receiptId
    });
  } catch (error) {
    if (marketCache.data) {
      return res.status(502).json({ message: "Unable to sell right now. Live prices are unavailable." });
    }
    return res.status(502).json({ message: "Unable to sell right now." });
  }
});

app.get("/api/admin/overview", async (req, res) => {
  if (USE_MONGODB) {
    try {
      const users = await User.find({});
      console.log(`[admin:overview] users=${users.length} storage=mongodb`);
      return res.json({
        totals: {
          totalUsers: users.length,
          mainWallet: Number(totalWalletSum(users, "mainWallet").toFixed(2)),
          wallet: Number(totalWalletSum(users, "wallet").toFixed(2))
        }
      });
    } catch (error) {
      console.error("Unable to load admin overview:", error);
      return res.status(500).json({ message: "Unable to load overview." });
    }
  }

  const db = readDb();
  console.log(`[admin:overview] users=${db.users.length} storage=${getStorageStatus().mode}`);
  res.json({
    totals: {
      totalUsers: db.users.length,
      mainWallet: Number(totalWalletSum(db.users, "mainWallet").toFixed(2)),
      wallet: Number(totalWalletSum(db.users, "wallet").toFixed(2))
    }
  });
});

app.get("/api/admin/users", async (req, res) => {
  if (USE_MONGODB) {
    try {
      const users = (await User.find({}).sort({ createdAt: -1 })).map(publicUser);
      console.log(`[admin:users] returned=${users.length} storage=mongodb`);
      return res.json({ users });
    } catch (error) {
      console.error("Unable to load admin users:", error);
      return res.status(500).json({ message: "Unable to load users." });
    }
  }

  const db = readDb();
  const users = db.users
    .slice()
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(publicUser);
  const status = getStorageStatus();
  console.log(`[admin:users] returned=${users.length} rawUsers=${db.users.length} storage=${status.mode} dataFile=${status.dataFile} dataFileExists=${status.dataFileExists} MONGODB_URI=${status.mongodbUri}`);
  res.json({ users });
});

app.post("/api/admin/users/:id/fund", async (req, res) => {
  const wallet = String(req.body?.wallet || "");
  const action = String(req.body?.action || "");
  const amount = Number(req.body?.amount);

  if (!isWalletKey(wallet)) {
    return res.status(400).json({ message: "Invalid wallet selected." });
  }

  if (!["add", "deduct"].includes(action)) {
    return res.status(400).json({ message: "Invalid action." });
  }

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ message: "Amount must be greater than zero." });
  }

  if (USE_MONGODB) {
    try {
      const user = await User.findById(req.params.id);
      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }

      ensureWalletAccounts(user);
      const currentBalance = Number(user.cashWallets[wallet] || 0);
      const nextBalance = action === "add" ? currentBalance + amount : currentBalance - amount;

      if (nextBalance < 0) {
        return res.status(400).json({ message: "Cannot deduct below zero." });
      }

      setWalletBalance(user, wallet, nextBalance);
      user.markModified("cashWallets");
      user.markModified(wallet);
      await user.save();

      return res.json({
        message: `${WALLET_LABELS[wallet]} ${action === "add" ? "credited" : "deducted"} successfully.`,
        receiptId: makeReceipt("ADM"),
        user: publicUser(user)
      });
    } catch (error) {
      console.error("Unable to fund MongoDB user:", error);
      return res.status(500).json({ message: "Unable to update user funds." });
    }
  }

  const db = readDb();
  const user = db.users.find((item) => item.id === req.params.id);

  if (!user) {
    return res.status(404).json({ message: "User not found." });
  }

  const currentBalance = Number(user.cashWallets[wallet] || 0);
  const nextBalance = action === "add" ? currentBalance + amount : currentBalance - amount;

  if (nextBalance < 0) {
    return res.status(400).json({ message: "Cannot deduct below zero." });
  }

  setWalletBalance(user, wallet, nextBalance);
  const receiptId = makeReceipt("ADM");
  addTransaction(db, {
    receiptId,
    type: action === "add" ? "admin_credit" : "admin_deduction",
    status: "confirmed",
    assetSymbol: "USD",
    assetName: "US Dollar",
    amount,
    fiatValue: amount,
    fee: 0,
    network: "BitVault Admin",
    confirmations: 1,
    sourceWallet: action === "add" ? null : wallet,
    destinationWallet: action === "add" ? wallet : null,
    fromUserId: action === "deduct" ? user.id : null,
    fromLabel: action === "add" ? "BitVault Admin" : `${user.firstName} ${user.lastName}`,
    senderAddress: action === "add" ? "BitVault Admin" : walletCodeFor(user, wallet),
    toUserId: action === "add" ? user.id : null,
    toLabel: action === "add" ? `${user.firstName} ${user.lastName}` : "BitVault Admin",
    receiverAddress: action === "add" ? walletCodeFor(user, wallet) : "BitVault Admin",
    txHash: makeTxHash(),
    timestamp: new Date().toISOString(),
    note: `${action === "add" ? "Added" : "Deducted"} funds in ${WALLET_LABELS[wallet]}.`
  });
  writeDb(db);

  return res.json({
    message: `${WALLET_LABELS[wallet]} ${action === "add" ? "credited" : "deducted"} successfully.`,
    receiptId,
    user: publicUser(user)
  });
});

app.get("/api/admin/transactions", (req, res) => {
  const db = readDb();
  const transactions = db.transactions
    .slice()
    .filter((item) => item.type !== "account_created")
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  res.json({ transactions });
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(APP_DIR, "admin.html"));
});

app.get("/", (req, res) => {
  res.sendFile(path.join(APP_DIR, "index.html"));
});

app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(APP_DIR, "index.html"));
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
  process.exit(1);
});

process.on("unhandledRejection", (error) => {
  console.error("Unhandled rejection:", error);
  process.exit(1);
});

async function ensureStorageReady() {
  if (!storageReadyPromise) {
    storageReadyPromise = initializeStorage();
  }

  return storageReadyPromise;
}

async function initializeStorage() {
  await connectMongoDb();

  if (USE_MONGODB) {
    await importJsonUsersIntoMongoDb();
  } else {
    recoverDataFiles();
    readDb();
  }

  logStorageStatus("startup");
}

async function startServer() {
  try {
    await ensureStorageReady();
    const server = app.listen(PORT, HOST, () => {
      console.log(`Server running on port ${PORT}`);
    });

    server.on("error", (error) => {
      console.error("Server failed to start:", error);
      process.exit(1);
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

if (!process.env.VERCEL) {
  startServer();
}

module.exports = app;
module.exports.app = app;
