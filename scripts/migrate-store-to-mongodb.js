const bcrypt = require("bcryptjs");
const fs = require("fs");
const mongoose = require("mongoose");
const path = require("path");

loadLocalEnv(path.join(__dirname, "..", ".env"));

const storePath = path.resolve(process.env.STORE_JSON_PATH || path.join(__dirname, "..", "backend", "data", "store.json"));

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

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

async function passwordFor(user) {
  if (typeof user.passwordHash === "string" && user.passwordHash.startsWith("$2")) {
    return user.passwordHash;
  }

  if (typeof user.password === "string" && user.password.startsWith("$2")) {
    return user.password;
  }

  if (typeof user.password === "string" && user.password) {
    return bcrypt.hash(user.password, 10);
  }

  return null;
}

async function main() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is required.");
  }

  const store = JSON.parse(fs.readFileSync(storePath, "utf8"));
  const users = Array.isArray(store.users) ? store.users : [];
  await mongoose.connect(process.env.MONGODB_URI);

  const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    firstName: { type: String, default: "" },
    lastName: { type: String, default: "" },
    role: { type: String, default: "user" },
    cashWallets: { type: Object, default: () => ({ mainWallet: 0, wallet: 0 }) },
    mainWallet: { type: Object, default: () => ({ balance: 0 }) },
    wallet: { type: Object, default: () => ({ balance: 0 }) },
    createdAt: { type: Date, default: Date.now }
  }, { versionKey: false });
  const User = mongoose.model("User", userSchema);

  let imported = 0;
  let skipped = 0;

  for (const user of users) {
    const email = normalizeEmail(user.email);
    const password = await passwordFor(user);
    if (!email || !password) {
      skipped += 1;
      continue;
    }

    await User.updateOne(
      { email },
      {
        $setOnInsert: {
          email,
          password,
          firstName: user.firstName || "",
          lastName: user.lastName || "",
          role: user.role || "user",
          cashWallets: user.cashWallets || { mainWallet: 0, wallet: 0 },
          mainWallet: user.mainWallet || { balance: 0 },
          wallet: user.wallet || { balance: 0 },
          createdAt: user.createdAt ? new Date(user.createdAt) : new Date()
        }
      },
      { upsert: true }
    );
    imported += 1;
  }

  const count = await User.countDocuments();
  console.log(`Imported or preserved ${imported} users from ${storePath}. Skipped ${skipped}. MongoDB now has ${count} users.`);
  await mongoose.disconnect();
}

main().catch(async (error) => {
  console.error("Migration failed:", error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
