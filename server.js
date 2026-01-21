const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const bodyParser = require("body-parser");
const basicAuth = require("express-basic-auth");
const fs = require("fs");

const app = express();

// Middleware
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());

const KEYS_FILE = path.join(__dirname, "keys.json");
const KEY_LIFETIME = 24 * 60 * 60 * 1000;
const KEY_PREFIX = "WARE";
const SECRET = "HOMERWARE_SUPER_SECRET";

// -------------------- HELPER --------------------
function generateKey(hwid) {
  const raw = crypto
    .createHash("sha256")
    .update(hwid + SECRET)
    .digest("base64")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, 48);
  return `${KEY_PREFIX}-${raw.match(/.{1,12}/g).join("-")}`;
}

function getHWID(req) {
  const queryHwid = req.query.hwid;
  const headerHwid = req.headers["x-hwid"];
  const fallback = req.headers["user-agent"] + "_" + req.ip;

  console.log("HWID sources:");
  console.log(" - Query param:", queryHwid);
  console.log(" - Header:", headerHwid);
  console.log(" - Fallback:", fallback);

  return queryHwid || headerHwid || fallback;
}

function loadKeys() {
  if (!fs.existsSync(KEYS_FILE)) return new Map();
  const data = JSON.parse(fs.readFileSync(KEYS_FILE, "utf-8"));
  return new Map(data.map(k => [k.hwid, k]));
}

function saveKeys(store) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(Array.from(store.values()), null, 2));
}

// -------------------- IN-MEMORY STORE --------------------
const store = loadKeys();

// -------------------- USER API --------------------
app.get("/api/get-key", (req, res) => {
  const hwid = req.headers["x-hwid"];
  if (!hwid) return res.status(400).json({ error: "Missing HWID" });

  const now = Date.now();
  const existing = store.get(hwid);
  if (existing && existing.expiresAt > now) return res.json(existing);

  const keyData = {
    id: uuidv4(),
    key: generateKey(hwid),
    hwid,
    createdAt: now,
    expiresAt: now + KEY_LIFETIME
  };

  store.set(hwid, keyData);
  saveKeys(store);
  res.json(keyData);
});

// -------------------- PERMANENT KEY GENERATOR --------------------
app.post("/panel/generate-key", (req, res) => {
  // Optional: check for admin token in headers for extra security
  const adminToken = req.headers["x-admin-token"];
  if (adminToken !== "HOMERWARE_SUPER_SECRET") {
    return res.status(403).json({ error: "Unauthorized" });
  }

  const hwid = "PERMANENT-" + uuidv4(); // Dummy HWID for permanent keys
  const keyData = {
    id: uuidv4(),
    key: generateKey(hwid),
    hwid: hwid,
    createdAt: Date.now(),
    expiresAt: Infinity // never expires
  };

  store.set(keyData.hwid, keyData);
  saveKeys(store);

  res.json({ success: true, key: keyData.key });
});

// server.js
app.get("/api/get-key", async (req, res) => {
  const hwid = getHWID(req);
  const now = Date.now();

  console.log("Processing request for HWID:", hwid);

  let existing = keys.find(k => k.hwid === hwid && k.expiresAt > now);
  if (existing) {
    console.log("Found existing key:", existing.key);
    await sendWebhookLog(
      "Key Used (Existing)",
      `**HWID:** \`${hwid}\`\n**Key:** \`${existing.key}\`\n**Expires:** <t:${Math.floor(existing.expiresAt/1000)}:R>`,
      0x00FF00
    );
    return res.json(existing);
  }

// -------------------- OWNER PANEL --------------------
app.use(
  "/panel",
  basicAuth({
    users: { homerwareadmin: "HOMERWARELOL" }, // CHANGE THIS!
    challenge: true
  })
);

app.get("/panel", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "panel.html"));
});

// Get all keys
app.get("/panel/keys", (req, res) => {
  res.json(Array.from(store.values()));
});

// Revoke a key
app.post("/panel/revoke", (req, res) => {
  const { id } = req.body;
  let found = false;
  for (let [hwid, keyObj] of store.entries()) {
    if (keyObj.id === id) {
      store.delete(hwid);
      found = true;
      break;
    }
  }
  if (found) saveKeys(store);
  res.json({ success: found });
});

// -------------------- FRONTEND --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "keysystem.html"));
});

// -------------------- START SERVER --------------------
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
