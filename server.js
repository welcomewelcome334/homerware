const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = "NopeYourNotSeeingMyPassword";

const WEBHOOK_URL = "https://discord.com/api/webhooks/1463092958671802373/pHd8AWKeo2sdiY0O53e9PNCMNat8c1SKNB1YPGBTbFH_tXV3eFFrN91O-Kjz8CiGkset";

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(rateLimit({ windowMs: 10 * 1000, max: 5, message: { error: "Too many requests" } }));

const DB_FILE = path.join(__dirname, "keys.json");

let keys = [];
if (fs.existsSync(DB_FILE)) {
  try {
    keys = JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
    console.log("Loaded", keys.length, "keys from DB");
  } catch {}
}

function saveKeys() {
  fs.writeFileSync(DB_FILE, JSON.stringify(keys, null, 2));
}

function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "WARE-";
  for (let i = 0; i < 48; i++) {
    if (i > 0 && i % 12 === 0) result += "-";
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
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

async function sendWebhookLog(title, description, color = 0x5865F2) {
  const payload = {
    embeds: [{
      title: title,
      description: description,
      color: color,
      timestamp: new Date().toISOString(),
      footer: { text: "Homerware Key System" }
    }]
  };

  try {
    await fetch(WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error("Webhook failed:", err);
  }
}

function authAdmin(req, res, next) {
  if (req.headers["authorization"] !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Validate a key without auto-generating
app.get("/api/validate-key", async (req, res) => {
  const key = req.query.key;
  const hwid = getHWID(req);
  const now = Date.now();

  if (!key) {
    return res.status(400).json({ error: "No key provided" });
  }

  const existing = keys.find(k => k.key === key);

  if (!existing) {
    return res.status(404).json({ error: "Key not found" });
  }

  if (existing.expiresAt <= now) {
    return res.status(403).json({ error: "Key has expired" });
  }

  // Optional: enforce HWID locking
  if (existing.hwid && existing.hwid !== hwid) {
    return res.status(403).json({ error: "Key is bound to a different HWID" });
  }

  // If HWID not set yet, bind it
  if (!existing.hwid) {
    existing.hwid = hwid;
    saveKeys();
  }

  await sendWebhookLog(
    "Key Validated",
    `**HWID:** \`${hwid}\`\n**Key:** \`${existing.key}\`\n**Expires:** <t:${Math.floor(existing.expiresAt/1000)}:R>`,
    0x00FF00
  );

  res.json(existing);
});

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

  console.log("No existing key found - generating new");

  const newKey = {
    id: uuidv4(),
    key: generateKey(),
    hwid,
    createdAt: now,
    expiresAt: now + 24 * 60 * 60 * 1000
  };

  keys.push(newKey);
  saveKeys();

  await sendWebhookLog(
    "New Key Generated",
    `**HWID:** \`${hwid}\`\n**Key:** \`${newKey.key}\`\n**Expires:** <t:${Math.floor(newKey.expiresAt/1000)}:R>`,
    0xFFFF00
  );

  res.json(newKey);
});

// Admin routes (unchanged)
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "adminpanel.html")));
app.get("/api/admin/keys", authAdmin, (req, res) => res.json(keys));
app.post("/api/admin/extend", authAdmin, (req, res) => {
  const key = keys.find(k => k.id === req.body.id);
  if (!key) return res.status(404).json({ error: "Not found" });
  key.expiresAt += req.body.hours * 60 * 60 * 1000;
  saveKeys();
  res.json({ success: true });
});
app.post("/api/admin/reset-hwid", authAdmin, (req, res) => {
  const key = keys.find(k => k.id === req.body.id);
  if (!key) return res.status(404).json({ error: "Not found" });
  key.hwid = null;
  saveKeys();
  res.json({ success: true });
});
app.post("/api/admin/revoke", authAdmin, (req, res) => {
  keys = keys.filter(k => k.id !== req.body.id);
  saveKeys();
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Homerware Key Server running on port ${PORT}`);
});
