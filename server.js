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

async function redeemCode() {
  const code = document.getElementById("promoCode").value.trim();
  if (!code) return alert("Enter a valid code!");

  try {
    const res = await fetch(`${API}/redeem-code`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-hwid": generateHWID()
      },
      body: JSON.stringify({ code })
    });
    const data = await res.json();
    if (data.success) {
      alert(`Success! Your key expires in ${data.expiresAtText}`);
      timerEl.textContent = data.expiresAtText;
    } else {
      alert("Invalid or expired code.");
    }
  } catch(err) {
    alert("Server error, try again later.");
  }
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
app.post("/api/get-key", (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ success: false, message: "Missing key or hwid" });

    let validKey = null;
    for (const k of store.values()) {
        // Key matches AND either permanent or not expired
        if (k.key === key && (k.expiresAt === Infinity || k.expiresAt > Date.now())) {
            validKey = k;
            break;
        }
    }

    if (!validKey) return res.json({ success: false, message: "Invalid or expired key" });

    // Optional: Assign HWID if not already assigned
    if (!validKey.hwid) validKey.hwid = hwid;

    res.json({
        success: true,
        key: validKey.key,
        hwid: validKey.hwid,
        createdAt: validKey.createdAt,
        expiresAt: validKey.expiresAt
    });
});

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
