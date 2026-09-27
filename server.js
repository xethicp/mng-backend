// Mars Nova Global — backend starter
// Handles: order creation, payment verification, webhook, WhatsApp send trigger.

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const Razorpay = require("razorpay");

const app = express();
app.set("trust proxy", 1); 
app.use(helmet()); 

const allowedOrigin = process.env.ALLOWED_ORIGIN;
app.use(cors(allowedOrigin ? { origin: allowedOrigin } : {}));

app.use(express.json({ limit: "50kb" })); 

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,     
  max: 60,                 
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests — please slow down and try again shortly." },
});
app.use("/api/", apiLimiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 15,                       
  idleTimeoutMillis: 30000,      
  connectionTimeoutMillis: 5000, 
});
pool.on("error", (err) => {
  console.error("Unexpected database pool error (handled, server still running):", err.message);
});

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

function validateBookingInput(body) {
  const { eventId, passName, qty } = body;
  if (typeof eventId !== "string" || !/^[a-zA-Z0-9_-]{1,40}$/.test(eventId)) {
    return "Invalid or missing event.";
  }
  if (typeof passName !== "string" || passName.length < 1 || passName.length > 60) {
    return "Invalid or missing pass type.";
  }
  const qtyNum = Number(qty);
  if (!Number.isInteger(qtyNum) || qtyNum < 1 || qtyNum > 10) {
    return "Quantity must be a whole number between 1 and 10.";
  }
  return null; 
}

function isNonEmptyString(v, maxLen) {
  return typeof v === "string" && v.trim().length > 0 && v.length <= (maxLen || 200);
}

// Helper: Smart Pass Lookup with Case-Insensitive & Fallback Matching
async function findPass(eventId, passName) {
  // 1. Exact match
  let passRes = await pool.query(
    "select id, price from passes where event_id=$1 and name=$2",
    [eventId, passName]
  );
  if (passRes.rows.length) return passRes.rows[0];

  // 2. Case-insensitive / whitespace-trimmed match
  passRes = await pool.query(
    "select id, price from passes where event_id=$1 and LOWER(TRIM(name))=LOWER(TRIM($2))",
    [eventId, passName]
  );
  if (passRes.rows.length) return passRes.rows[0];

  // 3. Fallback: If only 1 pass exists for this event, use it automatically
  passRes = await pool.query(
    "select id, price from passes where event_id=$1",
    [eventId]
  );
  if (passRes.rows.length === 1) return passRes.rows[0];

  return null;
}

// ---------------------------------------------------------------
// 1. Create a Razorpay order.
// ---------------------------------------------------------------
app.post("/api/create-order", async (req, res) => {
  try {
    const validationError = validateBookingInput(req.body);
    if (validationError) return res.status(400).json({ error: validationError });
    const { eventId, passName, qty } = req.body;

    const pass = await findPass(eventId, passName);
    if (!pass) return res.status(400).json({ error: "Invalid pass" });

    const rate = Number(pass.price);
    const amount = Math.round(rate * Number(qty)); 
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "Could not compute a valid amount" });
    }
    const order = await razorpay.orders.create({
      amount: amount * 100, 
      currency: "INR",
      receipt: `mng_${Date.now()}`,
    });

    res.json({ orderId: order.id, amount, key: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not create order" });
  }
});

// ---------------------------------------------------------------
// 2. Verify payment signature and write booking.
// ---------------------------------------------------------------
app.post("/api/verify-payment", async (req, res) => {
  try {
    const {
      razorpay_order_id, razorpay_payment_id, razorpay_signature,
      eventId, passName, qty, buyerName, buyerEmail, buyerWhatsapp,
      squadCode, agentId, channel,
    } = req.body;

    const validationError = validateBookingInput(req.body);
    if (validationError) return res.status(400).json({ error: validationError });
    if (!isNonEmptyString(razorpay_order_id) || !isNonEmptyString(razorpay_payment_id) || !isNonEmptyString(razorpay_signature)) {
      return res.status(400).json({ error: "Missing payment verification details." });
    }
    if (!isNonEmptyString(buyerName, 120)) return res.status(400).json({ error: "Buyer name is required." });
    if (!isNonEmptyString(buyerEmail, 160) || !buyerEmail.includes("@")) return res.status(400).json({ error: "A valid buyer email is required." });
    if (!isNonEmptyString(buyerWhatsapp, 15) || !/^\d{10,15}$/.test(buyerWhatsapp)) return res.status(400).json({ error: "A valid WhatsApp number is required." });

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (expected !== razorpay_signature) {
      return res.status(400).json({ error: "Signature mismatch — payment not verified" });
    }

    const pass = await findPass(eventId, passName);
    if (!pass) return res.status(400).json({ error: "Invalid pass" });

    const passId = pass.id;
    const rate = Number(pass.price);
    const amount = Math.round(rate * Number(qty));
    const code = `MNG-${eventId.toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;

    await pool.query(
      `insert into bookings
       (code,event_id,pass_id,qty,rate,amount,buyer_name,buyer_email,buyer_whatsapp,
        channel,agent_id,squad_code,status,razorpay_order_id,razorpay_payment_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'paid',$13,$14)`,
      [code, eventId, passId, qty, rate, amount, buyerName, buyerEmail, buyerWhatsapp,
       (channel === "Agent" ? "Agent" : "Website"), (isNonEmptyString(agentId, 60) ? agentId : null), (isNonEmptyString(squadCode, 60) ? squadCode : null),
       razorpay_order_id, razorpay_payment_id]
    );

    await pool.query(
      "update events set sold = least(sold + $1, capacity) where id=$2",
      [qty, eventId]
    );

    sendWhatsAppPass({ to: buyerWhatsapp, code, eventId, qty, amount }).catch(console.error);

    res.json({ ok: true, code, amount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ---------------------------------------------------------------
// 3. Webhook
// ---------------------------------------------------------------
app.post("/api/razorpay-webhook", express.raw({ type: "*/*" }), (req, res) => {
  const signature = req.headers["x-razorpay-signature"];
  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)
    .update(req.body)
    .digest("hex");

  if (signature !== expected) return res.status(400).send("Invalid webhook signature");

  const event = JSON.parse(req.body);
  console.log("Webhook received:", event.event);

  res.json({ received: true });
});

// ---------------------------------------------------------------
// 4. WhatsApp send
// ---------------------------------------------------------------
async function sendWhatsAppPass({ to, code, eventId, qty, amount }) {
  if (!process.env.WHATSAPP_ACCESS_TOKEN) {
    console.log("WhatsApp not configured yet — skipping send for", code);
    return;
  }
  const url = `https://graph.facebook.com/v20.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;
  const body = {
    messaging_product: "whatsapp",
    to: `91${to}`,
    type: "template",
    template: {
      name: process.env.WHATSAPP_TEMPLATE_NAME,
      language: { code: "en" },
      components: [
        { type: "body", parameters: [
          { type: "text", text: code },
          { type: "text", text: String(qty) },
          { type: "text", text: `₹${amount}` },
        ] },
      ],
    },
  };
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.WHATSAPP_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) console.error("WhatsApp send failed:", await resp.text());
}

app.get("/health", (req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------
// Gate Verification
// ---------------------------------------------------------------
app.post("/api/gate/verify", async (req, res) => {
  try {
    const pin = req.headers["x-gate-pin"];
    if (process.env.GATE_PIN && pin !== process.env.GATE_PIN) {
      return res.status(401).json({ status: "unauthorized", message: "Wrong gate PIN." });
    }
    const code = String(req.body.code || "").trim();
    if (!code) return res.status(400).json({ status: "not_found", message: "No code provided." });

    if (/^mng_sec_/i.test(code)) {
      const sq = await pool.query("select * from squads where access_id=$1", [code]);
      if (!sq.rows.length) return res.json({ status: "not_found", message: "No squad Access Card matches this code." });
      const squad = sq.rows[0];
      if (squad.revoked) return res.json({ status: "revoked", name: squad.name, message: "This Access Card has been revoked." });
      if (squad.checked_in) return res.json({ status: "duplicate", name: squad.name, checkedInAt: squad.checked_in_at, message: "Already checked in." });
      await pool.query("update squads set checked_in=true, checked_in_at=now() where access_id=$1", [code]);
      return res.json({ status: "granted", name: squad.name, type: "Squad Access Card" });
    }

    if (/^MNG-/i.test(code)) {
      const b = await pool.query("select * from bookings where code=$1", [code]);
      if (!b.rows.length) return res.json({ status: "not_found", message: "No pass matches this code." });
      const booking = b.rows[0];
      if (booking.checked_in) return res.json({ status: "duplicate", name: booking.buyer_name, checkedInAt: booking.checked_in_at, message: "Already checked in." });
      await pool.query("update bookings set checked_in=true, checked_in_at=now() where code=$1", [code]);
      return res.json({ status: "granted", name: booking.buyer_name, type: booking.pass_id ? "Individual pass" : "Pass", event: booking.event_id, qty: booking.qty });
    }

    return res.json({ status: "not_found", message: "This isn't an MNG pass code." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error", message: "Could not verify — try again." });
  }
});

app.use((err, req, res, next) => {
  console.error("Unhandled route error:", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Something went wrong on our end. Please try again." });
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection (server still running):", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught exception — restarting cleanly:", err);
  process.exit(1);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`MNG backend listening on :${port}`));
