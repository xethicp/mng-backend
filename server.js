// Mars Nova Global — backend starter
// Handles: order creation, payment verification, webhook, WhatsApp send trigger.
// This is a STARTING POINT — review auth, error handling and rate limiting before going live with real money.

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");
const Razorpay = require("razorpay");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ---------------------------------------------------------------
// 1. Create a Razorpay order. The AMOUNT IS COMPUTED SERVER-SIDE
//    from the database — never trust an amount sent by the browser.
// ---------------------------------------------------------------
app.post("/api/create-order", async (req, res) => {
  try {
    const { eventId, passName, qty } = req.body;
    const passRes = await pool.query(
      "select id, price from passes where event_id=$1 and name=$2",
      [eventId, passName]
    );
    if (!passRes.rows.length) return res.status(400).json({ error: "Invalid pass" });

    const rate = Number(passRes.rows[0].price);
    const amount = Math.round(rate * Number(qty)); // whole rupees
    const order = await razorpay.orders.create({
      amount: amount * 100, // Razorpay wants paise
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
// 2. Verify payment signature after the Razorpay checkout closes,
//    THEN write the booking. This is the step the old front-end
//    demo skipped entirely — never issue a pass before this passes.
// ---------------------------------------------------------------
app.post("/api/verify-payment", async (req, res) => {
  try {
    const {
      razorpay_order_id, razorpay_payment_id, razorpay_signature,
      eventId, passName, qty, buyerName, buyerEmail, buyerWhatsapp,
      squadCode, agentId, channel,
    } = req.body;

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (expected !== razorpay_signature) {
      return res.status(400).json({ error: "Signature mismatch — payment not verified" });
    }

    const passRes = await pool.query(
      "select id, price from passes where event_id=$1 and name=$2",
      [eventId, passName]
    );
    if (!passRes.rows.length) return res.status(400).json({ error: "Invalid pass" });
    const passId = passRes.rows[0].id;
    const rate = Number(passRes.rows[0].price);
    const amount = Math.round(rate * Number(qty));
    const code = `MNG-${eventId.toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;

    await pool.query(
      `insert into bookings
       (code,event_id,pass_id,qty,rate,amount,buyer_name,buyer_email,buyer_whatsapp,
        channel,agent_id,squad_code,status,razorpay_order_id,razorpay_payment_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'paid',$13,$14)`,
      [code, eventId, passId, qty, rate, amount, buyerName, buyerEmail, buyerWhatsapp,
       channel || "Website", agentId || null, squadCode || null,
       razorpay_order_id, razorpay_payment_id]
    );

    await pool.query(
      "update events set sold = least(sold + $1, capacity) where id=$2",
      [qty, eventId]
    );

    // Fire-and-forget WhatsApp send — don't block the response on it.
    sendWhatsAppPass({ to: buyerWhatsapp, code, eventId, qty, amount }).catch(console.error);

    res.json({ ok: true, code, amount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ---------------------------------------------------------------
// 3. Webhook — Razorpay calls this server-to-server as a backup,
//    in case the customer closes the browser right after paying.
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
  // TODO: reconcile event.payload.payment.entity.order_id against your bookings table
  // in case /api/verify-payment never ran (dropped connection, etc).

  res.json({ received: true });
});

// ---------------------------------------------------------------
// 4. WhatsApp send via Meta Cloud API (requires an approved template).
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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`MNG backend listening on :${port}`));
