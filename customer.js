const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const router = express.Router();

/* ================= MODELS ================= */

const customerSchema = new mongoose.Schema(
    {
        mobile: { type: String, required: true, unique: true },
        name: { type: String, trim: true, default: "" },
        email: { type: String, trim: true, lowercase: true, default: "" },
        city: { type: String, trim: true, default: "Jaipur" },
        area: { type: String, trim: true, default: "" },
        pincode: { type: String, trim: true, default: "" },
        address: { type: String, trim: true, default: "" },
        profileComplete: { type: Boolean, default: false },
        lastLoginAt: { type: Date }
    },
    { timestamps: true }
);
const Customer = mongoose.models.Customer || mongoose.model("Customer", customerSchema);

const otpSchema = new mongoose.Schema({
    mobile: { type: String, required: true, unique: true },
    otpHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    lastSentAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true }
});
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // expired OTP auto-delete
const Otp = mongoose.models.Otp || mongoose.model("Otp", otpSchema);

/* ================= OTP SERVICE ================= */
/* Real OTP lagane ke liye SIRF yahi section badalna hai. */

const OTP_MODE = process.env.OTP_MODE || "dev"; // "dev" | "live"
const DEV_OTP = "123456";
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 30 * 1000;
const MAX_ATTEMPTS = 5;

function generateOtp() {
    return OTP_MODE === "dev" ? DEV_OTP : String(crypto.randomInt(100000, 1000000));
}

// >>> YAHAN real SMS provider lagana hai (MSG91 / Fast2SMS / Twilio) <<<
async function deliverOtp(mobile, otp) {
    if (OTP_MODE === "dev") {
        console.log(`[DEV OTP] ${mobile} -> ${otp}`);
        return;
    }
    // Example: await msg91.send({ mobile: "91" + mobile, otp });
    throw new Error("SMS provider abhi configure nahi hai.");
}

const hashOtp = (mobile, otp) =>
    crypto.createHash("sha256").update(`${mobile}:${otp}:${process.env.JWT_SECRET}`).digest("hex");

class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

async function sendOtp(mobile) {
    const existing = await Otp.findOne({ mobile });
    if (existing && Date.now() - existing.lastSentAt.getTime() < RESEND_COOLDOWN_MS) {
        throw new HttpError(429, "Thodi der baad dobara OTP maango.");
    }
    const otp = generateOtp();
    await Otp.findOneAndUpdate(
        { mobile },
        { otpHash: hashOtp(mobile, otp), attempts: 0, lastSentAt: new Date(), expiresAt: new Date(Date.now() + OTP_EXPIRY_MS) },
        { upsert: true, new: true }
    );
    await deliverOtp(mobile, otp);
}

async function verifyOtp(mobile, otp) {
    const record = await Otp.findOne({ mobile });
    if (!record || record.expiresAt < new Date()) throw new HttpError(400, "OTP expire ho gaya. Naya OTP maango.");
    if (record.attempts >= MAX_ATTEMPTS) throw new HttpError(429, "Bahut galat attempts. Naya OTP maango.");
    if (record.otpHash !== hashOtp(mobile, otp)) {
        record.attempts += 1;
        await record.save();
        throw new HttpError(400, "Galat OTP.");
    }
    await Otp.deleteOne({ mobile }); // OTP ek hi baar chalega
}

/* ================= JWT + MIDDLEWARE ================= */

const signToken = (customer) =>
    jwt.sign({ id: customer._id, role: "customer" }, process.env.JWT_SECRET, { expiresIn: "30d" });

async function requireCustomer(req, res, next) {
    try {
        const header = req.headers.authorization || "";
        const token = header.startsWith("Bearer ") ? header.slice(7) : null;
        if (!token) throw new HttpError(401, "Login required.");
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        if (payload.role !== "customer") throw new HttpError(403, "Not allowed.");
        const customer = await Customer.findById(payload.id);
        if (!customer) throw new HttpError(401, "Account nahi mila.");
        req.customer = customer;
        next();
    } catch (err) {
        res.status(err.status || 401).json({ message: err.status ? err.message : "Session expire ho gaya. Dobara login karo." });
    }
}

/* ================= ROUTES ================= */

const isMobile = (v) => /^[6-9]\d{9}$/.test(String(v || ""));
const handle = (fn) => async (req, res) => {
    try { await fn(req, res); }
    catch (err) {
        if (!err.status) console.error("Customer auth error:", err);
        res.status(err.status || 500).json({ message: err.status ? err.message : "Server error." });
    }
};
const publicCustomer = (c) => ({
    id: c._id, mobile: c.mobile, name: c.name, email: c.email,
    city: c.city, area: c.area, pincode: c.pincode, address: c.address,
    profileComplete: c.profileComplete
});

// 1) OTP bhejo
router.post("/send-otp", handle(async (req, res) => {
    const mobile = String(req.body.mobile || "").trim();
    if (!isMobile(mobile)) throw new HttpError(400, "Valid 10-digit mobile number daalo.");
    await sendOtp(mobile);
    res.json({ message: "OTP bhej diya gaya.", devMode: OTP_MODE === "dev" });
}));

// 2) OTP verify -> login (naya customer ho to account ban jata hai)
router.post("/verify-otp", handle(async (req, res) => {
    const mobile = String(req.body.mobile || "").trim();
    const otp = String(req.body.otp || "").trim();
    if (!isMobile(mobile) || !/^\d{6}$/.test(otp)) throw new HttpError(400, "Mobile ya OTP galat hai.");
    await verifyOtp(mobile, otp);

    let customer = await Customer.findOne({ mobile });
    const isNewUser = !customer;
    if (!customer) customer = new Customer({ mobile });
    customer.lastLoginAt = new Date();
    await customer.save();

    res.json({
        message: "Login successful.",
        token: signToken(customer),
        isNewUser,
        needsProfile: !customer.profileComplete,
        customer: publicCustomer(customer)
    });
}));

// 3) Apni profile dekho (session check)
router.get("/me", requireCustomer, handle(async (req, res) => {
    res.json({ customer: publicCustomer(req.customer) });
}));

// 4) Profile save / update
router.put("/me", requireCustomer, handle(async (req, res) => {
    const name = String(req.body.name || "").trim().slice(0, 60);
    const email = String(req.body.email || "").trim().slice(0, 100);
    const city = String(req.body.city || "").trim().slice(0, 50);
    const area = String(req.body.area || "").trim().slice(0, 60);
    const pincode = String(req.body.pincode || "").trim();
    const address = String(req.body.address || "").trim().slice(0, 250);

    if (name.length < 2) throw new HttpError(400, "Apna naam daalo.");
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, "Valid email daalo.");
    if (pincode && !/^\d{6}$/.test(pincode)) throw new HttpError(400, "Pincode 6 digit ka hona chahiye.");

    Object.assign(req.customer, { name, email, city: city || "Jaipur", area, pincode, address, profileComplete: true });
    await req.customer.save();
    res.json({ message: "Profile saved.", customer: publicCustomer(req.customer) });
}));

module.exports = { router, requireCustomer, Customer };
