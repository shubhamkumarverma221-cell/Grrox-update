require("dotenv").config();

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 16) {
    console.error("JWT_SECRET missing/chhota hai. .env me kam se kam 16 akshar ka JWT_SECRET daalo.");
    process.exit(1);
}

const express = require("express");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const cors = require("cors");

const Product = require("./product");
const Business = require("./business");

const app = express();
const PORT = process.env.PORT || 5000;

mongoose.set("bufferCommands", false);

app.set("trust proxy", 1);
app.use(express.json({ limit: "8mb" })); // 4MB image base64 me ~5.4MB banti hai
const ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map(x => x.trim()).filter(Boolean);
app.use(cors(ORIGINS.length ? { origin: ORIGINS } : undefined));
app.use((req, res, next) => {
    res.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer" });
    next();
});

/* ---- simple rate limit (OTP / admin login) ---- */
const hits = new Map();
const limit = (max, windowMs) => (req, res, next) => {
    const k = req.ip + req.baseUrl + req.path, now = Date.now();
    const h = (hits.get(k) || []).filter(t => now - t < windowMs);
    if (h.length >= max) return res.status(429).json({ message: "Bahut zyada koshish. Thodi der baad try karo." });
    h.push(now); hits.set(k, h); next();
};
setInterval(() => hits.clear(), 60 * 60 * 1000).unref();
for (const base of ["/api/customers", "/api/business-auth"]) {
    app.use(base + "/send-otp", limit(5, 10 * 60 * 1000));
    app.use(base + "/verify-otp", limit(10, 10 * 60 * 1000));
}
app.use("/api/admin/login", limit(5, 10 * 60 * 1000));
app.use("/api", (req, res, next) => mongoose.connection.readyState === 1 ? next()
    : res.status(503).json({ message: "Database unavailable. MongoDB connection check karo." }));

// Keep the legacy frontend product/business routes working for the prototype UI.
// The newer protected business-auth routes remain available for authenticated flows.

//* GRROX CUSTOMER LOGIN - *// 
const cryptoLib = require("crypto");
const jwtLib = require("jsonwebtoken");
const customerRouter = express.Router();

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
        grroxId: {
            type: String,
            unique: true,
            sparse: true
        },
        wishlist: { type: [String], default: [] },
        lastLoginAt: { type: Date }
    },
    { timestamps: true }
);
const Customer = mongoose.models.Customer || mongoose.model("Customer", customerSchema);
async function generateGrroxCustomerId() {
    let id;
    let exists = true;

    while (exists) {
        id = String(
            Math.floor(10000000 + Math.random() * 90000000)
        );

        exists = await Customer.exists({ grroxId: id });
    }

    return id;
}

const otpSchema = new mongoose.Schema({
    mobile: { type: String, required: true, unique: true },
    otpHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    lastSentAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true }
});
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // expired OTP auto-delete
const Otp = mongoose.models.Otp || mongoose.model("Otp", otpSchema);

/* ---- Deal claims: kis customer ne kaunsi deal claim ki ---- */
const claimSchema = new mongoose.Schema({
    customerId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    productId: { type: mongoose.Schema.Types.ObjectId, required: true },
    businessId: { type: mongoose.Schema.Types.ObjectId, default: null, index: true },
    dealName: { type: String, default: "" },
    shopName: { type: String, default: "" },
    price: { type: Number, default: 0 },
    customerName: { type: String, default: "" },
    customerMobile: { type: String, default: "" },
    status: { type: String, enum: ["Pending", "Redeemed"], default: "Pending" }
}, { timestamps: true });
claimSchema.index({ customerId: 1, productId: 1 }, { unique: true }); // ek customer ek deal sirf ek baar claim kare
const Claim = mongoose.models.Claim || mongoose.model("Claim", claimSchema);
const claimCode = (c) => String(c._id).slice(-6).toUpperCase();
const publicClaim = (c) => ({
    _id: c._id, code: claimCode(c), dealName: c.dealName, shopName: c.shopName,
    price: c.price, status: c.status, createdAt: c.createdAt
});

/* ================= OTP SERVICE ================= */
/* Real OTP lagane ke liye SIRF yahi section badalna hai. */

const OTP_MODE = process.env.OTP_MODE || "dev"; // "dev" | "live"
const DEV_OTP = "123456";
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 30 * 1000;
const MAX_ATTEMPTS = 5;

function generateOtp() {
    return OTP_MODE === "dev" ? DEV_OTP : String(cryptoLib.randomInt(100000, 1000000));
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
    cryptoLib.createHash("sha256").update(`${mobile}:${otp}:${process.env.JWT_SECRET}`).digest("hex");

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
    jwtLib.sign({ id: customer._id, role: "customer" }, process.env.JWT_SECRET, { expiresIn: "30d" });

async function requireCustomer(req, res, next) {
    try {
        const header = req.headers.authorization || "";
        const token = header.startsWith("Bearer ") ? header.slice(7) : null;
        if (!token) throw new HttpError(401, "Login required.");
        const payload = jwtLib.verify(token, process.env.JWT_SECRET);
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
    id: c._id,
    grroxId: c.grroxId,
    mobile: c.mobile,
    name: c.name,
    email: c.email,
    city: c.city,
    area: c.area,
    pincode: c.pincode,
    address: c.address,
    profileComplete: c.profileComplete
});

// 1) OTP bhejo
customerRouter.post("/send-otp", handle(async (req, res) => {
    const mobile = String(req.body.mobile || "").trim();
    if (!isMobile(mobile)) throw new HttpError(400, "Valid 10-digit mobile number daalo.");
    await sendOtp(mobile);
    res.json({ message: "OTP bhej diya gaya.", devMode: OTP_MODE === "dev" });
}));

// 2) OTP verify -> login (naya customer ho to account ban jata hai)
customerRouter.post("/verify-otp", handle(async (req, res) => {
    const mobile = String(req.body.mobile || "").trim();
    const otp = String(req.body.otp || "").trim();
    if (!isMobile(mobile) || !/^\d{6}$/.test(otp)) throw new HttpError(400, "Mobile ya OTP galat hai.");
    await verifyOtp(mobile, otp);

    let customer = await Customer.findOne({ mobile });
    const isNewUser = !customer;

    if (!customer) {
        customer = new Customer({
            mobile,
            grroxId: await generateGrroxCustomerId()
        });
    }

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
customerRouter.get("/me", requireCustomer, handle(async (req, res) => {
    res.json({ customer: publicCustomer(req.customer) });
}));

// 4) Profile save / update
customerRouter.put("/me", requireCustomer, handle(async (req, res) => {
    const name = String(req.body.name || "").trim().slice(0, 60);
    const email = String(req.body.email || "").trim().slice(0, 100);
    const city = String(req.body.city || "").trim().slice(0, 50);
    const area = String(req.body.area || "").trim().slice(0, 60);
    const pincode = String(req.body.pincode || "").trim();
    const address = String(req.body.address || "").trim().slice(0, 250);

    if (name.length < 2) throw new HttpError(400, "Apna naam daalo.");
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, "Valid email daalo.");
    if (pincode && !/^\d{6}$/.test(pincode)) {
        throw new HttpError(400, "Pincode 6 digit ka hona chahiye.");
    }

    validateJaipurLocation(
        city || "Jaipur",
        area,
        pincode
    );

    Object.assign(req.customer, {
        name,
        email,
        city: "Jaipur",
        area,
        pincode,
        address,
        profileComplete: true
    });
    await req.customer.save();
    res.json({ message: "Profile saved.", customer: publicCustomer(req.customer) });
}));

// 5) Wishlist (DB me save: phone/browser badalne par bhi safe)
const cleanIds = (arr) =>
    [...new Set((Array.isArray(arr) ? arr : []).map(String).filter((id) => mongoose.isValidObjectId(id)))].slice(0, 200);

customerRouter.get("/wishlist", requireCustomer, handle(async (req, res) => {
    const ids = cleanIds(req.customer.wishlist);
    const alive = ids.length ? await Product.find({ _id: { $in: ids } }).select("_id") : [];
    res.json({ ids: alive.map((p) => String(p._id)) });
}));

customerRouter.put("/wishlist", requireCustomer, handle(async (req, res) => {
    req.customer.wishlist = cleanIds(req.body && req.body.ids);
    await req.customer.save();
    res.json({ ids: req.customer.wishlist });
}));

// 6) Meri claimed deals
customerRouter.get("/claims", requireCustomer, handle(async (req, res) => {
    const claims = await Claim.find({ customerId: req.customer._id }).sort({ _id: -1 }).limit(100);
    res.json({ claims: claims.map(publicClaim) });
}));

// Routes ko server se jodo
app.use("/api/customers", customerRouter);
/* ===================== CUSTOMER LOGIN END ===================== */

/* ======================================================================
   GRROX BUSINESS LOGIN (OTP + JWT) + SECURE SHOP / DEALS */
const BUSINESS_MODEL = "Business";
const PRODUCT_MODEL = "Product";
const DEAL_CATEGORIES = ["Electronics", "Clothing", "Grocery", "Stationery", "Electrical", "Food", "Salon", "Furniture", "Other"];
const bizRouter = express.Router();

const getModel = (name) => {
    const m = mongoose.models[name];
    if (!m) throw new HttpError(500, `"${name}" model nahi mila. server.js me apne model ka naam dekho aur BUSINESS_MODEL / PRODUCT_MODEL badlo.`);
    return m;
};
const bizStr = (v, max) => String(v == null ? "" : v).trim().slice(0, max);
const isBizMobile = (v) => /^\d{10}$/.test(String(v || ""));
const signBizToken = (b) => jwtLib.sign({ id: b._id, role: "business" }, process.env.JWT_SECRET, { expiresIn: "30d" });
const bizPub = (b) => ({
    _id: b._id, businessName: b.businessName, ownerName: b.ownerName, mobile: b.mobile,
    category: b.category, address: b.address, city: b.city, area: b.area,
    pincode: b.pincode, shopStatus: b.shopStatus || "Open", verificationStatus: b.verificationStatus || "Unverified"
});
const bearer = (req) => {
    const h = req.headers.authorization || "";
    return h.startsWith("Bearer ") ? h.slice(7) : null;
};

/* ---------- Middleware: sirf login business andar aa sakta hai ---------- */
async function requireBusiness(req, res, next) {
    try {
        const token = bearer(req);
        if (!token) throw new HttpError(401, "Login required.");
        const payload = jwtLib.verify(token, process.env.JWT_SECRET);
        if (payload.role !== "business") throw new HttpError(403, "Not allowed.");
        const business = await getModel(BUSINESS_MODEL).findById(payload.id);
        if (!business) throw new HttpError(401, "Business account nahi mila.");
        req.business = business;
        next();
    } catch (err) {
        res.status(err.status || 401).json({ message: err.status ? err.message : "Session expire ho gaya. Dobara login karo." });
    }
}

/* ---------- Validation ---------- */
const SHOP_FIELDS = { businessName: [2, 80], ownerName: [2, 60], category: [1, 40], address: [5, 250], city: [2, 50], area: [2, 60] };
/* ================= JAIPUR LOCATION VALIDATION ================= */

const JAIPUR_PINCODES = new Set([
    "302001",
    "302002",
    "302003",
    "302004",
    "302005",
    "302006",
    "302012",
    "302013",
    "302015",
    "302016",
    "302017",
    "302018",
    "302019",
    "302020",
    "302021",
    "302022",
    "302025",
    "302026",
    "302027",
    "302028",
    "302029",
    "302031",
    "302033",
    "302034",
    "302036",
    "302037",
    "302039"
]);

function validateJaipurLocation(city, area, pincode) {
    const cleanCity = String(city || "").trim().toLowerCase();
    const cleanArea = String(area || "").trim();
    const cleanPincode = String(pincode || "").trim();

    if (cleanCity !== "jaipur") {
        throw new HttpError(
            400,
            "GRROX abhi sirf Jaipur me available hai."
        );
    }

    if (!JAIPUR_PINCODES.has(cleanPincode)) {
        throw new HttpError(
            400,
            "Ye Jaipur ka valid PIN code nahi hai."
        );
    }

    if (cleanArea.length < 2) {
        throw new HttpError(
            400,
            "Jaipur ka valid area daalo."
        );
    }

    return true;
}
function cleanShop(b, partial) {
    const out = {};
    for (const [k, [min, max]] of Object.entries(SHOP_FIELDS)) {
        if (partial && b[k] === undefined) continue;
        const v = bizStr(b[k], max);
        if (v.length < min) throw new HttpError(400, `${k} sahi se bharo.`);
        out[k] = v;
    }
    if (!partial || b.pincode !== undefined) {
        const p = bizStr(b.pincode, 6);

        if (!/^\d{6}$/.test(p)) {
            throw new HttpError(
                400,
                "Pincode 6 digit ka hona chahiye."
            );
        }

        out.pincode = p;
    }

    if (!partial || b.city !== undefined || b.area !== undefined || b.pincode !== undefined) {
        const checkCity = out.city || b.city || "";
        const checkArea = out.area || b.area || "";
        const checkPincode = out.pincode || b.pincode || "";

        validateJaipurLocation(
            checkCity,
            checkArea,
            checkPincode
        );

        out.city = "Jaipur";
    }
    if (b.shopStatus !== undefined) {
        if (!["Open", "Closed"].includes(b.shopStatus)) throw new HttpError(400, "Shop status galat hai.");
        out.shopStatus = b.shopStatus;
    }
    return out;
}

function cleanDeal(b, partial) {
    const out = {};
    const has = (k) => b[k] !== undefined;
    if (!partial || has("name")) {
        const v = bizStr(b.name, 100);
        if (v.length < 2) throw new HttpError(400, "Deal ka naam kam se kam 2 akshar ka ho.");
        out.name = v;
    }
    if (!partial || has("price")) {
        const v = Number(b.price);
        if (!(v > 0 && v <= 10000000)) throw new HttpError(400, "Deal price sahi daalo.");
        out.price = v;
    }
    if (!partial || has("originalPrice")) {
        const v = Number(b.originalPrice || 0);
        if (!(v >= 0 && v <= 10000000)) throw new HttpError(400, "MRP sahi daalo.");
        out.originalPrice = v;
    }
    if (!partial || has("category")) {
        const v = bizStr(b.category, 40);
        if (!DEAL_CATEGORIES.includes(v)) throw new HttpError(400, "Category list me se chuno.");
        out.category = v;
    }
    if (has("offer")) out.offer = bizStr(b.offer, 40);
    if (has("description")) out.description = bizStr(b.description, 500);
    if (has("image")) {

        const v = String(
            b.image == null ? "" : b.image
        ).trim();

        /* Empty image allowed */
        if (!v) {
            out.image = "";
        }

        /* Uploaded Base64 image */
        else if (
            /^data:image\/(jpeg|png|webp);base64,/i.test(v)
        ) {

            /* Approximate 4MB limit */
            if (v.length > 5.5 * 1024 * 1024) {
                throw new HttpError(
                    400,
                    "Image maximum 4MB ki honi chahiye."
                );
            }

            out.image = v;
        }

        /* Old image URL bhi support rahega */
        else if (v.length <= 2000 && /^https?:\/\/[^\s"'<>]+$/i.test(v)) {

            out.image = v;

        }

        else {

            throw new HttpError(
                400,
                "Invalid image format."
            );
        }
    }
    return out;
}

const checkPrices = (price, mrp) => {
    if (mrp > 0 && price > mrp) throw new HttpError(400, "Deal price MRP se zyada nahi ho sakti.");
};

/* ---------- AUTH ROUTES ---------- */

bizRouter.post("/send-otp", handle(async (req, res) => {
    const mobile = bizStr(req.body.mobile, 10);
    if (!isBizMobile(mobile)) throw new HttpError(400, "Valid 10-digit mobile number daalo.");
    await sendOtp(mobile);
    res.json({ message: "OTP bhej diya gaya.", devMode: OTP_MODE === "dev" });
}));

// OTP sahi + account hai -> login token. Account nahi hai -> signupToken (15 min)
bizRouter.post("/verify-otp", handle(async (req, res) => {
    const mobile = bizStr(req.body.mobile, 10);
    const otp = bizStr(req.body.otp, 6);
    if (!isBizMobile(mobile) || !/^\d{6}$/.test(otp)) throw new HttpError(400, "Mobile ya OTP galat hai.");
    await verifyOtp(mobile, otp);

    const business = await getModel(BUSINESS_MODEL).findOne({ mobile });
    if (business) {
        return res.json({ exists: true, token: signBizToken(business), business: bizPub(business) });
    }
    const signupToken = jwtLib.sign({ mobile, role: "business-signup" }, process.env.JWT_SECRET, { expiresIn: "15m" });
    res.json({ exists: false, signupToken });
}));

// Naya business: mobile body se nahi, verified signupToken se aata hai
bizRouter.post("/signup", handle(async (req, res) => {
    let payload;
    try { payload = jwtLib.verify(bearer(req) || "", process.env.JWT_SECRET); }
    catch (e) { throw new HttpError(401, "OTP verification expire ho gaya. Dobara OTP se verify karo."); }
    if (payload.role !== "business-signup") throw new HttpError(403, "Not allowed.");

    const Business = getModel(BUSINESS_MODEL);
    if (await Business.findOne({ mobile: payload.mobile })) throw new HttpError(409, "Is mobile number se account pehle se hai. Login karo.");

    const data = cleanShop(req.body, false);
    delete data.shopStatus;
    const business = await Business.create({ ...data, mobile: payload.mobile, shopStatus: "Open" });
    res.status(201).json({ token: signBizToken(business), business: bizPub(business) });
}));

/* ---------- MY SHOP (sirf apni shop) ---------- */

bizRouter.get("/me", requireBusiness, handle(async (req, res) => {
    res.json({ business: bizPub(req.business) });
}));

bizRouter.put("/me", requireBusiness, handle(async (req, res) => {
    const data = cleanShop(req.body, true); // mobile aur _id kabhi update nahi hote
    Object.assign(req.business, data);
    await req.business.save();
    if (data.businessName) {
        await getModel(PRODUCT_MODEL).updateMany({ businessId: String(req.business._id) }, { shopName: data.businessName });
    }
    res.json({ message: "Shop updated.", business: bizPub(req.business) });
}));

bizRouter.post("/me/toggle-status", requireBusiness, handle(async (req, res) => {
    req.business.shopStatus = req.business.shopStatus === "Closed" ? "Open" : "Closed";
    await req.business.save();
    res.json({ business: bizPub(req.business) });
}));

/* ---------- MY DEALS (ownership check har jagah) ---------- */

bizRouter.get("/deals", requireBusiness, handle(async (req, res) => {
    const products = await getModel(PRODUCT_MODEL).find({ businessId: String(req.business._id) }).sort({ _id: -1 });
    res.json({ products });
}));

bizRouter.post("/deals", requireBusiness, handle(async (req, res) => {
    const data = cleanDeal(req.body, false);
    checkPrices(data.price, data.originalPrice);
    const product = await getModel(PRODUCT_MODEL).create({
        ...data,
        shopName: req.business.businessName,      // client se nahi, server se
        businessId: String(req.business._id),     // token wale business se
        city: req.business.city || "Jaipur"
    });
    res.status(201).json({ message: "Deal added.", product });
}));

bizRouter.put("/deals/:id", requireBusiness, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Deal nahi mili.");
    const deal = await getModel(PRODUCT_MODEL).findOne({ _id: req.params.id, businessId: String(req.business._id) });
    if (!deal) throw new HttpError(404, "Deal nahi mili.");   // doosre ki deal bhi yahi jawab degi
    const data = cleanDeal(req.body, true);
    checkPrices(data.price ?? deal.price, data.originalPrice ?? deal.originalPrice);
    Object.assign(deal, data);
    await deal.save();
    res.json({ message: "Deal updated.", product: deal });
}));

bizRouter.delete("/deals/:id", requireBusiness, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Deal nahi mili.");
    const r = await getModel(PRODUCT_MODEL).deleteOne({ _id: req.params.id, businessId: String(req.business._id) });
    if (!r.deletedCount) throw new HttpError(404, "Deal nahi mili.");
    res.json({ message: "Deal deleted." });
}));

app.use("/api/business-auth", bizRouter);
/* ===================== BUSINESS LOGIN END ===================== */

function requireDb(res) {
    if (mongoose.connection.readyState !== 1) {
        res.status(503).json({
            message: "Database unavailable. Please check your MongoDB connection."
        });
        return true;
    }
    return false;
}

app.get("/admin", (req, res) => res.sendFile(require("path").join(__dirname, "admin.html")));

// HOME: index.html isi folder me ho to wahi khulega (Business/Backend page nahi)
const fs = require("fs");
const nodePath = require("path");
app.get("/", (req, res) => {
    const indexFile = nodePath.join(__dirname, "index.html");
    if (fs.existsSync(indexFile)) return res.sendFile(indexFile);
    res.json({ message: "GRROX Backend is running!" });
});
app.get("/health", (req, res) => res.json({ ok: true, db: mongoose.connection.readyState === 1 }));

// GET ALL PRODUCTS
app.get("/api/products", async (req, res) => {
    if (requireDb(res)) return;

    try {
        // Band (Closed) shops ki deals public list me nahi dikhti
        const closedIds = await Business.find({ shopStatus: "Closed" }).distinct("_id");
        const products = await Product.find(closedIds.length ? { businessId: { $nin: closedIds } } : {})
            .sort({ createdAt: -1 }).limit(300);

        res.json({
            message: "Products fetched successfully!",
            products: products
        });
    } catch (error) {
        res.status(500).json({
            message: "Products fetch failed",
            error: error.message
        });
    }
});
// POPULAR DEALS: Most viewed and claimed products
app.get("/api/products/popular", async (req, res) => {
    if (requireDb(res)) return;

    ```
try {
    const closedIds = await Business.find({
        shopStatus: "Closed"
    }).distinct("_id");

    const filter = closedIds.length
        ? { businessId: { $nin: closedIds } }
        : {};

    const products = await Product.find(filter)
        .sort({ claims: -1, views: -1, createdAt: -1 })
        .limit(300);

    res.json({
        message: "Popular deals fetched successfully!",
        products
    });

} catch (error) {
    res.status(500).json({
        message: "Popular deals fetch failed",
        error: error.message
    });
}
```

});


// PUBLIC: deal ka view count (analytics)
app.post("/api/products/:id/view", handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Deal nahi mili.");
    await Product.updateOne({ _id: req.params.id }, { $inc: { views: 1 } });
    res.json({ ok: true });
}));

// CUSTOMER LOGIN WALA: deal claim (ek customer, ek deal, ek baar)
app.post("/api/products/:id/claim", requireCustomer, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Deal nahi mili.");
    if (!req.customer.profileComplete) throw new HttpError(400, "Claim karne se pehle apni profile poori karo.");
    const product = await Product.findById(req.params.id).select("name shopName price businessId");
    if (!product) throw new HttpError(404, "Deal nahi mili.");
    let claim;
    try {
        claim = await Claim.create({
            customerId: req.customer._id,
            productId: product._id,
            businessId: product.businessId || null,
            dealName: product.name,
            shopName: product.shopName,
            price: product.price,
            customerName: req.customer.name,
            customerMobile: req.customer.mobile
        });
    } catch (err) {
        if (err && err.code === 11000) throw new HttpError(409, "Aapne ye deal pehle hi claim kar li hai.");
        throw err;
    }
    await Product.updateOne({ _id: product._id }, { $inc: { claims: 1 } });
    res.status(201).json({ message: "Deal claim ho gayi!", claim: publicClaim(claim) });
}));

// PUBLIC: open shops aur unki deals (private fields nahi)
app.get("/api/shops", handle(async (req, res) => {
    const shops = await Business.find({ shopStatus: "Open" })
        .select("businessName category area city verificationStatus").sort({ createdAt: -1 });
    res.json({ shops });
}));
app.get("/api/shops/:id/deals", handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Shop nahi mili.");
    res.json({ products: await Product.find({ businessId: req.params.id }).sort({ _id: -1 }) });
}));

/* ---------- BUSINESS: apne customers (DB me, localStorage nahi) ---------- */
const BizCustomer = mongoose.models.BizCustomer || mongoose.model("BizCustomer", new mongoose.Schema({
    businessId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    name: { type: String, required: true, trim: true, maxlength: 60 },
    phone: { type: String, required: true },
    note: { type: String, default: "", maxlength: 200 }
}, { timestamps: true }));

bizRouter.get("/customers", requireBusiness, handle(async (req, res) => {
    res.json({ customers: await BizCustomer.find({ businessId: req.business._id }).sort({ _id: -1 }) });
}));
bizRouter.post("/customers", requireBusiness, handle(async (req, res) => {
    const name = bizStr(req.body.name, 60), phone = bizStr(req.body.phone, 10), note = bizStr(req.body.note, 200);
    if (name.length < 2) throw new HttpError(400, "Customer ka naam likho.");
    if (!isBizMobile(phone)) throw new HttpError(400, "10-digit mobile number daalo.");
    if (await BizCustomer.exists({ businessId: req.business._id, phone })) throw new HttpError(409, "Ye customer pehle se saved hai.");
    const customer = await BizCustomer.create({ businessId: req.business._id, name, phone, note });
    res.status(201).json({ customer });
}));
bizRouter.delete("/customers/:id", requireBusiness, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Customer nahi mila.");
    const r = await BizCustomer.deleteOne({ _id: req.params.id, businessId: req.business._id });
    if (!r.deletedCount) throw new HttpError(404, "Customer nahi mila.");
    res.json({ message: "Customer deleted." });
}));
bizRouter.delete("/customers", requireBusiness, handle(async (req, res) => {
    await BizCustomer.deleteMany({ businessId: req.business._id });
    res.json({ message: "Customer list clear ho gayi." });
}));

/* ---------- BUSINESS: settings ---------- */
bizRouter.get("/settings", requireBusiness, handle(async (req, res) => {
    res.json({ settings: req.business.settings || {} });
}));
bizRouter.put("/settings", requireBusiness, handle(async (req, res) => {
    const whatsapp = bizStr(req.body.whatsapp, 10);
    if (whatsapp && !isBizMobile(whatsapp)) throw new HttpError(400, "WhatsApp number 10 digit ka hona chahiye.");
    req.business.settings = {
        whatsapp, hours: bizStr(req.body.hours, 80), offer: bizStr(req.body.offer, 80),
        notifyClaims: req.body.notifyClaims !== false, weekly: !!req.body.weekly, showPhone: req.body.showPhone !== false
    };
    req.business.markModified("settings");
    await req.business.save();
    res.json({ message: "Settings saved.", settings: req.business.settings });
}));

/* ---------- BUSINESS: apni deals ke claims ---------- */
bizRouter.get("/claims", requireBusiness, handle(async (req, res) => {
    const claims = await Claim.find({ businessId: req.business._id }).sort({ _id: -1 }).limit(200);
    res.json({
        claims: claims.map((c) => ({ ...publicClaim(c), customerName: c.customerName, customerMobile: c.customerMobile }))
    });
}));
bizRouter.post("/claims/:id/redeem", requireBusiness, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Claim nahi mili.");
    const c = await Claim.findOne({ _id: req.params.id, businessId: req.business._id });
    if (!c) throw new HttpError(404, "Claim nahi mili.");
    c.status = c.status === "Redeemed" ? "Pending" : "Redeemed";
    await c.save();
    res.json({ claim: publicClaim(c) });
}));

/* ---------- ADMIN PANEL (ADMIN_KEY .env me) ---------- */
const adminRouter = express.Router();
const sha = (v) => cryptoLib.createHash("sha256").update(String(v || "")).digest();
async function requireAdmin(req, res, next) {
    try {
        const p = jwtLib.verify(bearer(req) || "", process.env.JWT_SECRET);
        if (p.role !== "admin") throw new Error("no");
        next();
    } catch (e) { res.status(401).json({ message: "Admin login required." }); }
}
adminRouter.post("/login", handle(async (req, res) => {
    const key = process.env.ADMIN_KEY;
    if (!key || !cryptoLib.timingSafeEqual(sha(req.body.key), sha(key))) throw new HttpError(401, "Galat admin key.");
    res.json({ token: jwtLib.sign({ role: "admin" }, process.env.JWT_SECRET, { expiresIn: "8h" }) });
}));
adminRouter.get("/stats", requireAdmin, handle(async (req, res) => {
    const [businesses, customers, deals, claims] = await Promise.all([
        Business.countDocuments(), Customer.countDocuments(), Product.countDocuments(), Claim.countDocuments()
    ]);
    res.json({ businesses, customers, deals, claims });
}));
adminRouter.get("/businesses", requireAdmin, handle(async (req, res) => {
    res.json({ businesses: await Business.find().sort({ createdAt: -1 }).limit(500) });
}));
adminRouter.post("/businesses/:id/verify", requireAdmin, handle(async (req, res) => {
    const b = mongoose.isValidObjectId(req.params.id) && await Business.findById(req.params.id);
    if (!b) throw new HttpError(404, "Business nahi mila.");
    b.verificationStatus = b.verificationStatus === "Verified" ? "Unverified" : "Verified";
    await b.save();
    res.json({ business: b });
}));
adminRouter.get("/customers", requireAdmin, handle(async (req, res) => {
    res.json({ customers: await Customer.find().select("grroxId mobile name area createdAt").sort({ createdAt: -1 }).limit(500) });
}));
adminRouter.delete("/businesses/:id", requireAdmin, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Business nahi mila.");
    const r = await Business.deleteOne({ _id: req.params.id });
    if (!r.deletedCount) throw new HttpError(404, "Business nahi mila.");
    await Promise.all([
        Product.deleteMany({ businessId: req.params.id }),
        BizCustomer.deleteMany({ businessId: req.params.id }),
        Claim.deleteMany({ businessId: req.params.id })
    ]);
    res.json({ message: "Business aur uski deals delete ho gayi." });
}));
adminRouter.get("/deals", requireAdmin, handle(async (req, res) => {
    res.json({ products: await Product.find().select("-image").sort({ _id: -1 }).limit(500) });
}));
adminRouter.delete("/deals/:id", requireAdmin, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Deal nahi mili.");
    await Product.deleteOne({ _id: req.params.id });
    res.json({ message: "Deal deleted." });
}));
app.use("/api/admin", adminRouter);

// Unknown API route / bad JSON / bahut badi request -> hamesha JSON jawab
app.use("/api", (req, res) => res.status(404).json({ message: "Route nahi mila." }));
app.use((err, req, res, next) => {
    if (err && err.type === "entity.too.large") return res.status(413).json({ message: "Data/image bahut bada hai." });
    if (err && err.type === "entity.parse.failed") return res.status(400).json({ message: "Request galat format me hai." });
    console.error("Unhandled error:", err);
    res.status(500).json({ message: "Server error." });
});

let memoryMongoServer;

async function ensureMongoConnection() {
    if (process.env.MONGODB_URI) {
        try {
            await mongoose.connect(process.env.MONGODB_URI, {
                serverSelectionTimeoutMS: 5000
            });
            console.log("MongoDB connected successfully!");
            return;
        } catch (error) {
            console.warn("Primary MongoDB connection failed:", error.message);
        }
    } else {
        console.warn("MONGODB_URI is not defined in the environment.");
    }

    if (process.env.USE_MEMORY_MONGO === "false") {
        console.warn("Continuing without MongoDB; database-dependent routes will return 503 until the DB is reachable.");
        return;
    }

    try {
        memoryMongoServer = await MongoMemoryServer.create({
            binary: { version: "7.0.14" },
            instance: { dbName: "grrox" }
        });
        await mongoose.connect(memoryMongoServer.getUri(), {
            dbName: "grrox"
        });
        console.log("MongoDB connected successfully via in-memory server.");
    } catch (error) {
        console.error("MongoDB connection failed:", error.message);
        console.warn("Continuing without MongoDB; database-dependent routes will return 503 until the DB is reachable.");
    }
}

async function startServer() {
    await ensureMongoConnection();

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, "0.0.0.0", () => {
        console.log(`GRROX Backend running on port ${PORT}`);
    });
}

process.on("SIGINT", async () => {
    if (memoryMongoServer) {
        await memoryMongoServer.stop();
    }
    process.exit(0);
});

if (require.main === module) {
    startServer();
}

module.exports = { app, startServer };