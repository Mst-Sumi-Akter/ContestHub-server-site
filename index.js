require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");

// --- Safer Firebase Initialization ---
try {
  if (process.env.FIREBASE_SERVICE_KEY_BASE64) {
    const serviceAccount = JSON.parse(
      Buffer.from(process.env.FIREBASE_SERVICE_KEY_BASE64, "base64").toString("utf8")
    );
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log(" Firebase Admin initialized");
  } else if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH) {
    const serviceAccount = require(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log("Firebase Admin initialized via path");
  } else {
    console.warn(" FIREBASE_SERVICE_KEY_BASE64 missing. Google Auth might fail.");
  }
} catch (error) {
  console.error(" Firebase Admin failed to initialize:", error.message);
}

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
if (!STRIPE_SECRET_KEY) {
  console.warn("STRIPE_SECRET_KEY missing. Payment features disabled.");
}
const stripe = STRIPE_SECRET_KEY ? require("stripe")(STRIPE_SECRET_KEY) : null;

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: ["http://localhost:5173", "http://localhost:5174", "https://contest-hub-b7db7.web.app", "https://contest-hub-b7db7.firebaseapp.com", "https://contest-hub-server-gamma-drab.vercel.app", "https://fantastic-cucurucho-3fa98b.netlify.app"], credentials: true }));
app.use(express.json());

if (!process.env.JWT_SECRET) {
  console.error(" JWT_SECRET missing in .env");
  process.exit(1);
}

/* ================= DATABASE ================= */
const client = new MongoClient(process.env.MONGO_URI);
let usersCollection;
let contestsCollection;

// Ensure DB connection before handling requests
async function ensureDB(req, res, next) {
  if (!usersCollection || !contestsCollection) {
    try {
      await connectDB();
      next();
    } catch (err) {
      res.status(500).send({ message: "Database connection failed" });
    }
  } else {
    next();
  }
}

async function connectDB() {
  if (usersCollection && contestsCollection) return;
  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME || "contestHub");
    usersCollection = db.collection("users");
    contestsCollection = db.collection("contests");
    console.log("MongoDB Connected");
  } catch (error) {
    console.error(" MongoDB Connection Error:", error.message);
    throw error;
  }
}

// Pre-connect for local environment
if (process.env.NODE_ENV !== "production") {
  connectDB().catch(console.error);
}

/* ================= JWT ================= */
const createToken = (user) =>
  jwt.sign({ email: user.email.toLowerCase(), role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
};

/* ================= ROLE CHECK ================= */
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== "admin")
    return res.status(403).send({ message: "Admin only" });
  next();
};

const verifyCreator = (req, res, next) => {
  if (req.user.role !== "creator")
    return res.status(403).send({ message: "Creator only" });
  next();
};

/* ================= AUTH ROUTES ================= */

// REGISTER
app.post("/auth/register", ensureDB, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!email || !password)
      return res.status(400).send({ message: "Email & password required" });

    const existing = await usersCollection.findOne({
      email: email.toLowerCase(),
    });
    if (existing)
      return res.status(400).send({ message: "User already exists" });

    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = {
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: role || "user",
      contestLimit: 2, // Default limit for free starters
      createdAt: new Date(),
    };

    await usersCollection.insertOne(user);
    const token = createToken(user);

    res.send({ token, role: user.role, email: user.email, name: user.name });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// LOGIN
app.post("/auth/login", ensureDB, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send({ message: "Email and password required" });

    const user = await usersCollection.findOne({
      email: email.toLowerCase(),
    });

    if (!user) return res.status(404).send({ message: "User not found" });
    if (!user.password || !bcrypt.compareSync(password, user.password))
      return res.status(400).send({ message: "Invalid credentials" });

    const token = createToken(user);
    res.send({
      token,
      role: user.role,
      email: user.email,
      name: user.name,
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// GOOGLE LOGIN
app.post("/auth/google-login", ensureDB, async (req, res) => {
  try {
    const { email, name, photoURL } = req.body;
    if (!email || !name)
      return res.status(400).send({ message: "Email and name required" });

    let user = await usersCollection.findOne({ email: email.toLowerCase() });
    if (!user) {
      user = {
        name,
        email: email.toLowerCase(),
        role: "user",
        photoURL,
        password: null,
        createdAt: new Date(),
      };
      await usersCollection.insertOne(user);
    } else if (photoURL && !user.photoURL) {
      // Update photo if missing
      await usersCollection.updateOne({ _id: user._id }, { $set: { photoURL } });
      user.photoURL = photoURL;
    }

    const token = createToken(user);
    res.send({
      token,
      role: user.role,
      email: user.email,
      name: user.name,
      photoURL: user.photoURL,
      bio: user.bio || "",
    });
  } catch (err) {
    console.error("Google login error:", err);
    res.status(500).send({ message: err.message });
  }
});

// GET current user
app.get("/auth/me", ensureDB, verifyJWT, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user) return res.status(404).send({ message: "User not found" });

    res.send({
      email: user.email,
      name: user.name,
      role: user.role,
      photoURL: user.photoURL || null,
      bio: user.bio || "",
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// GET all users (Admin only)
app.get("/users", ensureDB, verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection.find({}).toArray();
    res.send(users);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// UPDATE user role (Admin only)
app.put("/users/:id/role", ensureDB, verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!ObjectId.isValid(id))
      return res.status(400).send({ message: "Invalid user ID" });

    await usersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { role } }
    );
    res.send({ message: "Role updated successfully" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// UPDATE current user
app.put("/auth/me", ensureDB, verifyJWT, async (req, res) => {
  try {
    if (!req.user?.email)
      return res.status(401).send({ message: "Unauthorized" });

    const { name, photoURL, bio } = req.body;
    const userEmail = req.user.email.toLowerCase();

    const updateFields = {};
    if (name !== undefined) updateFields.name = name;
    if (photoURL !== undefined) updateFields.photoURL = photoURL;
    if (bio !== undefined) updateFields.bio = bio;

    const result = await usersCollection.findOneAndUpdate(
      { email: userEmail },
      { $set: updateFields },
      { returnDocument: "after" }
    );

    if (!result) return res.status(404).send({ message: "User not found" });

    res.send({
      email: result.email,
      name: result.name,
      role: result.role,
      photoURL: result.photoURL || null,
      bio: result.bio || "",
    });
  } catch (err) {
    console.error("Profile update failed:", err);
    res.status(500).send({ message: err.message });
  }
});


/* ================= CONTEST ROUTES ================= */

// GET all contests OR creator-wise OR search
app.get("/contests", ensureDB, async (req, res) => {
  try {
    const { creatorEmail, category, search } = req.query;
    let query = {};

    if (creatorEmail) {
      query.creatorEmail = creatorEmail;
    }

    if (category && category !== "All") {
      query.category = category;
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const contests = await contestsCollection.find(query).toArray();
    res.send(contests);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// GET contest by ID
app.get("/contests/:id", ensureDB, verifyJWT, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id))
      return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    res.send(contest);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

app.post("/contests", ensureDB, verifyJWT, verifyCreator, async (req, res) => {
  try {
    // Check limit
    const user = await usersCollection.findOne({ email: req.user.email });
    const count = await contestsCollection.countDocuments({ creatorEmail: req.user.email });
    const limit = user.contestLimit || 2;

    if (count >= limit) {
      return res.status(403).send({ message: `Contest limit reached (${limit}). Please upgrade your package.` });
    }

    const contest = {
      ...req.body,
      creatorEmail: req.user.email,
      status: "pending",
      participants: [],
      submissions: [],
      createdAt: new Date(),
      endDate: req.body.endDate || new Date(new Date().getTime() + 3 * 24 * 60 * 60 * 1000),
    };

    const result = await contestsCollection.insertOne(contest);
    res.status(201).send({ insertedId: result.insertedId });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// EDIT contest (creator & pending only)
app.put("/contests/edit/:id", ensureDB, verifyJWT, verifyCreator, async (req, res) => {
  try {
    const { id } = req.params;

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    if (contest.creatorEmail !== req.user.email || contest.status !== "pending")
      return res.status(403).send({ message: "Not allowed" });

    await contestsCollection.updateOne({ _id: contest._id }, { $set: req.body });
    res.send({ message: "Contest updated successfully" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// DELETE contest - Creator (pending) or Admin
app.delete("/contests/:id", ensureDB, verifyJWT, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id))
      return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    // Role-based delete check
    if (req.user.role === "creator") {
      // Creator can only delete own pending contest
      if (contest.creatorEmail !== req.user.email || contest.status !== "pending") {
        return res.status(403).send({ message: "Not allowed" });
      }
    } else if (req.user.role === "admin") {
      // Admin can delete any contest → nothing to check
    } else {
      return res.status(403).send({ message: "Not allowed" });
    }

    await contestsCollection.deleteOne({ _id: contest._id });
    res.send({ message: "Contest deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal Server Error" });
  }
});


// ADMIN confirm / reject contest
app.put("/contests/status/:id", ensureDB, verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!["confirmed", "rejected"].includes(status))
      return res.status(400).send({ message: "Invalid status" });

    const result = await contestsCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: { status } },
      { returnDocument: "after" }
    );

    res.send(result);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// REGISTER FOR CONTEST
app.post("/contests/:id/register", ensureDB, verifyJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const userEmail = req.user.email;

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    const participants = Array.isArray(contest.participants) ? contest.participants : [];
    if (participants.includes(userEmail))
      return res.status(400).send({ message: "Already registered" });

    await contestsCollection.updateOne(
      { _id: contest._id },
      { $set: { participants: [...participants, userEmail] } }
    );

    res.send({ message: "Registered successfully" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// SUBMIT TASK
app.post("/contests/:id/submit-task", ensureDB, verifyJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const { submission } = req.body;
    const userEmail = req.user.email;

    if (!submission) return res.status(400).send({ message: "Submission cannot be empty" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    if (!contest.participants?.includes(userEmail))
      return res.status(400).send({ message: "You are not registered for this contest" });

    const submissionObj = { userEmail, submission, submittedAt: new Date() };
    await contestsCollection.updateOne(
      { _id: contest._id },
      { $push: { submissions: submissionObj } }
    );

    res.send({ message: "Submission successful" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// Declare winner for a contest (creator only)
app.put("/contests/:id/declare-winner", ensureDB, verifyJWT, verifyCreator, async (req, res) => {
  try {
    const { id } = req.params;
    const { userEmail } = req.body;

    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    if (contest.submissions?.some(s => s.status === "winner")) {
      return res.status(400).send({ message: "Winner already declared" });
    }

    const updatedSubmissions = (contest.submissions || []).map((s) =>
      s.userEmail === userEmail ? { ...s, status: "winner" } : s
    );

    await contestsCollection.updateOne(
      { _id: contest._id },
      { $set: { submissions: updatedSubmissions } }
    );

    res.send({ message: "Winner declared successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// UPDATE contest - Creator can update own contest
app.put("/contests/:id", ensureDB, verifyJWT, verifyCreator, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    if (contest.creatorEmail !== req.user.email) {
      return res.status(403).send({ message: "Not authorized" });
    }

    const allowedFields = [
      "title", "description", "image", "price", "prizeMoney",
      "taskInstruction", "category", "endDate", "isActive"
    ];

    const updateFields = {};
    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) updateFields[field] = req.body[field];
    });

    const result = await contestsCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: updateFields },
      { returnDocument: "after" }
    );

    res.send({ message: "Contest updated successfully", contest: result });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// GET submissions for a contest (creator only)
app.get("/contests/:id/submissions", ensureDB, verifyJWT, verifyCreator, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id))
      return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    if (contest.creatorEmail !== req.user.email)
      return res.status(403).send({ message: "Not authorized" });

    res.send(
      (contest.submissions || []).map((s) => ({
        participantName: s.participantName || "Anonymous",
        participantEmail: s.userEmail,
        taskInfo: s.submission,
        submittedAt: s.submittedAt,
        status: s.status,
      }))
    );
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});

// ================= PACKAGES & LIMITS =================

const defaultPackages = [
  { id: "starter", name: "Starter", price: 0, limit: 2, description: "Post up to 2 contests for free" },
  { id: "pro", name: "Pro", price: 10, limit: 10, description: "Post up to 10 contests" },
  { id: "ultimate", name: "Ultimate", price: 25, limit: 100, description: "Unlimited-ish (up to 100) contests" },
];

app.get("/packages", async (req, res) => {
  res.send(defaultPackages);
});

// BUY PACKAGE
app.post("/users/buy-package", ensureDB, verifyJWT, async (req, res) => {
  try {
    const { packageId } = req.body;
    const pkg = defaultPackages.find((p) => p.id === packageId);
    if (!pkg) return res.status(400).send({ message: "Invalid package" });

    // Update user limit
    await usersCollection.updateOne(
      { email: req.user.email },
      { $set: { contestLimit: pkg.limit, currentPackage: pkg.id } }
    );

    res.send({ message: "Package purchased successfully", limit: pkg.limit });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// ================= LEADERBOARD =================
app.get("/leaderboard", ensureDB, async (req, res) => {
  try {
    // Optimized Leaderboard Calculation using MongoDB Aggregation
    const leaderboard = await contestsCollection.aggregate([
      { $unwind: "$submissions" },
      { $match: { "submissions.status": "winner" } },
      { $group: { _id: "$submissions.userEmail", points: { $sum: 1 } } },
      { $sort: { points: -1 } },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "email",
          as: "userDetails"
        }
      },
      { $unwind: "$userDetails" },
      {
        $project: {
          _id: 0,
          email: "$_id",
          name: "$userDetails.name",
          photoURL: "$userDetails.photoURL",
          role: "$userDetails.role",
          points: 1
        }
      }
    ]).toArray();

    res.send(leaderboard);
  } catch (err) {
    console.error("Leaderboard error:", err);
    res.status(500).send({ message: "Internal server error" });
  }
});


// ================= PAYMENT =================
app.post("/create-payment-intent", ensureDB, verifyJWT, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).send({ message: "Stripe not configured" });
    }

    let { price } = req.body;

    price = Number(price);
    if (!price || price <= 0) {
      return res.status(400).send({ message: "Invalid price" });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(price * 100),
      currency: "usd",
      automatic_payment_methods: { enabled: true },
    });

    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error("Stripe Error:", err);
    res.status(500).send({ message: "Payment failed" });
  }
});

/* ================= SERVER ================= */
app.get("/", (req, res) => res.send(" ContestHub API Running (Modernized)"));
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(` Server running on http://localhost:${PORT}`));
