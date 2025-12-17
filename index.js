require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: ["http://localhost:5173"], credentials: true }));
app.use(express.json());

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET missing in .env");
  process.exit(1);
}

/* ================= DATABASE ================= */
const client = new MongoClient(process.env.MONGO_URI);
let usersCollection;
let contestsCollection;

async function connectDB() {
  await client.connect();
  const db = client.db(process.env.DB_NAME || "contestHub");
  usersCollection = db.collection("users");
  contestsCollection = db.collection("contests");
  console.log("MongoDB Connected");
}
connectDB();

/* ================= JWT ================= */
const createToken = (user) =>
  jwt.sign({ email: user.email, role: user.role }, process.env.JWT_SECRET, {
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
app.post("/auth/register", async (req, res) => {
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
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await usersCollection.findOne({
      email: email.toLowerCase(),
    });

    if (!user) return res.status(404).send({ message: "User not found" });
    if (!bcrypt.compareSync(password, user.password))
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
app.post("/auth/google-login", async (req, res) => {
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
    res.status(500).send({ message: err.message });
  }
});

// GET current user
app.get("/auth/me", verifyJWT, async (req, res) => {
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

// UPDATE current user
app.put("/auth/me", verifyJWT, async (req, res) => {
  try {
    const { name, photoURL, bio } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (photoURL) updateFields.photoURL = photoURL;
    if (bio) updateFields.bio = bio;

    const emailLower = req.user.email.toLowerCase();
    const result = await usersCollection.findOneAndUpdate(
      { email: emailLower },
      { $set: updateFields },
      { returnDocument: "after" }
    );

    if (!result.value)
      return res.status(404).send({ message: "User not found" });

    res.send({
      email: result.value.email,
      name: result.value.name,
      photoURL: result.value.photoURL || null,
      bio: result.value.bio || "",
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

/* ================= CONTEST ROUTES ================= */

// GET all contests OR creator-wise
app.get("/contests", async (req, res) => {
  try {
    const { creatorEmail } = req.query;
    const filter = creatorEmail ? { creatorEmail } : {};
    const contests = await contestsCollection.find(filter).toArray();
    res.send(contests);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// GET contest by ID
app.get("/contests/:id", verifyJWT, async (req, res) => {
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

// CREATE contest (creator only)
app.post("/contests", verifyJWT, verifyCreator, async (req, res) => {
  try {
    const contest = {
      ...req.body,
      creatorEmail: req.user.email,
      status: "pending",
      participants: [],
      submissions: [],
      createdAt: new Date(),
      endDate: req.body.endDate || new Date(new Date().getTime() + 3*24*60*60*1000),
    };

    const result = await contestsCollection.insertOne(contest);
    res.status(201).send({ insertedId: result.insertedId });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// EDIT contest (creator & pending only)
app.put("/contests/edit/:id", verifyJWT, verifyCreator, async (req, res) => {
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
app.delete("/contests/:id", verifyJWT, async (req, res) => {
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
app.put("/contests/status/:id", verifyJWT, verifyAdmin, async (req, res) => {
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

    res.send(result.value);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// REGISTER FOR CONTEST
app.post("/contests/:id/register", verifyJWT, async (req, res) => {
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
app.post("/contests/:id/submit-task", verifyJWT, async (req, res) => {
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
app.put("/contests/:id/declare-winner", verifyJWT, verifyCreator, async (req, res) => {
  try {
    const { id } = req.params;
    const { userEmail } = req.body;

    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    // Only allow one winner per contest
    if (contest.submissions.some(s => s.status === "winner")) {
      return res.status(400).send({ message: "Winner already declared" });
    }

    const updatedSubmissions = contest.submissions.map((s) =>
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
app.put("/contests/:id", verifyJWT, verifyCreator, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    // Only allow creator of this contest to update
    if (contest.creatorEmail !== req.user.email) {
      return res.status(403).send({ message: "Not authorized" });
    }

    const allowedFields = [
      "title",
      "description",
      "image",
      "price",
      "prizeMoney",
      "taskInstruction",
      "category ",
      "endDate",
      "isActive"
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

    res.send({ message: "Contest updated successfully", contest: result.value });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// GET submissions for a contest (creator only)
app.get("/contests/:id/submissions", verifyJWT, verifyCreator, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id))
      return res.status(400).send({ message: "Invalid contest ID" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    // Only the contest creator can view submissions
    if (contest.creatorEmail !== req.user.email)
      return res.status(403).send({ message: "Not authorized" });

    // Send submissions with participant info
    res.send(
      (contest.submissions || []).map((s) => ({
        participantName: s.participantName || "Anonymous",
        participantEmail: s.userEmail,
        taskInfo: s.submission,
        submittedAt: s.submittedAt,
      }))
    );
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Internal server error" });
  }
});




/* ================= SERVER ================= */
app.get("/", (req, res) => res.send("🚀 ContestHub API Running"));
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
