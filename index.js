require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require("mongodb");

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB URI
const uri = process.env.MONGO_URI;

// Create Mongo Client
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true
  }
});

let contestCollection;

// Connect to database
async function connectDB() {
  try {
    await client.connect();
    const database = client.db("contestHub");       
    contestCollection = database.collection("contests"); 
    console.log(" MongoDB connected (Native Driver)");
  } catch (error) {
    console.error(" Database connection error:", error);
  }
}
connectDB();

// ---------- Routes ---------- //
app.get("/", (req, res) => {
  res.send("ContestHub API is running with Native MongoDB Driver");
});

// Get all contests
app.get("/contests", async (req, res) => {
  try {
    const contests = await contestCollection.find().toArray();
    res.json(contests);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get contest by id
app.get("/contests/:id", async (req, res) => {
  try {
    const contest = await contestCollection.findOne({ id: req.params.id });
    if (!contest) {
      return res.status(404).json({ error: "Contest not found" });
    }
    res.json(contest);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add new contest
app.post("/contests", async (req, res) => {
  try {
    const result = await contestCollection.insertOne(req.body);
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ---------- Server Listen ---------- //
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
