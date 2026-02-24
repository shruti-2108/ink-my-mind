const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();
const mysql = require("mysql2");
require("dotenv").config();

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

// 🔹 SIGNUP API
router.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // Check if user exists
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (results.length > 0) {
        return res.status(400).json({ message: "User already exists" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user
      db.query(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, email, hashedPassword],
        (err) => {
          if (err) {
            return res.status(500).json({ message: "Signup failed" });
          }
          res.status(201).json({ message: "Signup successful" });
        }
      );
    }
  );
  
});
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Server error" });
      }

      if (result.length === 0) {
        return res.status(401).json({ message: "User not found" });
      }

      const user = result[0];

      // ✅ CORRECT PASSWORD CHECK
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).json({ message: "Invalid password" });
      }

      res.json({
        message: "Login successful",
        userId: user.id,
        username: user.username
      });
    }
  );
});

router.post("/add-thought", (req, res) => {
  const { userId, content } = req.body;

  if (!content) {
    return res.status(400).json({ message: "Thought cannot be empty" });
  }

  const sql = "INSERT INTO thoughts (user_id, content) VALUES (?, ?)";

  db.query(sql, [userId, content], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Failed to save thought" });
    }

    res.json({ message: "Thought saved successfully" });
  });
});
router.get("/thoughts/:userId", (req, res) => {
  const userId = req.params.userId;

  const sql = "SELECT * FROM thoughts WHERE user_id = ? ORDER BY created_at DESC";

  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Failed to fetch thoughts" });
    }

    res.json(results);
  });
});


module.exports = router;
