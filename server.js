import express from "express";
import cors from "cors";
import { exec } from "child_process";
import fs from "fs";
import axios from "axios";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Load environment variables
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://admin:admin123@localhost:27017/loginAppDB?authSource=admin";
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";

mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB (loginAppDB)"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// User Schema - matches your existing database structure
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'users' }); // Explicitly use 'users' collection

const User = mongoose.model("User", userSchema);

// Root route to check server
app.get("/", (req, res) => {
    res.send("AI SDLC Security Compliance Auditor backend is running!");
});

// 🔐 Authentication Routes

// Signup Route
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({
      message: "User created successfully",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Server error during signup" });
  }
});

// Login Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login" });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// POST /analyze
app.post("/analyze", async (req, res) => {
    const { code, language } = req.body;

    // Save code to temp file based on language
    const fileExtensions = {
        python: "py",
        javascript: "js",
        cpp: "cpp",
        java: "java"
    };
    const filename = `input.${fileExtensions[language] || "txt"}`;
    fs.writeFileSync(filename, code);

    // Results
    let semgrepResult = null;
    let banditResult = null;
    let eslintResult = null;
    let cppcheckResult = null;
    let spotbugsResult = null;

    // 1️⃣ Run Semgrep
    exec(`semgrep --config=auto ${filename} --json`, (err, semOut) => {
        semgrepResult = semOut ? JSON.parse(semOut) : {};

        // Language-specific tools
        if (language === "python") {
            // Python → Bandit
            exec(`bandit -f json ${filename}`, async (bErr, bOut) => {
                banditResult = bOut ? JSON.parse(bOut) : {};
                finalize();
            });
        } else if (language === "javascript") {
            // JavaScript → ESLint
            exec(`npx eslint ${filename} -f json`, async (eErr, eOut) => {
                eslintResult = eOut ? JSON.parse(eOut) : {};
                finalize();
            });
        } else if (language === "cpp") {
            // C++ → Cppcheck (if installed)
            exec(`cppcheck --enable=all --json ${filename} 2>&1`, async (cErr, cOut) => {
                try {
                    cppcheckResult = cOut ? { output: cOut } : { note: "Cppcheck not installed or no issues found" };
                } catch (e) {
                    cppcheckResult = { note: "Cppcheck analysis completed" };
                }
                finalize();
            });
        } else if (language === "java") {
            // Java → Just use Semgrep for now (SpotBugs requires compiled .class files)
            spotbugsResult = { note: "Java analysis via Semgrep. For deeper analysis, use SpotBugs on compiled code." };
            finalize();
        } else {
            finalize();
        }
    });

    // 2️⃣ Final response with AI suggestion
    async function finalize() {
        const ai_feedback = await callCopilotAI(code, language);

        res.json({
            ok: true,
            semgrep: semgrepResult,
            bandit: banditResult,
            eslint: eslintResult,
            cppcheck: cppcheckResult,
            spotbugs: spotbugsResult,
            ai_feedback
        });
    }
});

// 🎯 POST /threat-model - STRIDE Threat Modeling
app.post("/threat-model", async (req, res) => {
    const { code, language } = req.body;
    
    try {
        const threatModel = await generateThreatModel(code, language);
        res.json({
            ok: true,
            threat_model: threatModel
        });
    } catch (err) {
        res.json({
            ok: false,
            error: err.message
        });
    }
});

// ⭐ Groq API for AI-powered security feedback (FREE)
async function callCopilotAI(code, language) {
    try {
        const API_KEY = process.env.GROQ_API_KEY;

        if (!API_KEY || API_KEY === 'your_groq_api_key_here') {
            return "⚠️ Groq API key not configured. Add GROQ_API_KEY to .env file.";
        }

        console.log("🔍 Calling Groq API...");
        
        const response = await axios.post(
            "https://api.groq.com/openai/v1/chat/completions",
            {
                model: "llama-3.3-70b-versatile",
                messages: [
                    { 
                        role: "system", 
                        content: "You are a highly skilled security auditor. Analyze the provided code for security vulnerabilities, explain the risks clearly, and suggest specific fixes. Be concise but thorough." 
                    },
                    { 
                        role: "user", 
                        content: `Analyze this ${language} code for security vulnerabilities:\n\n${code}` 
                    }
                ],
                temperature: 0.3,
                max_tokens: 800
            },
            { 
                headers: { 
                    "Authorization": `Bearer ${API_KEY}`,
                    "Content-Type": "application/json"
                },
                timeout: 30000
            }
        );

        console.log("✅ Groq API response received");
        return response.data.choices[0].message.content;

    } catch (err) {
        console.error("❌ Groq API Error:", err.response?.status, err.response?.data || err.message);
        
        // Provide detailed error message
        const errorMsg = err.response?.data?.error?.message || err.message;
        return `⚠️ AI Analysis: Unable to fetch AI feedback at this moment. (${errorMsg})\n\nBut don't worry! Your Semgrep and Bandit/ESLint results above are comprehensive and professional-grade security analysis tools used by industry leaders.`;
    }
}

// 🎯 STRIDE Threat Modeling with AI
async function generateThreatModel(code, language) {
    try {
        const API_KEY = process.env.GROQ_API_KEY;

        if (!API_KEY || API_KEY === 'your_groq_api_key_here') {
            return "⚠️ Groq API key not configured. Add GROQ_API_KEY to .env file.";
        }

        console.log("🎯 Generating STRIDE Threat Model...");
        
        const response = await axios.post(
            "https://api.groq.com/openai/v1/chat/completions",
            {
                model: "llama-3.3-70b-versatile",
                messages: [
                    { 
                        role: "system", 
                        content: `You are an expert security architect specializing in STRIDE threat modeling. Analyze code and identify threats in these categories:

**STRIDE Framework:**
- **S**poofing: Authentication threats, identity impersonation
- **T**ampering: Data integrity violations, unauthorized modifications
- **R**epudiation: Missing audit trails, non-repudiable actions
- **I**nformation Disclosure: Data leaks, privacy violations
- **D**enial of Service: Resource exhaustion, availability threats
- **E**levation of Privilege: Authorization bypass, privilege escalation

For each threat found:
1. Category (STRIDE letter)
2. Threat description
3. Attack scenario (how it could be exploited)
4. Risk level (Critical/High/Medium/Low)
5. Mitigation strategy

Be specific and actionable. Focus on real threats based on the code patterns.` 
                    },
                    { 
                        role: "user", 
                        content: `Perform STRIDE threat modeling on this ${language} code:\n\n${code}\n\nProvide a structured threat analysis with attack scenarios and mitigation recommendations.` 
                    }
                ],
                temperature: 0.4,
                max_tokens: 1500
            },
            { 
                headers: { 
                    "Authorization": `Bearer ${API_KEY}`,
                    "Content-Type": "application/json"
                },
                timeout: 40000
            }
        );

        console.log("✅ STRIDE Threat Model generated");
        return response.data.choices[0].message.content;

    } catch (err) {
        console.error("❌ Threat Model Error:", err.response?.status, err.response?.data || err.message);
        const errorMsg = err.response?.data?.error?.message || err.message;
        return `⚠️ Unable to generate threat model at this moment. (${errorMsg})`;
    }
}

app.listen(5000, () => {
    console.log("🔥 Backend running on http://localhost:5000");
});
