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
            // C++ → Enhanced security analysis with Cppcheck and Flawfinder
            exec(`cppcheck --enable=warning,style,performance,portability,information --template=gcc --inline-suppr ${filename} 2>&1`, async (cErr, cOut) => {
                try {
                    // Parse Cppcheck output
                    const cppcheckIssues = [];
                    if (cOut) {
                        const lines = cOut.split('\n');
                        lines.forEach(line => {
                            if (line.includes('error:') || line.includes('warning:') || line.includes('style:')) {
                                const match = line.match(/\[(.+?):(\d+)\]:\s*\((.+?)\)\s*(.+)/);
                                if (match) {
                                    cppcheckIssues.push({
                                        file: match[1],
                                        line: match[2],
                                        severity: match[3],
                                        message: match[4]
                                    });
                                }
                            }
                        });
                    }
                    cppcheckResult = { issues: cppcheckIssues, raw_output: cOut };
                } catch (e) {
                    cppcheckResult = { note: "Cppcheck analysis completed", raw_output: cOut };
                }
                
                // Also try Flawfinder for security-specific issues
                exec(`flawfinder --minlevel=0 --context --quiet ${filename}`, (fErr, fOut) => {
                    try {
                        const flawfinderIssues = [];
                        if (fOut) {
                            const lines = fOut.split('\n');
                            lines.forEach(line => {
                                if (line.match(/^\S+:\d+:/)) {
                                    flawfinderIssues.push(line);
                                }
                            });
                        }
                        cppcheckResult.flawfinder = flawfinderIssues;
                        cppcheckResult.flawfinder_output = fOut;
                    } catch (e) {
                        cppcheckResult.flawfinder = [];
                    }
                    finalize();
                });
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

// 🎯 POST /threat-model - Multi-Framework Threat Modeling
app.post("/threat-model", async (req, res) => {
    const { code, language, framework = "STRIDE" } = req.body;
    
    try {
        const threatModel = await generateThreatModel(code, language, framework);
        res.json({
            ok: true,
            threat_model: threatModel,
            framework: framework
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

// 🎯 Multi-Framework Threat Modeling with AI
async function generateThreatModel(code, language, framework = "STRIDE") {
    try {
        const API_KEY = process.env.GROQ_API_KEY;

        if (!API_KEY || API_KEY === 'your_groq_api_key_here') {
            return "⚠️ Groq API key not configured. Add GROQ_API_KEY to .env file.";
        }

        console.log(`🎯 Generating ${framework} Threat Model...`);
        
        const frameworkPrompts = {
            STRIDE: {
                system: `You are an expert security architect specializing in STRIDE threat modeling. Analyze code and identify threats in these categories:

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

Be specific and actionable. Focus on real threats based on the code patterns.`,
                user: `Perform STRIDE threat modeling on this ${language} code:\n\n${code}\n\nProvide a structured threat analysis with attack scenarios and mitigation recommendations.`
            },
            PASTA: {
                system: `You are an expert security architect specializing in PASTA (Process for Attack Simulation and Threat Analysis) methodology. This is a risk-centric approach with seven stages.

**PASTA Framework:**
1. **Define Business Objectives** - Security requirements and compliance
2. **Define Technical Scope** - Architecture, dependencies, data flows
3. **Application Decomposition** - Components, trust boundaries, entry points
4. **Threat Analysis** - Identify threat agents and attack vectors
5. **Vulnerability Analysis** - Known weaknesses and exposures
6. **Attack Modeling** - Simulate attack scenarios and paths
7. **Risk & Impact Analysis** - Likelihood, impact, and prioritization

For each stage, provide:
- Analysis specific to the code
- Risk assessment (1-10 scale)
- Attack scenarios
- Mitigation recommendations

Focus on business impact and attack simulation.`,
                user: `Perform PASTA threat modeling on this ${language} code:\n\n${code}\n\nProvide analysis across all 7 PASTA stages with risk assessment and attack simulation.`
            },
            DREAD: {
                system: `You are an expert security architect specializing in DREAD risk assessment methodology. DREAD provides quantitative threat ranking.

**DREAD Framework:**
- **D**amage Potential (0-10): How much damage could the attack cause?
- **R**eproducibility (0-10): How easy is it to reproduce the attack?
- **E**xploitability (0-10): How much effort is needed to exploit?
- **A**ffected Users (0-10): How many users would be impacted?
- **D**iscoverability (0-10): How easy is it to discover the vulnerability?

For each identified threat:
1. Threat description
2. DREAD scores for each category
3. Total DREAD Score (sum/average)
4. Risk Level (Critical: >40, High: 30-40, Medium: 20-30, Low: <20)
5. Attack scenario
6. Mitigation strategy

Provide numerical scores and justify each rating.`,
                user: `Perform DREAD risk assessment on this ${language} code:\n\n${code}\n\nProvide quantitative DREAD scoring for each identified threat with justification.`
            }
        };

        const selectedPrompt = frameworkPrompts[framework] || frameworkPrompts.STRIDE;
        
        const response = await axios.post(
            "https://api.groq.com/openai/v1/chat/completions",
            {
                model: "llama-3.3-70b-versatile",
                messages: [
                    { 
                        role: "system", 
                        content: selectedPrompt.system
                    },
                    { 
                        role: "user", 
                        content: selectedPrompt.user
                    }
                ],
                temperature: 0.4,
                max_tokens: 2000
            },
            { 
                headers: { 
                    "Authorization": `Bearer ${API_KEY}`,
                    "Content-Type": "application/json"
                },
                timeout: 40000
            }
        );

        console.log(`✅ ${framework} Threat Model generated`);
        return response.data.choices[0].message.content;

    } catch (err) {
        console.error("❌ Threat Model Error:", err.response?.status, err.response?.data || err.message);
        const errorMsg = err.response?.data?.error?.message || err.message;
        return `⚠️ Unable to generate threat model at this moment. (${errorMsg})`;
    }
}

// 🔧 POST /api/fix-code - Generate Fixed Code
app.post("/api/fix-code", async (req, res) => {
    const { code, language, vulnerabilities } = req.body;
    
    try {
        const API_KEY = process.env.GROQ_API_KEY;

        if (!API_KEY || API_KEY === 'your_groq_api_key_here') {
            return res.json({
                ok: false,
                error: "Groq API key not configured"
            });
        }

        console.log("🔧 Generating fixed code...");
        
        // Build vulnerability summary
        const vulnSummary = vulnerabilities.map((v, idx) => 
            `${idx + 1}. [${v.tool}] Line ${v.line}: ${v.message}`
        ).join("\n");

        const response = await axios.post(
            "https://api.groq.com/openai/v1/chat/completions",
            {
                model: "llama-3.3-70b-versatile",
                messages: [
                    { 
                        role: "system", 
                        content: `You are an expert security engineer. Your task is to fix security vulnerabilities in code while maintaining functionality. 

Guidelines:
1. Fix ALL identified security issues
2. Add security best practices (input validation, error handling, etc.)
3. Add comments explaining the security improvements
4. Maintain the original functionality
5. Use modern, secure coding patterns
6. Return ONLY the fixed code, no explanations outside the code comments` 
                    },
                    { 
                        role: "user", 
                        content: `Fix the security vulnerabilities in this ${language} code:

**Original Code:**
\`\`\`${language}
${code}
\`\`\`

**Vulnerabilities Found:**
${vulnSummary}

Please provide the complete, secure version of this code with all vulnerabilities fixed. Include inline comments explaining the security fixes.` 
                    }
                ],
                temperature: 0.3,
                max_tokens: 2000
            },
            { 
                headers: { 
                    "Authorization": `Bearer ${API_KEY}`,
                    "Content-Type": "application/json"
                },
                timeout: 45000
            }
        );

        console.log("✅ Fixed code generated");
        
        let fixedCode = response.data.choices[0].message.content;
        
        // Remove markdown code blocks if present
        fixedCode = fixedCode.replace(/```[\w]*\n/g, '').replace(/```$/g, '').trim();
        
        res.json({
            ok: true,
            fixed_code: fixedCode
        });

    } catch (err) {
        console.error("❌ Fix Code Error:", err.response?.status, err.response?.data || err.message);
        const errorMsg = err.response?.data?.error?.message || err.message;
        res.json({
            ok: false,
            error: `Unable to generate fixed code. ${errorMsg}`
        });
    }
});

// 📄 POST /api/generate-report - Generate AI Report for PDF
app.post("/api/generate-report", async (req, res) => {
    const { originalCode, fixedCode, language, vulnerabilities } = req.body;
    
    try {
        const API_KEY = process.env.GROQ_API_KEY;

        if (!API_KEY || API_KEY === 'your_groq_api_key_here') {
            return res.json({
                ok: false,
                error: "Groq API key not configured"
            });
        }

        console.log("📄 Generating security report...");
        
        // Build vulnerability summary
        const vulnSummary = vulnerabilities?.map((v, idx) => 
            `${idx + 1}. [${v.tool}] Line ${v.line} - ${v.severity}: ${v.message}`
        ).join("\n") || "No vulnerabilities detected";

        const response = await axios.post(
            "https://api.groq.com/openai/v1/chat/completions",
            {
                model: "llama-3.3-70b-versatile",
                messages: [
                    { 
                        role: "system", 
                        content: `You are a security report writer. Create a professional, detailed security analysis report.

Structure the report with these sections:
1. EXECUTIVE SUMMARY - Brief overview of findings
2. VULNERABILITIES DETECTED - Detailed explanation of each issue
3. SECURITY ANALYSIS - Technical analysis of the risks
4. FIXES IMPLEMENTED - Explanation of how each vulnerability was fixed
5. CODE IMPROVEMENTS - Security best practices applied
6. RECOMMENDATIONS - Future security measures

Use clear, professional language. Be specific about security risks and fixes.` 
                    },
                    { 
                        role: "user", 
                        content: `Generate a comprehensive security report for this ${language} code analysis:

**VULNERABILITIES FOUND:**
${vulnSummary}

**ORIGINAL VULNERABLE CODE:**
${originalCode}

**FIXED SECURE CODE:**
${fixedCode}

Please provide a detailed security report explaining what was wrong, why it was dangerous, and how the fixes address each vulnerability.` 
                    }
                ],
                temperature: 0.3,
                max_tokens: 2500
            },
            { 
                headers: { 
                    "Authorization": `Bearer ${API_KEY}`,
                    "Content-Type": "application/json"
                },
                timeout: 50000
            }
        );

        console.log("✅ Security report generated");
        
        res.json({
            ok: true,
            report: response.data.choices[0].message.content
        });

    } catch (err) {
        console.error("❌ Report Generation Error:", err.response?.status, err.response?.data || err.message);
        const errorMsg = err.response?.data?.error?.message || err.message;
        res.json({
            ok: false,
            error: `Unable to generate report. ${errorMsg}`
        });
    }
});

app.listen(5000, () => {
    console.log("🔥 Backend running on http://localhost:5000");
});
