# 🔥 AI SDLC Security Compliance Auditor

A comprehensive web application that analyzes code for security vulnerabilities using multiple tools including Semgrep, Bandit, ESLint, and AI-powered feedback from GitHub Copilot.

## Features

- **Multi-Tool Analysis**: Combines Semgrep, Bandit (Python), ESLint (JavaScript), and AI feedback
- **Language Support**: Python and JavaScript code analysis
- **Interactive Code Editor**: CodeMirror-based editor with syntax highlighting
- **Real-time Results**: Displays analysis results in readable JSON format
- **AI-Powered Insights**: Leverages GitHub Copilot API for intelligent vulnerability detection

## Prerequisites

Before running this application, ensure you have the following installed:

- **Node.js** (v16 or higher)
- **npm** (comes with Node.js)
- **Python** (v3.8 or higher)
- **Semgrep**: `pip install semgrep`
- **Bandit**: `pip install bandit`
- **GitHub Copilot API Key** (requires GitHub Copilot subscription)

### Installing Security Tools

```bash
# Install Semgrep
pip install semgrep

# Install Bandit
pip install bandit

# Verify installations
semgrep --version
bandit --version
```

## Project Structure

```
ssd_project/
├── server.js              # Backend server (Node.js + Express)
├── package.json           # Backend dependencies
├── eslint.config.mjs      # ESLint configuration
├── .env                   # Environment variables (API keys)
├── .gitignore            # Git ignore rules
├── README.md             # This file
└── frontend/             # React frontend
    ├── package.json      # Frontend dependencies
    ├── src/
    │   ├── App.js        # Main React component
    │   ├── index.js      # React entry point
    │   └── ...
    └── public/
```

## Installation

### 1. Clone or navigate to the project directory

```bash
cd /home/mustan-sir-hussain/Desktop/ssd_project
```

### 2. Install backend dependencies

```bash
npm install
```

### 3. Install frontend dependencies

```bash
cd frontend
npm install
cd ..
```

## Configuration

### 1. Set up environment variables

Edit the `.env` file in the root directory and add your GitHub Copilot API key:

```env
COPILOT_API_KEY=your_actual_api_key_here
```

**How to get a GitHub Copilot API Key:**
1. You need a GitHub Copilot subscription
2. Generate a personal access token at: https://github.com/settings/tokens
3. The token needs appropriate Copilot API permissions

### 2. ESLint Configuration

The project includes `eslint.config.mjs` for JavaScript code analysis. No additional configuration needed.

## Running the Application

### Option 1: Run Both Servers Together (Recommended)

```bash
npm run dev
```

This will start:
- Backend server on `http://localhost:5000`
- Frontend server on `http://localhost:3000`

### Option 2: Run Servers Separately

**Terminal 1 - Backend:**
```bash
npm start
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm start
```

## Usage

1. Open your browser and navigate to `http://localhost:3000`
2. Select the programming language (Python or JavaScript)
3. Paste or write your code in the CodeMirror editor
4. Click the "Analyze Code" button
5. Wait for the analysis to complete (loading indicator will show)
6. View the results which include:
   - **Semgrep**: Security patterns and vulnerabilities
   - **Bandit** (for Python) or **ESLint** (for JavaScript): Language-specific issues
   - **AI Feedback**: GitHub Copilot's security analysis

## API Endpoints

### Backend (Port 5000)

#### `GET /`
- Returns: Server status message
- Response: `"🔥 AI SDLC Security Compliance Auditor backend is running!"`

#### `POST /analyze`
- Accepts: JSON body with `{ code: string, language: string }`
- Returns: JSON object with analysis results
```json
{
  "ok": true,
  "semgrep": { ... },
  "bandit": { ... },    // for Python
  "eslint": { ... },    // for JavaScript
  "ai_feedback": "..."
}
```

## Technology Stack

### Backend
- **Node.js** with ES Modules
- **Express.js** - Web framework
- **CORS** - Cross-origin resource sharing
- **dotenv** - Environment variable management
- **Axios** - HTTP client for API calls
- **child_process** - Running security tools

### Frontend
- **React** - UI framework
- **CodeMirror** - Code editor component
- **Axios** - HTTP client
- **react-codemirror2** - React wrapper for CodeMirror

### Security Tools
- **Semgrep** - Static analysis for both Python and JavaScript
- **Bandit** - Python-specific security linter
- **ESLint** - JavaScript linter
- **GitHub Copilot API** - AI-powered vulnerability detection

## Error Handling

The application includes comprehensive error handling:
- Frontend displays error messages if backend is unreachable
- Backend catches and returns errors from security tools
- AI feedback errors are gracefully handled and reported

## Troubleshooting

### Backend won't start
- Ensure all dependencies are installed: `npm install`
- Check if port 5000 is available
- Verify `.env` file exists with API key

### Frontend won't start
- Navigate to frontend directory and run: `npm install`
- Check if port 3000 is available
- Clear cache: `rm -rf node_modules package-lock.json && npm install`

### Security tools not found
- Verify Semgrep installation: `semgrep --version`
- Verify Bandit installation: `bandit --version`
- Ensure tools are in your system PATH

### AI feedback returns errors
- Verify your GitHub Copilot API key is correct
- Ensure you have an active GitHub Copilot subscription
- Check your internet connection

## Development

To modify the application:

1. **Backend changes**: Edit `server.js`
2. **Frontend changes**: Edit files in `frontend/src/`
3. **Add dependencies**: Use `npm install <package>` in respective directories

## License

This project is for educational purposes.

## Contributors

Built for AI SDLC Security Compliance Auditing.
