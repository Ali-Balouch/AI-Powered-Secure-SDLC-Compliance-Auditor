import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { Controlled as CodeMirror } from "react-codemirror2";

// Import CodeMirror CSS
import "codemirror/lib/codemirror.css";
import "codemirror/theme/material.css";
import "codemirror/mode/python/python";
import "codemirror/mode/javascript/javascript";
import "codemirror/mode/clike/clike";

function MainApp() {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("python");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [threatModel, setThreatModel] = useState(null);
  const [loadingThreat, setLoadingThreat] = useState(false);
  const [activeTab, setActiveTab] = useState("security");
  const navigate = useNavigate();

  const user = JSON.parse(localStorage.getItem("user") || "{}");

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    navigate("/login");
  };

  const analyzeCode = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:5000/analyze", {
        code,
        language
      });
      setResult(res.data);
    } catch (err) {
      setResult({ error: err.message });
    }
    setLoading(false);
  };

  const generateThreatModel = async () => {
    setLoadingThreat(true);
    try {
      const res = await axios.post("http://localhost:5000/threat-model", {
        code,
        language
      });
      setThreatModel(res.data.threat_model);
      setActiveTab("threat");
    } catch (err) {
      setThreatModel(`Error: ${err.message}`);
    }
    setLoadingThreat(false);
  };

  const getSecurityFindings = () => {
    if (!result) return [];
    
    const findings = [];

    if (result.semgrep?.results) {
      result.semgrep.results.forEach((item) => {
        findings.push({
          tool: "Semgrep",
          severity: item.extra?.severity || "INFO",
          line: item.start?.line || "N/A",
          message: item.extra?.message || "Security issue detected",
          cwe: item.extra?.metadata?.cwe?.[0] || "N/A",
          owasp: item.extra?.metadata?.owasp?.[0] || "N/A",
          reference: item.extra?.metadata?.references?.[0] || null
        });
      });
    }

    if (result.bandit?.results) {
      result.bandit.results.forEach((item) => {
        findings.push({
          tool: "Bandit",
          severity: item.issue_severity || "MEDIUM",
          line: item.line_number || "N/A",
          message: item.issue_text || "Security issue detected",
          testId: item.test_id || "N/A",
          cwe: `CWE-${item.issue_cwe?.id || "N/A"}`,
          reference: item.more_info || null
        });
      });
    }

    if (result.eslint && Array.isArray(result.eslint) && result.eslint.length > 0) {
      result.eslint.forEach((item) => {
        findings.push({
          tool: "ESLint",
          severity: item.severity || "WARNING",
          line: item.line || "N/A",
          message: item.message || "Code quality issue",
          ruleId: item.ruleId || "N/A"
        });
      });
    }

    return findings;
  };

  const getSeverityColor = (severity) => {
    switch ((severity || "").toUpperCase()) {
      case "ERROR":
      case "HIGH":
        return "#e74c3c";
      case "WARNING":
      case "MEDIUM":
        return "#f39c12";
      case "LOW":
        return "#3498db";
      default:
        return "#95a5a6";
    }
  };

  const findings = getSecurityFindings();
  const cmRef = useRef(null);

  const handleEditorDidMount = (editor) => {
    cmRef.current = editor;
    
    const wrapper = editor.getWrapperElement();
    wrapper.style.height = '400px';
    wrapper.style.minHeight = '400px';
    editor.setSize('100%', '400px');
    
    const scrollInfo = editor.getScrollInfo();
    editor.scrollTo(0, 0);
    editor.setCursor({ line: 0, ch: 0 });
    
    setTimeout(() => {
      editor.refresh();
      editor.scrollTo(0, 0);
    }, 10);
    
    editor.on('change', (instance, changeObj) => {
      if (changeObj.origin === 'paste' || changeObj.origin === '+input') {
        setTimeout(() => {
          const cursor = instance.getCursor();
          if (cursor.line === 0 && cursor.ch === 0) {
            instance.scrollTo(0, 0);
          }
        }, 0);
      }
    });
  };

  useEffect(() => {
    if (cmRef.current && code.length > 0) {
      const info = cmRef.current.getScrollInfo();
      if (info.top > 100) {
        cmRef.current.scrollTo(0, 0);
      }
    }
  }, [code]);

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#ecf0f1" }}>
      {/* Header with User Info */}
      <div style={{
        backgroundColor: "#2c3e50",
        color: "white",
        padding: "20px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        borderBottom: "4px solid #e74c3c"
      }}>
        <div>
          <h1 style={{ margin: "0 0 5px 0" }}>AI SDLC Security Compliance Auditor</h1>
          <p style={{ margin: "0", opacity: 0.8 }}>Professional Security Analysis for Python & JavaScript</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontWeight: "bold" }}>👤 {user.name || "User"}</div>
            <div style={{ fontSize: "12px", opacity: 0.8 }}>{user.email}</div>
          </div>
          <button
            onClick={handleLogout}
            style={{
              padding: "8px 16px",
              backgroundColor: "#e74c3c",
              color: "white",
              border: "none",
              borderRadius: "5px",
              cursor: "pointer",
              fontWeight: "bold"
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main Container */}
      <div style={{ display: "flex", flexDirection: "column", padding: "20px", maxWidth: "1400px", margin: "0 auto" }}>
        
        {/* Input Section */}
        <div style={{
          backgroundColor: "white",
          borderRadius: "8px",
          padding: "20px",
          marginBottom: "20px",
          boxShadow: "0 2px 10px rgba(0,0,0,0.1)"
        }}>
          <div style={{ marginBottom: "15px", display: "flex", gap: "15px", alignItems: "center" }}>
            <div>
              <label style={{ fontWeight: "bold", marginRight: "10px" }}>Language: </label>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                style={{
                  padding: "8px 12px",
                  fontSize: "14px",
                  borderRadius: "4px",
                  border: "2px solid #3498db",
                  cursor: "pointer"
                }}
              >
                <option value="python">🐍 Python</option>
                <option value="javascript">📝 JavaScript</option>
                <option value="cpp">⚙️ C++</option>
                <option value="java">☕ Java</option>
              </select>
            </div>
            <div style={{ marginLeft: "auto", display: "flex", gap: "10px" }}>
              <button
                onClick={analyzeCode}
                disabled={loading || !code.trim()}
                style={{
                  padding: "10px 20px",
                  cursor: loading || !code.trim() ? "not-allowed" : "pointer",
                  backgroundColor: loading || !code.trim() ? "#95a5a6" : "#e74c3c",
                  color: "white",
                  border: "none",
                  borderRadius: "5px",
                  fontSize: "14px",
                  fontWeight: "bold"
                }}
              >
                {loading ? "🔍 Analyzing..." : "🚀 Analyze Code"}
              </button>

              <button
                onClick={generateThreatModel}
                disabled={loadingThreat || !code.trim()}
                style={{
                  padding: "10px 20px",
                  cursor: loadingThreat || !code.trim() ? "not-allowed" : "pointer",
                  backgroundColor: loadingThreat || !code.trim() ? "#95a5a6" : "#9b59b6",
                  color: "white",
                  border: "none",
                  borderRadius: "5px",
                  fontSize: "14px",
                  fontWeight: "bold"
                }}
              >
                {loadingThreat ? "🎯 Modeling..." : "🎯 Threat Model"}
              </button>
            </div>
          </div>

          <div style={{ border: "2px solid #34495e", borderRadius: "5px", overflow: "hidden" }}>
            <CodeMirror
              value={code}
              options={{
                mode: language === "python" ? "python" : 
                      language === "javascript" ? "javascript" :
                      language === "cpp" ? "text/x-c++src" :
                      language === "java" ? "text/x-java" : "python",
                theme: "material",
                lineNumbers: true,
                lineWrapping: true
              }}
              onBeforeChange={(editor, data, value) => {
                setCode(value);
              }}
              editorDidMount={handleEditorDidMount}
            />
          </div>
        </div>

        {/* Tab Navigation */}
        {(result || threatModel) && (
          <div style={{
            backgroundColor: "white",
            borderRadius: "8px 8px 0 0",
            padding: "0",
            marginBottom: "0",
            boxShadow: "0 2px 10px rgba(0,0,0,0.1)",
            display: "flex",
            borderBottom: "2px solid #ecf0f1"
          }}>
            <button
              onClick={() => setActiveTab("security")}
              style={{
                flex: 1,
                padding: "15px",
                border: "none",
                borderBottom: activeTab === "security" ? "3px solid #e74c3c" : "none",
                backgroundColor: activeTab === "security" ? "white" : "#ecf0f1",
                fontWeight: "bold",
                cursor: "pointer",
                fontSize: "16px",
                color: activeTab === "security" ? "#2c3e50" : "#7f8c8d",
                borderRadius: "8px 0 0 0"
              }}
            >
              🛡️ Security Analysis
            </button>
            <button
              onClick={() => setActiveTab("threat")}
              style={{
                flex: 1,
                padding: "15px",
                border: "none",
                borderBottom: activeTab === "threat" ? "3px solid #9b59b6" : "none",
                backgroundColor: activeTab === "threat" ? "white" : "#ecf0f1",
                fontWeight: "bold",
                cursor: "pointer",
                fontSize: "16px",
                color: activeTab === "threat" ? "#2c3e50" : "#7f8c8d",
                borderRadius: "0 8px 0 0"
              }}
            >
              🎯 STRIDE Threat Model
            </button>
          </div>
        )}

        {/* Results Section */}
        {result && activeTab === "security" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", minHeight: "500px" }}>
            
            <div style={{
              backgroundColor: "white",
              borderRadius: "8px",
              padding: "20px",
              boxShadow: "0 2px 10px rgba(0,0,0,0.1)",
              overflowY: "auto",
              maxHeight: "600px"
            }}>
              <h2 style={{ color: "#2c3e50", marginTop: "0", borderBottom: "2px solid #e74c3c", paddingBottom: "10px" }}>
                🛡️ Security Findings ({findings.length})
              </h2>

              {findings.length === 0 ? (
                <div style={{
                  backgroundColor: "#d5f4e6",
                  color: "#27ae60",
                  padding: "20px",
                  borderRadius: "5px",
                  textAlign: "center",
                  fontWeight: "bold"
                }}>
                  ✅ No security vulnerabilities detected!
                </div>
              ) : (
                findings.map((finding, idx) => (
                  <div
                    key={idx}
                    style={{
                      backgroundColor: "#f8f9fa",
                      border: `3px solid ${getSeverityColor(finding.severity)}`,
                      borderRadius: "6px",
                      padding: "15px",
                      marginBottom: "12px"
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: "8px" }}>
                      <h4 style={{ margin: "0", color: "#2c3e50" }}>{finding.tool}</h4>
                      <span style={{
                        backgroundColor: getSeverityColor(finding.severity),
                        color: "white",
                        padding: "4px 8px",
                        borderRadius: "3px",
                        fontSize: "12px",
                        fontWeight: "bold"
                      }}>
                        {finding.severity}
                      </span>
                    </div>

                    <p style={{ margin: "8px 0", color: "#34495e", fontSize: "14px" }}>
                      <strong>Line {finding.line}:</strong> {finding.message}
                    </p>

                    <div style={{ fontSize: "12px", color: "#7f8c8d", marginTop: "8px" }}>
                      {finding.cwe && <p style={{ margin: "4px 0" }}>🔗 {finding.cwe}</p>}
                      {finding.owasp && <p style={{ margin: "4px 0" }}>📋 {finding.owasp}</p>}
                      {finding.testId && <p style={{ margin: "4px 0" }}>📌 {finding.testId}</p>}
                      {finding.reference && (
                        <a href={finding.reference} target="_blank" rel="noopener noreferrer" style={{
                          color: "#3498db",
                          textDecoration: "none"
                        }}>
                          Learn more →
                        </a>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div style={{
              backgroundColor: "white",
              borderRadius: "8px",
              padding: "20px",
              boxShadow: "0 2px 10px rgba(0,0,0,0.1)",
              overflowY: "auto",
              maxHeight: "600px"
            }}>
              <h2 style={{ color: "#2c3e50", marginTop: "0", borderBottom: "2px solid #27ae60", paddingBottom: "10px" }}>
                💡 AI Security Analysis
              </h2>

              {result.ai_feedback ? (
                <div style={{
                  backgroundColor: "#f0f7ff",
                  border: "2px solid #3498db",
                  borderRadius: "6px",
                  padding: "15px",
                  fontSize: "14px",
                  lineHeight: "1.6",
                  color: "#2c3e50",
                  whiteSpace: "pre-wrap",
                  wordWrap: "break-word"
                }}>
                  {result.ai_feedback}
                </div>
              ) : (
                <div style={{
                  backgroundColor: "#ffe5e5",
                  color: "#c0392b",
                  padding: "15px",
                  borderRadius: "5px",
                  textAlign: "center"
                }}>
                  ⚠️ No AI analysis available
                </div>
              )}
            </div>
          </div>
        )}

        {threatModel && activeTab === "threat" && (
          <div style={{
            backgroundColor: "white",
            borderRadius: "0 0 8px 8px",
            padding: "30px",
            boxShadow: "0 2px 10px rgba(0,0,0,0.1)",
            marginTop: "0"
          }}>
            <h2 style={{ color: "#2c3e50", marginTop: "0", borderBottom: "2px solid #9b59b6", paddingBottom: "10px" }}>
              🎯 STRIDE Threat Model Analysis
            </h2>

            <div style={{
              backgroundColor: "#f8f4ff",
              border: "2px solid #9b59b6",
              borderRadius: "6px",
              padding: "20px",
              fontSize: "14px",
              lineHeight: "1.8",
              color: "#2c3e50",
              whiteSpace: "pre-wrap",
              wordWrap: "break-word",
              fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif"
            }}>
              {threatModel}
            </div>
          </div>
        )}

        {!result && !loading && !threatModel && !loadingThreat && (
          <div style={{
            backgroundColor: "white",
            borderRadius: "8px",
            padding: "60px 20px",
            textAlign: "center",
            boxShadow: "0 2px 10px rgba(0,0,0,0.1)"
          }}>
            <h3 style={{ color: "#7f8c8d", marginTop: "0" }}>👆 Paste your code and click "Analyze Code" to start</h3>
            <p style={{ color: "#95a5a6" }}>Supports Python and JavaScript code analysis</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default MainApp;
