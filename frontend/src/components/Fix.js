import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Controlled as CodeMirror } from "react-codemirror2";
import axios from "axios";
import jsPDF from "jspdf";

import "codemirror/lib/codemirror.css";
import "codemirror/theme/material.css";
import "codemirror/mode/python/python";
import "codemirror/mode/javascript/javascript";
import "codemirror/mode/clike/clike";
import "./Fix.css";

function Fix() {
  const location = useLocation();
  const navigate = useNavigate();
  const { originalCode, language, vulnerabilities } = location.state || {};

  const [fixedCode, setFixedCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);

  const user = JSON.parse(localStorage.getItem("user") || "{}");

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    navigate("/login");
  };

  const handleBackToAnalysis = () => {
    navigate("/app");
  };

  const generateFixedCode = async () => {
    if (!originalCode) {
      alert("No code to fix!");
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post("http://localhost:5000/api/fix-code", {
        code: originalCode,
        language,
        vulnerabilities
      });

      setFixedCode(response.data.fixed_code);
      
      // Show PDF report modal after code is fixed
      setTimeout(() => {
        setShowReportModal(true);
      }, 1000);
    } catch (error) {
      console.error("Error generating fix:", error);
      setFixedCode("Error generating fixed code. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(fixedCode);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  const generatePDFReport = async () => {
    setGeneratingReport(true);
    
    try {
      // Get AI-generated report from backend
      const response = await axios.post("http://localhost:5000/api/generate-report", {
        originalCode,
        fixedCode,
        language,
        vulnerabilities
      });

      const reportText = response.data.report;

      // Create PDF
      const doc = new jsPDF();
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      const margin = 15;
      const maxWidth = pageWidth - (margin * 2);
      let yPosition = 20;

      // Header
      doc.setFillColor(44, 62, 80);
      doc.rect(0, 0, pageWidth, 35, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(20);
      doc.text('Security Vulnerability Report', pageWidth / 2, 20, { align: 'center' });
      doc.setFontSize(10);
      doc.text(`Generated: ${new Date().toLocaleString()}`, pageWidth / 2, 28, { align: 'center' });

      yPosition = 45;

      // Report content
      doc.setTextColor(0, 0, 0);
      doc.setFontSize(10);

      const lines = doc.splitTextToSize(reportText, maxWidth);
      
      for (let i = 0; i < lines.length; i++) {
        if (yPosition > pageHeight - 20) {
          doc.addPage();
          yPosition = 20;
        }
        doc.text(lines[i], margin, yPosition);
        yPosition += 6;
      }

      // Footer
      const totalPages = doc.internal.getNumberOfPages();
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(128, 128, 128);
        doc.text(
          `Page ${i} of ${totalPages} | AI SDLC Security Auditor`,
          pageWidth / 2,
          pageHeight - 10,
          { align: 'center' }
        );
      }

      // Save PDF
      doc.save(`Security_Report_${language}_${Date.now()}.pdf`);

    } catch (error) {
      console.error("Error generating report:", error);
      alert("Failed to generate report. Please try again.");
    } finally {
      setGeneratingReport(false);
      setShowReportModal(false);
    }
  };

  return (
    <div className="fix-container">
      {/* Header */}
      <div className="fix-header">
        <div>
          <h1>🔧 Code Fix Generator</h1>
          <p>AI-powered security vulnerability remediation</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontWeight: "bold" }}>👤 {user.name || "User"}</div>
            <div style={{ fontSize: "12px", opacity: 0.8 }}>{user.email}</div>
          </div>
          <button onClick={handleLogout} className="logout-btn">
            Logout
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="fix-content">
        <button onClick={handleBackToAnalysis} className="back-btn">
          ← Back to Analysis
        </button>

        {/* Two Column Layout */}
        <div className="code-comparison">
          {/* Original Code */}
          <div className="code-panel">
            <div className="panel-header vulnerable">
              <h2>⚠️ Vulnerable Code</h2>
              <span className="language-badge">{language}</span>
            </div>
            <div className="code-editor-wrapper">
              <CodeMirror
                value={originalCode || "// No code provided"}
                options={{
                  mode: language === "python" ? "python" : 
                        language === "javascript" ? "javascript" :
                        language === "cpp" ? "text/x-c++src" :
                        language === "java" ? "text/x-java" : "python",
                  theme: "material",
                  lineNumbers: true,
                  lineWrapping: true,
                  readOnly: true
                }}
              />
            </div>
          </div>

          {/* Fixed Code */}
          <div className="code-panel">
            <div className="panel-header secure">
              <h2>✅ Secured Code</h2>
              <div style={{ display: "flex", gap: "10px" }}>
                {fixedCode && (
                  <>
                    <button 
                      onClick={copyToClipboard} 
                      className="copy-btn"
                    >
                      {copySuccess ? "✓ Copied!" : "📋 Copy Code"}
                    </button>
                    <button 
                      onClick={() => setShowReportModal(true)} 
                      className="copy-btn"
                      style={{ backgroundColor: "rgba(52, 152, 219, 0.3)", borderColor: "rgba(52, 152, 219, 0.5)" }}
                    >
                      📄 Generate Report
                    </button>
                  </>
                )}
              </div>
            </div>
            <div className="code-editor-wrapper">
              {!fixedCode && !loading && (
                <div className="generate-prompt">
                  <div className="prompt-icon"></div>
                  <h3>Welcome to Secure Coding</h3>
                  <p>Click the button below to fixes</p>
                  <button onClick={generateFixedCode} className="generate-btn">
                     Generate Fixed Code
                  </button>
                </div>
              )}

              {loading && (
                <div className="loading-state">
                  <div className="spinner"></div>
                  <p>AI is analyzing and fixing your code...</p>
                </div>
              )}

              {fixedCode && !loading && (
                <CodeMirror
                  value={fixedCode}
                  options={{
                    mode: language === "python" ? "python" : 
                          language === "javascript" ? "javascript" :
                          language === "cpp" ? "text/x-c++src" :
                          language === "java" ? "text/x-java" : "python",
                    theme: "material",
                    lineNumbers: true,
                    lineWrapping: true,
                    readOnly: false
                  }}
                  onBeforeChange={(editor, data, value) => {
                    setFixedCode(value);
                  }}
                />
              )}
            </div>
          </div>
        </div>

        {/* Vulnerabilities Summary */}
        {vulnerabilities && vulnerabilities.length > 0 && (
          <div className="vulnerabilities-summary">
            <h3>🛡️ Issues Fixed ({vulnerabilities.length})</h3>
            <div className="vulnerability-list">
              {vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="vulnerability-item">
                  <div className="vuln-badge">{vuln.tool}</div>
                  <div className="vuln-details">
                    <strong>Line {vuln.line}:</strong> {vuln.message}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* PDF Report Modal */}
      {showReportModal && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 2000
        }}>
          <div style={{
            backgroundColor: "white",
            borderRadius: "15px",
            padding: "40px",
            maxWidth: "500px",
            width: "90%",
            boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
            textAlign: "center"
          }}>
            <div style={{ fontSize: "60px", marginBottom: "20px" }}>📄</div>
            <h2 style={{ color: "#2c3e50", marginTop: 0, marginBottom: "10px" }}>
              Generate Security Report?
            </h2>
            <p style={{ color: "#7f8c8d", marginBottom: "30px", lineHeight: "1.6" }}>
              AI will analyze the vulnerabilities and fixes, then create a comprehensive PDF report with explanations.
            </p>
            
            <div style={{ display: "flex", gap: "15px", justifyContent: "center" }}>
              <button
                onClick={generatePDFReport}
                disabled={generatingReport}
                style={{
                  padding: "15px 30px",
                  backgroundColor: generatingReport ? "#95a5a6" : "#3498db",
                  color: "white",
                  border: "none",
                  borderRadius: "8px",
                  cursor: generatingReport ? "not-allowed" : "pointer",
                  fontSize: "16px",
                  fontWeight: "bold",
                  transition: "all 0.3s"
                }}
              >
                {generatingReport ? "⏳ Generating..." : "📥 Generate PDF"}
              </button>

              <button
                onClick={() => setShowReportModal(false)}
                disabled={generatingReport}
                style={{
                  padding: "15px 30px",
                  backgroundColor: "#95a5a6",
                  color: "white",
                  border: "none",
                  borderRadius: "8px",
                  cursor: generatingReport ? "not-allowed" : "pointer",
                  fontSize: "16px",
                  fontWeight: "bold"
                }}
              >
                Skip
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Fix;
