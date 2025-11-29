import { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import axios from "axios";
import "./ThreatModel.css";

function ThreatModel() {
  const location = useLocation();
  const navigate = useNavigate();
  const { code, language, framework = "STRIDE" } = location.state || {};

  const [threatModel, setThreatModel] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedFramework, setSelectedFramework] = useState(framework);

  const user = JSON.parse(localStorage.getItem("user") || "{}");

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    navigate("/login");
  };

  const handleBackToAnalysis = () => {
    navigate("/app");
  };

  const generateThreatModel = async (selectedFramework) => {
    if (!code) {
      alert("No code to analyze!");
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post("http://localhost:5000/threat-model", {
        code,
        language,
        framework: selectedFramework
      });

      setThreatModel(response.data.threat_model);
    } catch (error) {
      console.error("Error generating threat model:", error);
      setThreatModel("Error generating threat model. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const switchFramework = (newFramework) => {
    setSelectedFramework(newFramework);
    setThreatModel(null);
    generateThreatModel(newFramework);
  };

  useEffect(() => {
    if (code) {
      generateThreatModel(selectedFramework);
    }
  }, []);

  const getFrameworkInfo = (fw) => {
    const info = {
      STRIDE: {
        icon: "🛡️",
        name: "STRIDE",
        description: "Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege",
        color: "#9b59b6"
      },
      PASTA: {
        icon: "🍝",
        name: "PASTA",
        description: "Process for Attack Simulation and Threat Analysis",
        color: "#3498db"
      },
      DREAD: {
        icon: "⚠️",
        name: "DREAD",
        description: "Damage, Reproducibility, Exploitability, Affected Users, Discoverability",
        color: "#e74c3c"
      }
    };
    return info[fw] || info.STRIDE;
  };

  const currentFramework = getFrameworkInfo(selectedFramework);

  return (
    <div className="threat-model-container">
      {/* Header */}
      <div className="threat-header">
        <div>
          <h1>🎯 Threat Modeling Analysis</h1>
          <p>AI-powered security threat assessment</p>
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
      <div className="threat-content">
        <button onClick={handleBackToAnalysis} className="back-btn">
          ← Back to Analysis
        </button>

        {/* Framework Selection Tabs */}
        <div className="framework-tabs">
          <button
            className={`framework-tab ${selectedFramework === "STRIDE" ? "active stride" : ""}`}
            onClick={() => switchFramework("STRIDE")}
          >
            <span className="tab-icon">🛡️</span>
            <span className="tab-name">STRIDE</span>
          </button>
          <button
            className={`framework-tab ${selectedFramework === "PASTA" ? "active pasta" : ""}`}
            onClick={() => switchFramework("PASTA")}
          >
            <span className="tab-icon">🍝</span>
            <span className="tab-name">PASTA</span>
          </button>
          <button
            className={`framework-tab ${selectedFramework === "DREAD" ? "active dread" : ""}`}
            onClick={() => switchFramework("DREAD")}
          >
            <span className="tab-icon">⚠️</span>
            <span className="tab-name">DREAD</span>
          </button>
        </div>

        {/* Threat Model Display */}
        <div className="threat-panel">
          <div className="panel-header" style={{ backgroundColor: currentFramework.color }}>
            <div>
              <h2>
                {currentFramework.icon} {currentFramework.name} Threat Model
              </h2>
              <p>{currentFramework.description}</p>
            </div>
          </div>

          <div className="threat-body">
            {loading && (
              <div className="loading-state">
                <div className="spinner"></div>
                <p>Analyzing threats using {currentFramework.name} framework...</p>
              </div>
            )}

            {!loading && threatModel && (
              <div className="threat-result">
                <pre>{threatModel}</pre>
              </div>
            )}

            {!loading && !threatModel && !code && (
              <div className="empty-state">
                <h3>No code provided</h3>
                <p>Please go back and analyze your code first.</p>
              </div>
            )}
          </div>
        </div>

        {/* Framework Info Card */}
        <div className="info-card">
          <h3>About {currentFramework.name}</h3>
          {selectedFramework === "STRIDE" && (
            <div>
              <p><strong>STRIDE</strong> is a threat modeling methodology developed by Microsoft. It categorizes threats into six types:</p>
              <ul>
                <li><strong>S</strong>poofing - Identity impersonation</li>
                <li><strong>T</strong>ampering - Data modification</li>
                <li><strong>R</strong>epudiation - Denying actions</li>
                <li><strong>I</strong>nformation Disclosure - Exposing sensitive data</li>
                <li><strong>D</strong>enial of Service - Resource exhaustion</li>
                <li><strong>E</strong>levation of Privilege - Unauthorized access</li>
              </ul>
            </div>
          )}
          {selectedFramework === "PASTA" && (
            <div>
              <p><strong>PASTA</strong> (Process for Attack Simulation and Threat Analysis) is a risk-centric framework with seven stages:</p>
              <ul>
                <li>Define business objectives</li>
                <li>Define technical scope</li>
                <li>Application decomposition</li>
                <li>Threat analysis</li>
                <li>Vulnerability analysis</li>
                <li>Attack modeling</li>
                <li>Risk and impact analysis</li>
              </ul>
            </div>
          )}
          {selectedFramework === "DREAD" && (
            <div>
              <p><strong>DREAD</strong> is a quantitative risk assessment model that rates threats based on:</p>
              <ul>
                <li><strong>D</strong>amage - How bad would the attack be?</li>
                <li><strong>R</strong>eproducibility - How easy is it to reproduce?</li>
                <li><strong>E</strong>xploitability - How much work is needed?</li>
                <li><strong>A</strong>ffected Users - How many users are impacted?</li>
                <li><strong>D</strong>iscoverability - How easy is it to discover?</li>
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ThreatModel;
