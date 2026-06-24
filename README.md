# 🛡️ AI-Sentinel

### AI-Powered Automated Penetration Testing Framework using Machine Learning and Explainable AI

AI-Sentinel is an intelligent cybersecurity framework that automates network reconnaissance, vulnerability assessment, AI-driven risk classification, anomaly detection, attack simulation, and professional security report generation.

The framework combines **Supervised Machine Learning (Random Forest)**, **Unsupervised Anomaly Detection (Isolation Forest)**, and **Explainable AI (XAI)** to provide accurate and transparent security assessments.

---

## 🚀 Key Features

* 🔍 Automated Network Reconnaissance using Nmap
* 🤖 AI-Based Vulnerability Risk Classification
* 🌲 Random Forest Risk Prediction Model
* 🚨 Isolation Forest Anomaly Detection
* 🧠 Hybrid Risk Scoring Engine
* 📖 Explainable AI (XAI) for transparent decisions
* ⚔️ Automated Attack Simulation in Lab Environment
* 📄 Professional Security Report Generation (PDF)
* 🌐 Flask-Based Web Dashboard
* 📊 Interactive Risk Visualization

---

## 🏗️ System Architecture

```text
Target Host
     │
     ▼
Network Scanner (Nmap)
     │
     ▼
AI Analyzer
├── Random Forest Classifier
├── Isolation Forest
└── Hybrid Risk Scoring
     │
     ▼
Attack Engine
     │
     ▼
Report Generator
     │
     ▼
Flask Dashboard
```

---

## 🧠 AI Models

### Random Forest Classifier

The supervised model classifies vulnerabilities into five security levels:

* SAFE
* LOW
* MEDIUM
* HIGH
* CRITICAL

**Model Accuracy:** 94.5%

---

### Isolation Forest

The unsupervised model detects unusual service behaviors and previously unseen threat patterns.

Capabilities:

* Unknown Threat Detection
* Behavioral Anomaly Detection
* Outlier Identification
* Zero-Day Like Pattern Recognition

---

### Hybrid AI Risk Scoring

Final Risk Score:

```text
Final Score =
0.70 × Random Forest +
0.30 × Isolation Forest +
Expert Security Rules
```

This combines:

* Machine Learning
* Anomaly Detection
* Domain Knowledge
* Security Expert Rules

---

## 🛠️ Tech Stack

### Programming Language

* Python 3.11

### Backend

* Flask
* Flask-SocketIO

### AI & Machine Learning

* Scikit-Learn
* Random Forest
* Isolation Forest
* NumPy
* Pandas

### Cybersecurity Tools

* Nmap
* Metasploit
* Kali Linux

### Reporting

* ReportLab

### Web Technologies

* HTML
* CSS
* JavaScript
* Chart.js

### Additional Libraries

* Requests
* BeautifulSoup

---

## 📁 Project Structure

```text
AI-Sentinel/

├── app.py
├── main.py
├── scanner.py
├── ai_analyzer.py
├── attack_engine.py
├── report_generator.py
├── requirements.txt
│
├── model/
│
├── templates/
│
├── reports/
│
├── screenshots/
│   ├── dashboard.png
│   ├── scan_results.png
│   └── ai_analysis.png
│
├── README.md
├── LICENSE
└── .gitignore
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/TayyabAkhtar786/AI_Sentinel.git

cd AI-Sentinel
```

Create virtual environment:

```bash
python -m venv venv
```

Activate:

### Linux

```bash
source venv/bin/activate
```

### Windows

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Project

### Terminal Mode

```bash
python main.py
```

This launches the AI-powered penetration testing engine from the command line.

---

### Graphical Dashboard

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

---

## 📸 Screenshots

### Dashboard

<img width="975" height="348" alt="image" src="https://github.com/user-attachments/assets/436ce3fd-eb10-46b6-ae81-6672dca23951" />


---

### Scan Results

<img width="975" height="298" alt="image" src="https://github.com/user-attachments/assets/3d55d026-18c7-4860-b7a6-5ff54c4632a9" />


---

### AI Analysis

<img width="975" height="298" alt="image" src="https://github.com/user-attachments/assets/762b90d3-8af5-4b51-b02a-f947d1a4db84" />

---

## 🎯 Capabilities

AI-Sentinel can:

✔ Discover open ports and services

✔ Identify vulnerable software versions

✔ Detect known CVEs

✔ Classify vulnerabilities into risk levels

✔ Detect suspicious anomalies

✔ Explain AI decisions

✔ Simulate attacks in isolated lab environments

✔ Generate professional PDF reports

---

## 📈 Example Risk Categories

| Risk Level | Description                    |
| ---------- | ------------------------------ |
| SAFE       | No significant security issues |
| LOW        | Minor vulnerabilities          |
| MEDIUM     | Requires attention             |
| HIGH       | Serious security weakness      |
| CRITICAL   | Immediate remediation required |

---

## 🔬 Research Contribution

This project demonstrates:

* Practical application of AI in Cybersecurity
* Hybrid Supervised + Unsupervised Learning
* Explainable AI for Security Decisions
* Automated Vulnerability Assessment
* Intelligent Threat Prioritization

The project bridges Artificial Intelligence and Cybersecurity by showing how machine learning can improve the speed, transparency, and effectiveness of security assessments.

---

## 🚧 Future Improvements

* Real-Time Monitoring
* Deep Learning Models
* Natural Language Security Queries
* Automated Patch Suggestions
* Multi-Target Scanning
* CVE API Integration
* Federated Learning
* SIEM Integration

---

## ⚠️ Ethical Use Disclaimer

This project is intended strictly for:

* Educational purposes
* Research
* Authorized Security Assessments
* Controlled Laboratory Environments

Do NOT use this tool against systems without explicit authorization.
The author assumes no responsibility for misuse or unauthorized activities.

---

## 👨‍💻 Author

**Tayyab Akhtar**

Cybersecurity Enthusiast | AI Engineer | Penetration Testing Researcher

Areas of Interest:

* Cybersecurity
* Artificial Intelligence
* Penetration Testing
* Machine Learning
* Explainable AI

---

⭐ If you found this project interesting, consider giving it a star.
