# Mini-SIEM: Real-Time Threat Monitoring Dashboard

A lightweight Security Information and Event Management (SIEM) system built with Python for cybersecurity education and threat detection.

---

## 🛡️ Features

- Real-time log analysis for SSH and web server logs
- Detects brute force login attempts, root login attempts, suspicious IP activity, SQL injection, XSS, and directory traversal
- Interactive Streamlit dashboard visualizing attack trends and threat distribution
- IP geolocation mapping of attacker sources
- Exportable JSON and CSV reports for further investigation
- Configurable brute force thresholds and time windows

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

```
git clone <your-repo-url>
cd mini-siem-dashboard
pip install -r requirements.txt
```

### Usage

1. Generate random test logs (optional but recommended):

```
python generate_logs.py
```

2. Run the demo threat analysis:

```
python demo.py
```

3. Launch the interactive dashboard:

```
streamlit run siem_dashboard.py
```

4. Open your browser to [http://localhost:8501](http://localhost:8501) to access the dashboard.

---

## 📁 Project Structure

```
mini-siem-dashboard/
├── mini_siem.py          - Core SIEM analysis engine
├── siem_dashboard.py     - Streamlit web dashboard
├── auth.log              - Sample SSH authentication logs
├── access.log            - Sample web server access logs
├── generate_logs.py      - Script to generate random test logs
├── demo.py               - Demo script for testing threat detection
├── deploy.sh             - Deployment automation script
├── requirements.txt      - Python dependencies
└── README.md             - This documentation file
```

---

## 🔍 Threat Detection

This project identifies cybersecurity threats including:

- Brute force SSH login attempts
- Unauthorized root login attempts
- IPs exhibiting suspicious repeated access
- SQL injection and other web application attacks (XSS, directory traversal)
- Suspicious user agents indicative of automated scanning tools

---

## 🎯 Educational Value

- Hands-on experience with log parsing and regex pattern matching
- Real-time data visualization concepts with Streamlit and Plotly
- Understanding core SIEM functions used by SOC analysts
- Practical exposure to threat hunting and incident detection

---

## 🤝 Contributing

Contributions are welcome! Please open issues or pull requests for bug fixes, features, or improvements.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📞 Contact

For questions or feedback, please reach out via GitHub issues or contact [your-email@example.com].

---

_Last updated: September 2025_

```
