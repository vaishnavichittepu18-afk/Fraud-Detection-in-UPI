# UPI Fraud Detection Engine

A rule-based, deterministic transaction risk analysis framework designed to secure the UPI ecosystem against common payment vulnerabilities without relying on heavy machine learning overhead.

## 🚀 Key Features
* **Multi-Layered Verification Engine:** Separates risk profiling across QR payload structure scans, VPA target validation, and historical user behavioral checks.
* **Defensive Input Sanitization:** Safely standardizes localized user inputs (including currency symbols like ₹, spaces, and diverse decimal delimiters) to prevent structural injection attacks.
* **Adaptive Crowdsourced Mitigations:** Dynamically tracks user reports on VPAs and enforces systemic blacklisting once a statistical threshold is crossed.

## 🛠️ Tech Stack
* **Backend:** Python / Flask
* **Database:** SQLite
