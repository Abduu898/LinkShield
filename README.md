# 🛡️ LinkShield — Chrome Extension URL Security Analyzer

LinkShield is a Google Chrome extension (Manifest V3) designed to analyze URL structures locally and detect potential indicators of phishing and suspicious links using a lightweight heuristic engine.

---

## 🎯 Project Goals

- **Local & Private Analysis:** Performs real-time URL inspection directly within the browser without transmitting user input to external servers.
- **Transparent Heuristics:** Employs an explicit, rule-based detection engine with explainable findings for every flagged indicator.
- **DOM Security:** Implements rigorous input sanitization (`sanitizeHtml`) to prevent local Cross-Site Scripting (XSS) vulnerabilities.
- **Local Persistence:** Retains recent scan history using Chrome's asynchronous storage API (`chrome.storage.local`).

---

## 📐 Technical Architecture

Built with a modular, zero-dependency architecture (Vanilla JavaScript) to prioritize performance, security, and maintainability:

- `manifest.json`: Manifest V3 configuration file restricting permissions strictly to required local storage (`storage`).
- `popup.html`: Clean, accessible interface styled with modern CSS variables.
- `popup.js`: Manages UI interactions, DOM updates, event handling, HTML sanitization, and storage lifecycle.
- `analyzer.js`: Core logic module handling URL parsing, schema validation, heuristic evaluation, and risk scoring.

---

## 🔍 Heuristic Detection Rules

The engine parses submitted URLs using the native `URL` API and applies 5 targeted heuristic rules:

| Rule | Indicator | Severity | Weight | Technical Rationale |
| :--- | :--- | :--- | :---: | :--- |
| **Rule 1** | Direct IPv4 Address | `SUSPECT` | 3 | Bypasses standard DNS resolution and frequently correlates with temporary attack infrastructure. |
| **Rule 2** | Masking Symbol (`@`) | `HIGH` | 4 | Exploits URL user-info syntax to obscure the true destination hostname from the user. |
| **Rule 3** | Excessive Subdomains ($\ge 3$) | `SUSPECT` | 2 | Deep subdomain layering used to inject trusted brand names into untrusted hostnames (adjusted for multi-part TLDs). |
| **Rule 4** | Unencrypted Protocol (HTTP) | `LOW` | 1 | Indicates lack of TLS/SSL encryption in transit. |
| **Rule 5** | Hostname Target Keywords | `INFORMATIONAL` | 1 | Identifies sensitive keywords (`login`, `verify`, `account`, `banking`) when embedded directly in the hostname. |

### Risk Level Classification:
- **HIGH:** Cumulative Score $\ge 4$
- **MODERATE:** Cumulative Score $\ge 2$
- **LOW:** Cumulative Score $< 2$

---

## 🚀 Local Installation (Development)

1. Clone or download this repository to your local machine:
   ```bash
   git clone [https://github.com/Abduu898/LinkShield.git](https://github.com/Abduu898/LinkShield.git)
