# ⚡ PayloadGen (v2.5.0)

![React](https://img.shields.io/badge/React-18-blue?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)
![Vite](https://img.shields.io/badge/Vite-fast-purple?logo=vite)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3-cyan?logo=tailwindcss)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> 🧪 **A high-performance Offensive Security Dashboard.**
> Access a curated database of payloads with technical breakdowns, "Cyber-Hacker" aesthetics, and fuzzer-ready export options.

---

## 🚀 Live Demo

🔗 **Live Preview:**
👉 [https://payloadgeneratorui.vercel.app](https://payloadgeneratorui.vercel.app)

---

## 🧠 New Features (v2.5)

*   **🎨 Cyber-Professional UI:** A sleek, forced dark-mode interface with glassmorphism, neon accents, and CRT-style grid effects designed for late-night hacking.
*   **📚 Expanded Database:** Now supports **12+ Categories** including SSRF, Prototype Pollution, LDAP Injection, and Cloud Metadata attacks.
*   **🔬 Technical Analysis:** Every payload comes with a "Technical Analysis" breakdown explaining *how* and *why* it works (bypass techniques, context, etc.).
*   **⚡ Fuzzer-Ready Exports:**
    *   **TXT Export:** Generates a clean, newline-separated wordlist perfect for **Burp Suite Intruder**, **FFUF**, or **OWASP ZAP**.
    *   **JSON Export:** Full database dump for integration with custom scanners.
*   **🔍 Advanced Search:** Instant filtering by payload string, description, or tags (e.g., `#bypass`, `#aws`, `#auth`).

---

## 📂 Project Structure

```
payloadgenerator/
│
├── src/
│   ├── components/
│   │   └── Footer.tsx       # Cyber-styled footer
│   ├── PayloadDashboard.tsx # Main UI Logic & Layout
│   ├── Payloads.ts          # Expanded Database (The "Brain")
│   ├── config.ts            # Author Config
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css            # Tailwind & Custom Cyber Effects
│
├── index.html
├── vite.config.ts
├── tailwind.config.js
└── package.json
```

---

## 🛠️ Tech Stack

*   **Core:** React 18 + TypeScript
*   **Build:** Vite
*   **Styling:** TailwindCSS + Custom CSS Variables (Neon/Glassmorphism)
*   **Icons:** Lucide React
*   **Utils:** Blob API (for exports), Clipboard API

---

## ⚙️ Installation & Run Locally

```bash
# 1. Clone the repository
git clone https://github.com/krsatyam11/payloadgenerator.git

# 2. Navigate to directory
cd payloadgenerator

# 3. Install dependencies
npm install

# 4. Run the development server
npm run dev
```

Open in browser: `http://localhost:5173`

---

## 📌 Supported Attack Vectors

| Category | Description |
| :--- | :--- |
| **🧨 XSS** | Cross-Site Scripting (Reflected, SVG, Polyglots) |
| **💉 SQLi** | SQL Injection (Auth Bypass, Blind, Time-based) |
| **🖥️ CMDi** | Command Injection (Unix/Win chaining, OOB) |
| **🧩 SSTI** | Server-Side Template Injection (Jinja2, Java, Ruby) |
| **☁️ SSRF** | Server-Side Request Forgery (Cloud Metadata, AWS) |
| **📁 LFI** | Local File Inclusion (Path Traversal, Wrappers) |
| **🌐 RFI** | Remote File Inclusion (SMB, HTTP) |
| **📄 XXE** | XML External Entity (LFD, SSRF via XXE) |
| **🎭 CSRF** | Cross-Site Request Forgery (Auto-submit forms) |
| **🗄️ NoSQLi** | NoSQL Injection (MongoDB, Regex extraction) |
| **🔄 Redirect** | Open Redirects (Filter bypasses) |
| **🧬 Proto** | JavaScript Prototype Pollution (JSON, Gadgets) |

---

## 💾 How to Use Exports

### 1. Fuzzer Wordlist (.txt)
Click the **TXT** button in the header.
*   **Output:** A clean text file with one payload per line.
*   **Use Case:** Load directly into **Burp Suite Intruder** (Payloads tab) or use with **FFUF**:
    ```bash
    ffuf -w payloads.txt -u https://target.com/vuln?param=FUZZ
    ```

### 2. Full Database (.json)
Click the **JSON** button in the header.
*   **Output:** A structured JSON file containing payload, description, and tags.
*   **Use Case:** Import into custom Python/Go scanners.

---

## 👨‍💻 Author

**Kr Satyam**
🎓 3rd Year CSE Student
🛡️ Cybersecurity Learner & Offensive Security Enthusiast

📧 Email: **[kaizenbreach@gmail.com](mailto:kaizenbreach@gmail.com)**

---

## 🌐 Socials

[![GitHub](https://img.shields.io/badge/GitHub-krsatyam11-black?logo=github)](https://github.com/krsatyam11)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-krsatyam07-blue?logo=linkedin)](https://linkedin.com/in/krsatyam07)
[![YouTube](https://img.shields.io/badge/YouTube-KaizenBreach-red?logo=youtube)](https://youtube.com/@KaizenBreach)
[![Instagram](https://img.shields.io/badge/Instagram-kaizenbreach-purple?logo=instagram)](https://instagram.com/kaizenbreach)
[![Threads](https://img.shields.io/badge/Threads-kaizenbreach-black?logo=threads)](https://threads.net/@kaizenbreach)

---

## ⚠️ Disclaimer

> 🛑 **Legal Warning:**
> This project is designed for **educational purposes, authorized penetration testing, and CTF challenges only**.
>
> The author (**Kr Satyam**) is not responsible for any illegal use of these payloads. Never attack a system without explicit written permission from the owner.

---

## ⭐ Support

If you find this tool useful for your bug bounties or pentests:

*   ⭐ **Star the repo**
*   🍴 **Fork it**
*   🧠 **Contribute new payloads**

---

## 📜 License

📄 MIT License
