# 🏦 VulnBank

**VulnBank** is a deliberately vulnerable banking web application built for educational purposes and penetration testing practice. It simulates a realistic modern web application with a sleek dark-themed SPA (Single Page Application) interface, while intentionally implementing terrible security practices on the backend.

⚠️ **WARNING:** This application is explicitly vulnerable and should **never** be deployed in production or accessible over the public internet. Use it only in isolated local environments for educational purposes.

---

## 🚀 Quick Start

The easiest way to run VulnBank is through Docker:

```bash
# Clone the repository
git clone https://github.com/Neivoc/VulnBank.git
cd VulnBank

# Build and start the container
docker compose up --build -d
```

The application will be accessible at: `http://localhost:4000`

### Default Accounts
| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin123` | Administrator |
| `carlos` | `carlos123`| Standard User |
| `maria`  | `maria123` | Standard User |

*(Note: You can also register your own custom user directly from the login page!)*

---

## 🎯 Vulnerability Mapping

VulnBank contains **8 specific vulnerabilities** to discover and exploit. To make the challenge more realistic, there are no explicit "tests" or visual hints in the UI; you must find them as you would in a real pentest.

1. **JWT Tampering (Signature Bypass):** The underlying JWT library is configured poorly and blindly accepts the payload using `.decode()` instead of validating the cryptographic signature. Privileges can be escalated without knowing the secret key!
2. **User Enumeration:** Login and registration endpoints provide specific error messages that reveal whether an account exists or not.
3. **Insecure Direct Object Reference (IDOR):** Changing the IDs directly in the API requests or manipulating internal URLs like `/profile/1` will allow you to read other users' data without authorization blocks.
4. **Information Disclosure:** A debug endpoint is accidentally left exposed without authentication, leaking severe system details (such as tokens, software versions, and secrets).
5. **SQL Injection (SQLi):** The Transaction Search parses strings directly into SQLite queries instead of employing parameterized queries.
6. **Sensitive Data in Local Storage:** Complete session parameters, raw user roles, and even JWT tokens are kept purely inside the browser's `localStorage`.
7. **Stored XSS:** The application trusts user input (like support messages or transfer remarks) entirely, storing them verbatim and rendering them back into the DOM dynamically.
8. **Insecure File Upload (Client-Side Check Bypass):** The avatar uploader features a "secure" Javascript check limiting files to PNG/JPG. However, the server completely disregards file types, enabling Remote Code/Script inclusion (like `.html` or `.php`) via simple traffic interception.

---

## 💻 Tech Stack
* **Backend:** Node.js, Express.js
* **Database:** SQLite3
* **Frontend:** Vanilla HTML/CSS/JS (Dark Glassmorphism Theme)

Enjoy hacking! 🧑‍💻
