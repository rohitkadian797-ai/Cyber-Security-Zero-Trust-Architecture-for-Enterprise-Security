# Zero Trust Architecture for Enterprise Security (ZTA)

[![Node.js](https://img.shields.io/badge/Node.js-v18%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Security](https://img.shields.io/badge/Security-Zero%20Trust%20(NIST%20800--207)-critical.svg)](#architecture-overview)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade **Zero Trust Architecture (ZTA)** security platform built in alignment with **NIST SP 800-207** standards. The system enforces continuous verification, dynamic policy-based access control, adaptive risk scoring, network microsegmentation, and comprehensive audit telemetry.

---

## 🛡️ Core Zero Trust Pillars

1. **Verify Explicitly**: Always authenticate and authorize based on all available data points (identity, location, device posture, service/workload, data classification, and anomalies).
2. **Use Least Privilege Access**: Limit user access with Just-In-Time (JIT) and Just-Enough-Access (JEA), Risk-Based Adaptive Polices, and data protection.
3. **Assume Breach**: Minimize blast radius and segment access. Verify end-to-end encryption and use analytics to gain visibility and improve defenses.

---

## 🏛️ System Architecture

```mermaid
graph TD
    Client[Enterprise Client / User] -->|1. Request with Context & Token| PEP[Policy Enforcement Point - API Gateway]
    PEP -->|2. Check Authentication| Auth[Authentication Service (MFA / TOTP)]
    PEP -->|3. Evaluate Context & Posture| PDP[Policy Decision Point - Policy Engine]
    PDP -->|Query Rules & Thresholds| DB[(Zero Trust SQLite Store)]
    PDP -->|Evaluate Trust Score & Device Posture| Risk[Adaptive Risk Assessment Engine]
    PDP -->|4. Grant / Deny Decision| PEP
    PEP -->|5. Allow Access via Microsegmentation| Micro[Internal Protected Resources / Microsegments]
    PEP -->|6. Log Telemetry Event| Audit[Audit & Telemetry Service]
```

### Key Components
- **Policy Enforcement Point (PEP)**: Intercepts all traffic, validates JWT sessions, and blocks unauthorized requests at the perimeter and internal boundaries.
- **Policy Decision Point (PDP)**: Dynamically evaluates real-time risk scores, time/location context, device posture, and role permissions.
- **Continuous Adaptive Trust Engine**: Calculates dynamic risk scores considering IP geolocation, device compliance status, and failed attempts.
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA with QR code generation via `otplib` and `qrcode`.
- **Microsegmentation Engine**: Enforces strict east-west and north-south traffic policies between enterprise services.
- **Immutable Audit Logging**: Detailed audit trail of all access requests, policy evaluations, and security alerts.

---

## 📦 Project Structure

```text
.
├── client/                     # Frontend Management Dashboard
│   ├── index.html              # Interactive Zero Trust Console
│   ├── package.json            # Client dependencies & scripts
│   └── src/
│       ├── main.js             # Client logic & API integrations
│       └── style.css           # Modern Cyberpunk / Dark Security UI
│
├── server/                     # Backend Zero Trust Engine (TypeScript)
│   ├── package.json            # Server dependencies
│   ├── tsconfig.json           # TypeScript configuration
│   ├── .env.example            # Environment template
│   └── src/
│       ├── index.ts            # Server entrypoint & security middleware
│       ├── db/                 # SQLite database schema, initialization & seed data
│       ├── middleware/         # PEP middleware & Auth verification
│       ├── routes/             # API routes (Auth, Policy, Resources, Network, Audit)
│       ├── services/           # Authentication & Policy Evaluation Engine
│       ├── types/              # TypeScript definitions & schemas
│       └── utils/              # Cryptographic helpers & hash utilities
│
└── .gitignore                  # Git ignore rules (node_modules, .env, db files)
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher

### 1. Backend Setup (Server)

```bash
cd server

# Install dependencies
npm install

# Configure environment variables
cp .env.example .env

# Seed initial database policies and users
npm run seed

# Start server in development mode
npm run dev
```
The server will start on `http://localhost:5000`.

### 2. Frontend Setup (Client)

```bash
cd client

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Open your browser and navigate to `http://localhost:5173`.

---

## 🔒 Security & Policy Features

- **Strict Headers**: Hardened with Helmet (`CSP`, `HSTS`, `X-Content-Type-Options`).
- **Rate Limiting**: Defends against brute-force and credential stuffing attacks.
- **Dynamic Context**: Checks time of day, client IP, device health, and role.
- **Input Validation**: Strongly typed schema validation using `zod`.
- **Cryptographic Security**: Passwords hashed with `bcryptjs`, tokens signed with `jsonwebtoken`.

---

## 📡 API Endpoints Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register new identity |
| `POST` | `/api/auth/login` | Authenticate identity (Step 1) |
| `POST` | `/api/auth/verify-mfa` | Complete MFA TOTP validation (Step 2) |
| `GET`  | `/api/policy` | List active Zero Trust access policies |
| `POST` | `/api/policy/evaluate` | Dynamic PDP policy evaluation |
| `GET`  | `/api/resources` | List protected enterprise resources |
| `GET`  | `/api/network/segments`| View microsegmentation zones |
| `GET`  | `/api/audit/logs` | Real-time security telemetry and audit trails |

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
