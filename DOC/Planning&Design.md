# Phase 0: Planning and Design Documentation
## Secure Banking System with PostgreSQL

---

## 1. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Login UI   │  │  Dashboard   │  │  Admin Panel │           │
│  │  (index.html)│  │(dashboard.html)│ │ (admin.html) │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                  │                  │                 │
│         └──────────────────┴──────────────────┘                 │
│                            │                                    │
└────────────────────────────┼────────────────────────────────────┘
                             │ HTTPS (Port 8080)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FRONTEND LAYER                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              NGINX Web Server (Alpine)                    │  │
│  │  - Serves static HTML/CSS/JS                              │  │
│  │  - Port 8080 exposed                                      │  │
│  │  - Resource limits: 0.5 CPU, 256MB RAM                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                             │
                             │ HTTP API Calls (Port 3000)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │           Node.js/Express API Server                      │  │
│  │                                                           │  │
│  │  Authentication Middleware:                               │  │
│  │  ├─ JWT Token Verification                                │  │
│  │  ├─ Role-Based Access Control (RBAC)                      │  │
│  │  └─ Session Management                                    │  │
│  │                                                           │  │
│  │  API Endpoints:                                           │  │
│  │  ├─ /api/auth/*        (Registration/Login)               │  │
│  │  ├─ /api/user/*        (User Operations)                  │  │
│  │  ├─ /api/admin/*       (Admin Operations)                 │  │
│  │  └─ /api/user/sample-data, /api/user/csv-analytics        │  │
│  │                                                           │  │
│  │  Security Features:                                       │  │
│  │  ├─ Input validation & sanitization                       │  │
│  │  ├─ Bcrypt password hashing (12 rounds)                   │  │
│  │  ├─ JWT with 24h expiry                                   │  │
│  │  ├─ CORS configured for specific origins                  │  │
│  │  └─ Rate limiting & account lockout                       │  │
│  │                                                           │  │
│  │  Resource limits: 1.0 CPU, 512MB RAM                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                             │
                             │ PostgreSQL Protocol (SSL/TLS)
                             │ Port 5432
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DATABASE LAYER                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              PostgreSQL 15 Database                       │  │
│  │                                                           │  │
│  │  Security Configuration:                                  │  │
│  │  ├─ SSL/TLS encryption REQUIRED                           │  │
│  │  ├─ Self-signed certificates (auto-generated)             │  │
│  │  ├─ SCRAM-SHA-256 authentication                          │  │
│  │  └─ Separate admin and app users                          │  │
│  │                                                           │  │
│  │  Database Users:                                          │  │
│  │  ├─ postgres (superuser)                                  │  │
│  │  ├─ admin_user (full privileges)                          │  │
│  │  └─ app_user (restricted privileges)                      │  │
│  │                                                           │  │
│  │  Tables:                                                  │  │
│  │  ├─ users          (user accounts)                        │  │
│  │  ├─ accounts       (bank accounts)                        │  │
│  │  ├─ transactions   (transaction history)                  │  │
│  │  ├─ sessions       (JWT session tracking)                 │  │
│  │  └─ audit_log      (security audit trail)                 │  │
│  │                                                           │  │
│  │  Security Features:                                       │  │
│  │  ├─ Audit triggers on all tables                          │  │
│  │  ├─ Failed login tracking                                 │  │
│  │  ├─ Account lockout after 5 failed attempts               │  │
│  │  ├─ Parameterized queries (SQL injection prevention)      │  │
│  │  └─ Stored procedures for sensitive operations            │  │
│  │                                                           │  │
│  │  Persistent Storage: db_data volume                       │  │
│  │  Resource limits: 0.5 CPU, 512MB RAM                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      NETWORK LAYER                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │         Docker Bridge Network: secure-net                 │  │
│  │  - Internal container communication                       │  │
│  │  - Database NOT exposed to host                           │  │
│  │  - Only frontend (8080) and API (3000) exposed            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Security Goals and Threat List

### **Security Goals**

#### **Confidentiality**
1. **Protect user credentials** - Passwords hashed with bcrypt (12 rounds)
2. **Secure data transmission** - PostgreSQL SSL/TLS encryption required
3. **Protect sensitive data at rest** - Database stored in encrypted volume
4. **JWT token security** - Short expiry (24h), signed with secret key
5. **File access control** - CSV/JSON files only accessible via authenticated API

#### **Integrity**
1. **Prevent SQL injection** - Parameterized queries throughout
2. **Input validation** - Client and server-side validation
3. **Audit logging** - All database changes tracked with triggers
4. **Transaction consistency** - ACID properties maintained
5. **Data immutability** - Transactions cannot be deleted (INSERT only)

#### **Availability**
1. **Resource limits** - CPU/memory constraints prevent DoS
2. **Account lockout** - 5 failed login attempts = 15min lockout
3. **Health checks** - Database connectivity monitoring
4. **Graceful degradation** - Error handling without data exposure
5. **Session management** - Expired tokens automatically rejected

### **Threat Model and Mitigations**

| **Threat** | **Category** | **Likelihood** | **Impact** | **Mitigation** |
|------------|--------------|----------------|------------|----------------|
| **SQL Injection** | Integrity | High | Critical | Parameterized queries, input validation |
| **Brute Force Login** | Confidentiality | High | High | Account lockout, bcrypt slow hashing |
| **Session Hijacking** | Confidentiality | Medium | High | JWT with short expiry, HTTPS only |
| **Privilege Escalation** | Authorization | Medium | Critical | RBAC, separate DB users, middleware checks |
| **XSS Attacks** | Integrity | Medium | Medium | Input sanitization, CSP headers |
| **CSRF Attacks** | Integrity | Medium | Medium | CORS configuration, token validation |
| **DoS/Resource Exhaustion** | Availability | Medium | Medium | Docker resource limits, rate limiting |
| **Data Breach (DB)** | Confidentiality | Low | Critical | SSL/TLS required, restricted network access |
| **Password Leakage** | Confidentiality | Medium | High | Bcrypt hashing, no password logging |
| **Unauthorized File Access** | Confidentiality | Medium | Medium | JWT authentication required for all endpoints |
| **Man-in-the-Middle** | Confidentiality | Low | High | SSL/TLS encryption on DB connections |
| **Directory Traversal** | Confidentiality | Low | High | Path validation in file operations |

---

## 3. Milestone Timeline

### **Week 1: Foundation & Setup** ✅
- [x] Docker environment configuration
- [x] PostgreSQL database with SSL/TLS
- [x] Basic authentication (JWT)
- [x] User registration and login
- [x] Frontend UI (login, dashboard)

### **Week 2: Core Banking Features** ✅
- [x] Account creation and management
- [x] Deposit/withdrawal operations
- [x] Transaction history tracking
- [x] Balance updates with audit trail
- [x] User-specific data filtering

### **Week 3: Security Hardening** ✅
- [x] Role-Based Access Control (Admin/Standard)
- [x] Failed login tracking and account lockout
- [x] Audit logging on all tables
- [x] Input validation and sanitization
- [x] SQL injection prevention

### **Week 4: Advanced Features** ✅
- [x] Admin dashboard (all users/accounts/transactions)
- [x] Analytics endpoints (user and system-wide)
- [x] CSV/JSON secure file endpoints (Parts D & E)
- [x] CSV export functionality
- [x] Resource limits and health checks

### **Week 5: Testing & Documentation** 🔄
- [x] Security testing scripts (PowerShell)
- [x] Port scan verification
- [x] SSL/TLS verification
- [x] Injection testing
- [ ] Comprehensive documentation
- [ ] Final report and reflection

---

## 4. One-Page Planning Sheet

### **Project Overview**
**Name:** Secure Banking System with PostgreSQL  
**Goal:** Build a containerized banking application with defense-in-depth security  
**Stack:** PostgreSQL 15, Node.js/Express, Docker Compose, NGINX

### **Core Requirements**
✅ User authentication with JWT  
✅ Role-based access control (Admin/Standard)  
✅ PostgreSQL with SSL/TLS encryption  
✅ Account management (create, deposit, withdraw)  
✅ Transaction history with audit trail  
✅ Secure file access (CSV/JSON endpoints)  
✅ Docker containerization with resource limits

### **Security Checklist**
- [x] Passwords hashed with bcrypt (12 rounds)
- [x] JWT tokens with 24h expiry
- [x] PostgreSQL SSL/TLS required
- [x] SQL injection prevention (parameterized queries)
- [x] Input validation (client + server)
- [x] Failed login tracking (5 attempts = lockout)
- [x] Audit logging on all tables
- [x] CORS configured for specific origins
- [x] Separate database users (admin_user, app_user)
- [x] Resource limits on all containers
- [x] Health checks on database
- [x] No sensitive data in logs

### **Deployment Architecture**
```
Frontend (NGINX:8080) → API Server (Node:3000) → Database (PostgreSQL:5432)
                                                          ↓
                                                  Persistent Volume
```

### **Key Security Features**
1. **Authentication:** JWT-based with bcrypt password hashing
2. **Authorization:** Middleware checks role before admin operations
3. **Encryption:** SSL/TLS on database connections
4. **Auditing:** Triggers log all INSERT/UPDATE/DELETE operations
5. **Rate Limiting:** Account lockout after failed login attempts
6. **Network Security:** Database not exposed to host, internal bridge network

### **Testing Strategy**
- ✅ Port scan (verify only 3000, 8080 exposed)
- ✅ SSL verification (PostgreSQL encryption enabled)
- ✅ Injection testing (SQL injection attempts rejected)
- ✅ Authentication testing (unauthorized requests blocked)
- ✅ Authorization testing (standard users can't access admin endpoints)

### **Known Limitations**
- Self-signed SSL certificates (not production-ready)
- No rate limiting middleware (only DB-level lockout)
- No email verification for registration
- No password reset functionality
- No multi-factor authentication (MFA)

### **Next Steps for Production**
1. Use Let's Encrypt or proper CA certificates
2. Implement rate limiting middleware (express-rate-limit)
3. Add email verification with SendGrid/SMTP
4. Implement password reset with time-limited tokens
5. Add MFA (TOTP with Google Authenticator)
6. Configure proper logging (Winston/Bunyan)
7. Set up monitoring (Prometheus/Grafana)
8. Add backup automation