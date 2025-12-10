# Phase 5: Team Report and Reflection
## Secure Banking System with PostgreSQL

---

## 1. Architecture Documentation

### **System Overview**

The Secure Banking System is a three-tier web application built with defense-in-depth security principles. The architecture consists of:

1. **Frontend Layer (NGINX)** - Static file server
2. **Application Layer (Node.js/Express)** - API server with authentication
3. **Database Layer (PostgreSQL 15)** - Persistent data storage with encryption

### **Component Details**

#### **Frontend Container**
- **Image:** nginx:alpine
- **Purpose:** Serves static HTML/CSS/JavaScript files
- **Exposed Port:** 8080
- **Files Served:**
  - `index.html` - Login and registration page
  - `dashboard.html` - User dashboard
  - `admin.html` - Administrator panel
  - `dataviewer.html` - Secure CSV/JSON data viewer
- **Security Features:**
  - Minimal Alpine Linux base (reduced attack surface)
  - Resource limits: 0.5 CPU, 256MB RAM
  - Only static content (no server-side execution)

#### **Application Server Container**
- **Image:** node:18-alpine
- **Purpose:** RESTful API server handling business logic
- **Exposed Port:** 3000
- **Key Components:**
  - Express.js web framework
  - JWT authentication middleware
  - Bcrypt password hashing
  - CORS protection
  - Input validation
- **API Endpoints:**
  ```
  Authentication:
    POST /api/auth/register - User registration
    POST /api/auth/login    - User login (returns JWT)
  
  User Operations:
    GET  /api/user/accounts              - List user's accounts
    POST /api/user/accounts/create       - Create new account
    GET  /api/user/transactions/:id      - Get account transactions
    POST /api/user/accounts/:id/deposit  - Deposit money
    POST /api/user/accounts/:id/withdraw - Withdraw money
    GET  /api/user/analytics             - User transaction analytics
    GET  /api/user/sample-data           - Secure JSON endpoint (Part D)
    GET  /api/user/csv-analytics         - Secure CSV endpoint (Part E)
  
  Admin Operations (requires admin role):
    GET /api/admin/users        - List all users
    GET /api/admin/accounts     - List all accounts
    GET /api/admin/transactions - List all transactions
    GET /api/admin/stats        - System statistics
    GET /api/admin/analytics    - System-wide analytics
  ```
- **Security Features:**
  - JWT token validation on all protected routes
  - Role-Based Access Control (RBAC)
  - Parameterized SQL queries (SQL injection prevention)
  - Input sanitization
  - Resource limits: 1.0 CPU, 512MB RAM

#### **Database Container**
- **Image:** Custom PostgreSQL 15 (with SSL setup)
- **Purpose:** Persistent data storage
- **Internal Port:** 5432 (NOT exposed to host)
- **Database Schema:**
  ```
  users
    ├─ user_id (primary key, auto-increment)
    ├─ username (unique, 3-50 chars)
    ├─ email (unique, validated)
    ├─ password_hash (bcrypt, 12 rounds)
    ├─ full_name
    ├─ role (admin/standard)
    ├─ is_active (account status)
    ├─ failed_login_attempts
    ├─ locked_until (lockout timestamp)
    └─ timestamps
  
  accounts
    ├─ account_id (primary key)
    ├─ user_id (foreign key → users)
    ├─ account_number (unique, auto-generated)
    ├─ balance (decimal, CHECK >= 0)
    ├─ status (active/suspended/closed)
    └─ timestamps
  
  transactions
    ├─ transaction_id (primary key)
    ├─ account_id (foreign key → accounts)
    ├─ transaction_type (deposit/withdrawal/transfer)
    ├─ amount (decimal, CHECK > 0)
    ├─ balance_after
    ├─ description
    └─ transaction_date
  
  sessions
    ├─ session_id (primary key)
    ├─ user_id (foreign key → users)
    ├─ token_hash
    ├─ ip_address
    ├─ user_agent
    ├─ expires_at
    └─ revoked
  
  audit_log
    ├─ audit_id (primary key)
    ├─ user_id (foreign key → users)
    ├─ action (INSERT/UPDATE/DELETE)
    ├─ table_name
    ├─ record_id
    ├─ old_values (JSONB)
    ├─ new_values (JSONB)
    └─ created_at
  ```
- **Database Users:**
  - `postgres` - Superuser (for initialization only)
  - `admin_user` - Full privileges (for admin operations)
  - `app_user` - Restricted privileges (used by API server)
- **Security Features:**
  - SSL/TLS encryption REQUIRED
  - SCRAM-SHA-256 authentication
  - Principle of least privilege (app_user has no DELETE)
  - Audit triggers on all tables
  - Failed login tracking with stored procedures
  - Account lockout (5 failed attempts = 15min lock)
  - Resource limits: 0.5 CPU, 512MB RAM

### **Network Architecture**

```
Docker Bridge Network: secure-net
├─ frontend:80    → Host:8080
├─ server:3000    → Host:3000
└─ db:5432        → Internal only (NOT exposed)
```

**Security Benefits:**
- Database is not accessible from the host machine
- All inter-container communication goes through the internal bridge network
- Only web server and API are exposed to external connections

### **Data Flow**

#### **User Login Flow:**
```
1. User enters credentials in index.html
2. Frontend sends POST to /api/auth/login
3. Server queries database for user
4. Server verifies password with bcrypt.compare()
5. Server checks if account is locked
6. Server generates JWT token (24h expiry)
7. Server returns token + user info
8. Frontend stores token in localStorage
9. All subsequent requests include JWT in Authorization header
```

#### **Authenticated Request Flow:**
```
1. Frontend sends request with JWT token
2. authenticateToken() middleware extracts and verifies token
3. Middleware decodes user_id and role from token
4. Middleware sets PostgreSQL session variable
5. Database queries filtered by user_id (for standard users)
6. Results returned to client
```

#### **Admin Authorization Flow:**
```
1. Request goes through authenticateToken() middleware
2. requireAdmin() middleware checks req.user.role
3. If role !== 'admin', return 403 Forbidden
4. If role === 'admin', proceed to handler
5. Handler queries database WITHOUT user_id filter
6. Returns system-wide data
```

---

## 2. Security Configuration Documentation

### **Authentication & Authorization**

#### **Password Security**
- **Hashing Algorithm:** bcrypt with 12 rounds (2^12 = 4096 iterations)
- **Salt:** Automatically generated per password
- **Storage:** Only hash stored in database, never plaintext
- **Verification:** `bcrypt.compare()` for constant-time comparison

```javascript
// Registration
const password_hash = await bcrypt.hash(password, 12);

// Login
const match = await bcrypt.compare(password, user.password_hash);
```

#### **JWT Token Security**
- **Algorithm:** HS256 (HMAC with SHA-256)
- **Secret Key:** Stored in environment variable (JWT_SECRET)
- **Expiry:** 24 hours
- **Payload:**
  ```json
  {
    "user_id": 1,
    "username": "alice",
    "role": "standard",
    "iat": 1234567890,
    "exp": 1234654290
  }
  ```
- **Validation:** Every request verifies signature and expiry

#### **Role-Based Access Control (RBAC)**
- **Roles:** admin, standard
- **Middleware Chain:**
  ```javascript
  app.get("/api/admin/users", 
    authenticateToken,  // Step 1: Verify JWT
    requireAdmin,       // Step 2: Check role === 'admin'
    handler            // Step 3: Execute request
  );
  ```
- **Enforcement:** Backend validates role from signed JWT (client cannot tamper)

### **Database Security**

#### **SSL/TLS Encryption**
- **Configuration:**
  ```
  ssl = on
  ssl_cert_file = 'server.crt'
  ssl_key_file = 'server.key'
  ```
- **Certificate Generation:**
  ```bash
  openssl genrsa -out server.key 2048
  openssl req -new -x509 -days 365 -key server.key -out server.crt
  ```
- **Client Connection:**
  ```javascript
  ssl: process.env.PGSSLMODE === 'require' 
    ? { rejectUnauthorized: false } 
    : false
  ```
- **Verification:** `SHOW ssl;` returns "on"

#### **User Privilege Separation**
```sql
-- App user has restricted privileges
GRANT SELECT, INSERT, UPDATE ON users TO app_user;
GRANT SELECT, INSERT, UPDATE ON accounts TO app_user;
GRANT SELECT, INSERT ON transactions TO app_user;  -- No UPDATE/DELETE
REVOKE DELETE ON ALL TABLES FROM app_user;

-- Admin user has full privileges
GRANT ALL PRIVILEGES ON ALL TABLES TO admin_user;
```

#### **Audit Logging**
```sql
CREATE TRIGGER audit_users_trigger 
  AFTER INSERT OR UPDATE OR DELETE ON users 
  FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
```

**Logged Information:**
- User who made the change (from session variable)
- Action type (INSERT/UPDATE/DELETE)
- Table name
- Record ID
- Old values (for UPDATE/DELETE)
- New values (for INSERT/UPDATE)
- Timestamp

#### **Failed Login Protection**
```sql
CREATE FUNCTION increment_failed_login(p_username VARCHAR) 
RETURNS VOID AS $$
BEGIN
  UPDATE users
  SET failed_login_attempts = failed_login_attempts + 1,
      locked_until = CASE 
        WHEN failed_login_attempts >= 4 
        THEN CURRENT_TIMESTAMP + INTERVAL '15 minutes'
        ELSE locked_until 
      END
  WHERE username = p_username;
END;
$$ LANGUAGE plpgsql;
```

**Protection Mechanism:**
1. After 5 failed login attempts, account is locked for 15 minutes
2. Lockout tracked in `locked_until` column
3. Login endpoint checks `locked_until` before password verification
4. Successful login resets `failed_login_attempts` to 0

### **Input Validation**

#### **Client-Side Validation**
```javascript
// Username: 3-50 alphanumeric + underscore
pattern="[a-zA-Z0-9_]{3,50}"

// Email: Standard email format
type="email"

// Password: Minimum 8 characters
minlength="8"
```

#### **Server-Side Validation**
```javascript
function validateUsername(username) {
  return username && 
         username.length >= 3 && 
         username.length <= 50 && 
         /^[a-zA-Z0-9_]+$/.test(username);
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email) && email.length <= 100;
}

function validatePassword(password) {
  return password && password.length >= 8;
}
```

### **SQL Injection Prevention**
```javascript
// ✅ SECURE: Parameterized query
await pool.query(
  'SELECT * FROM users WHERE username = $1',
  [username]  // Parameter is properly escaped
);

// ❌ INSECURE: String concatenation (NOT USED)
// await pool.query(
//   `SELECT * FROM users WHERE username = '${username}'`
// );
```

### **CORS Configuration**
```javascript
app.use(cors({
  origin: ["http://localhost:8080", "http://localhost:3000"],
  credentials: true
}));
```
**Protection:** Only specified origins can make requests to API

### **Resource Limits**
```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
```
**Protection:** Prevents resource exhaustion attacks

---

## 3. Verification Results

### **Test 1: Port Scan**
```powershell
.\run-security-tests.ps1
```

**Expected Ports:**
- ✅ Port 3000 (API Server) - OPEN
- ✅ Port 8080 (Frontend) - OPEN
- ✅ Port 5432 (Database) - CLOSED to host

**Results:**
```
Port 3000 open   ✓
Port 8080 open   ✓
Port 5432 closed ✓
Port 80   closed ✓
Port 443  closed ✓
Port 135  closed ✓
Port 445  closed ✓
```

**Interpretation:** Database is properly isolated and not exposed to external connections.

### **Test 2: SSL/TLS Verification**
```powershell
docker exec postgresql-client-server-main-db-1 `
  psql "postgresql://app_user:AppPass456!@localhost:5432/postgres?sslmode=require" `
  -tAc "SHOW ssl;"
```

**Result:** `on`

**Interpretation:** PostgreSQL SSL encryption is enabled and enforced.

### **Test 3: SQL Injection Test**
```powershell
Invoke-RestMethod `
  -Uri "http://localhost:3000/api/user/accounts?id=1 OR 1=1" `
  -Method GET
```

**Result:** `401 Unauthorized - Access token required`

**Interpretation:** 
1. Injection attempt was blocked by authentication middleware
2. Even if authenticated, parameterized queries would prevent injection

### **Test 4: Authentication Tests**

#### **Without Token:**
```bash
curl http://localhost:3000/api/user/accounts
```
**Result:** `401 Unauthorized - Access token required` ✓

#### **With Invalid Token:**
```bash
curl -H "Authorization: Bearer invalid_token" \
  http://localhost:3000/api/user/accounts
```
**Result:** `403 Forbidden - Invalid or expired token` ✓

#### **With Valid Token (Standard User):**
```bash
curl -H "Authorization: Bearer <valid_standard_token>" \
  http://localhost:3000/api/user/accounts
```
**Result:** Returns only user's own accounts ✓

### **Test 5: Authorization Tests**

#### **Standard User Accessing Admin Endpoint:**
```bash
curl -H "Authorization: Bearer <standard_user_token>" \
  http://localhost:3000/api/admin/users
```
**Result:** `403 Forbidden - Admin access required` ✓

#### **Admin User Accessing Admin Endpoint:**
```bash
curl -H "Authorization: Bearer <admin_token>" \
  http://localhost:3000/api/admin/users
```
**Result:** Returns all users (system-wide data) ✓

### **Test 6: Failed Login Protection**

#### **Test Procedure:**
1. Attempt login with wrong password 5 times
2. Check database for `locked_until` value
3. Attempt login with correct password
4. Verify lockout message

**Results:**
- After 5 failed attempts: `locked_until` set to NOW() + 15 minutes ✓
- Login with correct password: `403 Forbidden - Account locked` ✓
- After 15 minutes: Login succeeds and `failed_login_attempts` reset to 0 ✓

### **Test 7: Audit Logging**

#### **Test Procedure:**
1. Create a new user
2. Update user's email
3. Query audit_log table

**Results:**
```sql
SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 5;
```

| audit_id | action | table_name | record_id | new_values | created_at |
|----------|--------|------------|-----------|------------|------------|
| 147 | UPDATE | users | 21 | {"email":"new@test.com"} | 2025-01-15 10:32:45 |
| 146 | INSERT | users | 21 | {"username":"testuser",...} | 2025-01-15 10:30:12 |

**Interpretation:** All database changes are logged with full details ✓

### **Test 8: CSV/JSON Endpoint Security (Parts D & E)**

#### **JSON Endpoint Without Authentication:**
```bash
curl http://localhost:3000/api/user/sample-data
```
**Result:** `401 Unauthorized` ✓

#### **JSON Endpoint With Authentication:**
```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:3000/api/user/sample-data
```
**Result:**
```json
{
  "success": true,
  "data": [...],
  "message": "Secure JSON data retrieved",
  "accessed_by": "alice",
  "accessed_at": "2025-01-15T10:45:30.123Z"
}
```
✓ File contents served securely
✓ Access logged with username and timestamp

#### **CSV Endpoint Without Authentication:**
```bash
curl http://localhost:3000/api/user/csv-analytics
```
**Result:** `401 Unauthorized` ✓

#### **CSV Endpoint With Authentication:**
```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:3000/api/user/csv-analytics
```
**Result:**
```json
{
  "success": true,
  "analytics": {
    "totalTransactions": 40,
    "totalDeposits": "12450.67",
    "totalWithdrawals": "8234.12",
    "netFlow": "4216.55",
    ...
  },
  "message": "CSV analytics generated",
  "accessed_by": "alice",
  "accessed_at": "2025-01-15T10:47:15.456Z"
}
```
✓ CSV processed server-side (never sent raw to client)
✓ Analytics computed on backend
✓ Access logged with username and timestamp

---

