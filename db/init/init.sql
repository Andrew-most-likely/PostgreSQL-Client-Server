
-- ============================================
-- SECURE BANKING SYSTEM - FRESH BUILD DATABASE SETUP
-- ============================================

-- Drop existing objects
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS transactions CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP FUNCTION IF EXISTS audit_trigger_func() CASCADE;
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;
DROP FUNCTION IF EXISTS set_current_user(INT) CASCADE;
DROP FUNCTION IF EXISTS increment_failed_login(VARCHAR) CASCADE;
DROP FUNCTION IF EXISTS reset_failed_login(INT) CASCADE;

-- Drop users if they exist
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_user') THEN
        EXECUTE 'REASSIGN OWNED BY admin_user TO postgres';
        EXECUTE 'DROP OWNED BY admin_user CASCADE';
        EXECUTE 'DROP USER admin_user';
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
        EXECUTE 'REASSIGN OWNED BY app_user TO postgres';
        EXECUTE 'DROP OWNED BY app_user CASCADE';
        EXECUTE 'DROP USER app_user';
    END IF;
END $$;

-- ============================================
-- CREATE TABLES
-- ============================================

CREATE TABLE users (
  user_id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  role VARCHAR(20) DEFAULT 'standard' CHECK (role IN ('admin', 'standard')),
  is_active BOOLEAN DEFAULT TRUE,
  failed_login_attempts INT DEFAULT 0,
  locked_until TIMESTAMP NULL,
  last_login TIMESTAMP NULL,
  password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
  session_id VARCHAR(255) PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked BOOLEAN DEFAULT FALSE
);

CREATE TABLE accounts (
  account_id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  account_number VARCHAR(16) UNIQUE NOT NULL,
  balance DECIMAL(15,2) DEFAULT 0.00 CHECK (balance >= 0),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE transactions (
  transaction_id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id INT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
  transaction_type VARCHAR(20) NOT NULL CHECK (transaction_type IN ('deposit', 'withdrawal', 'transfer')),
  amount DECIMAL(15,2) NOT NULL CHECK (amount > 0),
  balance_after DECIMAL(15,2),
  transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  description VARCHAR(255),
  created_by INT REFERENCES users(user_id)
);

CREATE TABLE audit_log (
  audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id INT REFERENCES users(user_id),
  action VARCHAR(100) NOT NULL,
  table_name VARCHAR(50),
  record_id INT,
  old_values JSONB,
  new_values JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- CREATE INDEXES
-- ============================================

CREATE INDEX idx_accounts_user_id ON accounts(user_id);
CREATE INDEX idx_transactions_account_id ON transactions(account_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

-- ============================================
-- CREATE FUNCTIONS
-- ============================================

CREATE FUNCTION update_updated_at_column() RETURNS TRIGGER LANGUAGE plpgsql AS $func$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$func$;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_accounts_updated_at BEFORE UPDATE ON accounts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE FUNCTION audit_trigger_func() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $func$
DECLARE
  v_user_id INT;
  v_record_id INT;
BEGIN
  BEGIN
    v_user_id := current_setting('app.current_user_id', TRUE)::INT;
  EXCEPTION WHEN OTHERS THEN
    v_user_id := NULL;
  END;
  IF (TG_OP = 'DELETE') THEN
    IF TG_TABLE_NAME = 'users' THEN v_record_id := OLD.user_id;
    ELSIF TG_TABLE_NAME = 'accounts' THEN v_record_id := OLD.account_id;
    ELSIF TG_TABLE_NAME = 'transactions' THEN v_record_id := OLD.transaction_id;
    END IF;
    INSERT INTO audit_log (user_id, action, table_name, record_id, old_values) VALUES (v_user_id, TG_OP, TG_TABLE_NAME, v_record_id, row_to_json(OLD));
    RETURN OLD;
  ELSIF (TG_OP = 'UPDATE') THEN
    IF TG_TABLE_NAME = 'users' THEN v_record_id := NEW.user_id;
    ELSIF TG_TABLE_NAME = 'accounts' THEN v_record_id := NEW.account_id;
    ELSIF TG_TABLE_NAME = 'transactions' THEN v_record_id := NEW.transaction_id;
    END IF;
    INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values) VALUES (v_user_id, TG_OP, TG_TABLE_NAME, v_record_id, row_to_json(OLD), row_to_json(NEW));
    RETURN NEW;
  ELSIF (TG_OP = 'INSERT') THEN
    IF TG_TABLE_NAME = 'users' THEN v_record_id := NEW.user_id;
    ELSIF TG_TABLE_NAME = 'accounts' THEN v_record_id := NEW.account_id;
    ELSIF TG_TABLE_NAME = 'transactions' THEN v_record_id := NEW.transaction_id;
    END IF;
    INSERT INTO audit_log (user_id, action, table_name, record_id, new_values) VALUES (v_user_id, TG_OP, TG_TABLE_NAME, v_record_id, row_to_json(NEW));
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$func$;

CREATE TRIGGER audit_users_trigger AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
CREATE TRIGGER audit_accounts_trigger AFTER INSERT OR UPDATE OR DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
CREATE TRIGGER audit_transactions_trigger AFTER INSERT OR UPDATE OR DELETE ON transactions FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();

CREATE FUNCTION set_current_user(p_user_id INT) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $func$
BEGIN
  PERFORM set_config('app.current_user_id', p_user_id::TEXT, TRUE);
END;
$func$;

CREATE FUNCTION increment_failed_login(p_username VARCHAR) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $func$
BEGIN
  UPDATE users SET failed_login_attempts = failed_login_attempts + 1, locked_until = CASE WHEN failed_login_attempts >= 4 THEN CURRENT_TIMESTAMP + INTERVAL '15 minutes' ELSE locked_until END WHERE username = p_username;
END;
$func$;

CREATE FUNCTION reset_failed_login(p_user_id INT) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $func$
BEGIN
  UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE user_id = p_user_id;
END;
$func$;

-- ============================================
-- INSERT SAMPLE DATA
-- ============================================

INSERT INTO users (username, password_hash, full_name, email, role) VALUES
('admin','$2b$10$rZc6vgHKqFqO5xNFvQmJ4.VhF/JqVBXQ7fN5xZ4eKgL8Nx/CcBqHC','System Administrator','admin@secure.local','admin'),
('shobbs','$2b$10$XYZ1234567890abcdefghijklmnopqrstuvwxyz123456789ABC','Gerald Walker','fpowell@yahoo.com','standard'),
('glara','$2b$10$ABC1234567890abcdefghijklmnopqrstuvwxyz123456789DEF','Robert Parks MD','thompsonjason@pugh.com','standard'),
('barnold','$2b$10$DEF1234567890abcdefghijklmnopqrstuvwxyz123456789GHI','Nathan Griffin','lbailey@yahoo.com','standard'),
('riverasusan','$2b$10$GHI1234567890abcdefghijklmnopqrstuvwxyz123456789JKL','Laurie Burns','emily16@gmail.com','standard'),
('wpearson','$2b$10$JKL1234567890abcdefghijklmnopqrstuvwxyz123456789MNO','Ian Mcclure','kingmichael@hotmail.com','standard'),
('joshua28','$2b$10$MNO1234567890abcdefghijklmnopqrstuvwxyz123456789PQR','Martin Williams','rlawson@solomon-miller.com','standard'),
('kennethsmith','$2b$10$PQR1234567890abcdefghijklmnopqrstuvwxyz123456789STU','Jeffrey Conrad','cherryann@gmail.com','standard'),
('brianna87','$2b$10$STU1234567890abcdefghijklmnopqrstuvwxyz123456789VWX','Katie Bryant','sbradley@gmail.com','standard'),
('guerrerodaniel','$2b$10$VWX1234567890abcdefghijklmnopqrstuvwxyz123456789YZA','Joshua Montgomery','faulknereric@hotmail.com','standard'),
('steven38','$2b$10$YZA1234567890abcdefghijklmnopqrstuvwxyz123456789BCD','Jennifer Wells','gwilson@nelson-harris.com','standard'),
('ryanfowler','$2b$10$BCD1234567890abcdefghijklmnopqrstuvwxyz123456789EFG','James Castro','timothywall@yahoo.com','standard'),
('steinkelly','$2b$10$EFG1234567890abcdefghijklmnopqrstuvwxyz123456789HIJ','Amy Contreras','owenswayne@martinez-juarez.org','standard'),
('xcole','$2b$10$HIJ1234567890abcdefghijklmnopqrstuvwxyz123456789KLM','Michael Mercado','jennifer17@oneill-larsen.com','standard'),
('christinamayo','$2b$10$KLM1234567890abcdefghijklmnopqrstuvwxyz123456789NOP','Jasmine Bowen','james13@gmail.com','standard'),
('megan92','$2b$10$NOP1234567890abcdefghijklmnopqrstuvwxyz123456789QRS','Joshua Mathews','moranangela@yahoo.com','standard'),
('robinsonpatrick','$2b$10$QRS1234567890abcdefghijklmnopqrstuvwxyz123456789TUV','Donald Mitchell','pbeck@hotmail.com','standard'),
('hessmelissa','$2b$10$TUV1234567890abcdefghijklmnopqrstuvwxyz123456789WXY','Keith Anderson','msmith@gmail.com','standard'),
('ksmith','$2b$10$WXY1234567890abcdefghijklmnopqrstuvwxyz123456789ZAB','Andrew Herrera','nathanrobertson@yahoo.com','standard'),
('danielsmith','$2b$10$ZAB1234567890abcdefghijklmnopqrstuvwxyz123456789CDE','Lisa Murillo','iedwards@hotmail.com','standard'),
('ilewis','$2b$10$CDE1234567890abcdefghijklmnopqrstuvwxyz123456789FGH','Donna Gonzalez','mariawilliams@carter.com','standard');

INSERT INTO accounts (user_id, account_number, balance, status) VALUES
(2,'ACC2002',2185.98,'active'),(3,'ACC2003',177.76,'active'),(4,'ACC2004',1205.18,'active'),(5,'ACC2005',1509.59,'active'),
(6,'ACC2006',1038.77,'active'),(7,'ACC2007',2053.55,'active'),(8,'ACC2008',4802.70,'active'),(9,'ACC2009',691.91,'active'),
(10,'ACC2010',4720.50,'active'),(11,'ACC2011',1666.96,'active'),(12,'ACC2012',1446.22,'suspended'),(13,'ACC2013',2939.77,'active'),
(14,'ACC2014',4195.24,'suspended'),(15,'ACC2015',558.51,'active'),(16,'ACC2016',4236.61,'active'),(17,'ACC2017',4708.71,'active'),
(18,'ACC2018',2333.57,'active'),(19,'ACC2019',1822.35,'active'),(20,'ACC2020',3930.69,'active'),(21,'ACC2021',649.39,'active');

INSERT INTO transactions (account_id, transaction_type, amount, description, balance_after) VALUES
(1,'deposit',802.87,'Initial deposit',802.87),(2,'deposit',534.01,'Paycheck deposit',534.01),
(3,'transfer',99.79,'Transfer to savings',277.55),(4,'deposit',266.68,'Refund credited',1471.86),
(5,'withdrawal',440.27,'ATM withdrawal',1069.32),(6,'deposit',365.04,'Direct deposit',1403.81),
(7,'deposit',331.41,'Check deposit',2384.96),(8,'transfer',132.91,'Bill payment',4669.79),
(9,'deposit',916.26,'Bonus payment',1608.17),(10,'withdrawal',101.19,'Cash withdrawal',4619.31);

-- ============================================
-- CREATE DATABASE USERS
-- ============================================

CREATE USER admin_user WITH PASSWORD 'AdminPass123!';
GRANT ALL PRIVILEGES ON DATABASE postgres TO admin_user;
ALTER USER admin_user CREATEDB;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO admin_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO admin_user;

CREATE USER app_user WITH PASSWORD 'AppPass456!';
GRANT CONNECT ON DATABASE postgres TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE ON users TO app_user;
GRANT SELECT, INSERT, UPDATE ON accounts TO app_user;
GRANT SELECT, INSERT ON transactions TO app_user;
GRANT SELECT, INSERT, UPDATE ON sessions TO app_user;
GRANT SELECT, INSERT ON audit_log TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
GRANT EXECUTE ON FUNCTION set_current_user TO app_user;
GRANT EXECUTE ON FUNCTION increment_failed_login TO app_user;
GRANT EXECUTE ON FUNCTION reset_failed_login TO app_user;
REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM app_user;

-- ============================================
-- ENABLE ROW LEVEL SECURITY
-- ============================================

ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE accounts DISABLE ROW LEVEL SECURITY;
ALTER TABLE transactions DISABLE ROW LEVEL SECURITY;
ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY;

CREATE POLICY users_select_policy ON users FOR SELECT TO app_user USING (user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) OR EXISTS (SELECT 1 FROM users u WHERE u.user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND u.role = 'admin'));
CREATE POLICY users_update_policy ON users FOR UPDATE TO app_user USING (user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1)) WITH CHECK (user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND role = (SELECT role FROM users WHERE user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1)));
CREATE POLICY users_insert_policy ON users FOR INSERT TO app_user WITH CHECK (role = 'standard');

CREATE POLICY accounts_select_policy ON accounts FOR SELECT TO app_user USING (user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) OR EXISTS (SELECT 1 FROM users u WHERE u.user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND u.role = 'admin'));
CREATE POLICY accounts_modify_policy ON accounts FOR ALL TO app_user USING (EXISTS (SELECT 1 FROM users u WHERE u.user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND u.role = 'admin')) WITH CHECK (EXISTS (SELECT 1 FROM users u WHERE u.user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND u.role = 'admin'));

CREATE POLICY transactions_select_policy ON transactions FOR SELECT TO app_user USING (account_id IN (SELECT account_id FROM accounts WHERE user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1)) OR EXISTS (SELECT 1 FROM users u WHERE u.user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND u.role = 'admin'));
CREATE POLICY transactions_insert_policy ON transactions FOR INSERT TO app_user WITH CHECK (account_id IN (SELECT account_id FROM accounts WHERE user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1)) OR EXISTS (SELECT 1 FROM users u WHERE u.user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND u.role = 'admin'));

CREATE POLICY sessions_policy ON sessions FOR ALL TO app_user USING (user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1)) WITH CHECK (user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1));

CREATE POLICY audit_log_select_policy ON audit_log FOR SELECT TO app_user USING (user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) OR EXISTS (SELECT 1 FROM users u WHERE u.user_id = COALESCE(current_setting('app.current_user_id', TRUE)::INT, -1) AND u.role = 'admin'));
CREATE POLICY audit_log_insert_policy ON audit_log FOR INSERT TO app_user WITH CHECK (TRUE);

-- ============================================
-- VERIFICATION
-- ============================================



SELECT 'users' as table_name, COUNT(*) as row_count FROM users
UNION ALL SELECT 'accounts', COUNT(*) FROM accounts
UNION ALL SELECT 'transactions', COUNT(*) FROM transactions
UNION ALL SELECT 'sessions', COUNT(*) FROM sessions
UNION ALL SELECT 'audit_log', COUNT(*) FROM audit_log
ORDER BY table_name;



