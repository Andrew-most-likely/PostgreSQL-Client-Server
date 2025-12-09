-- ============================================
-- SECURE BANKING SYSTEM - COMPLETE DATABASE SETUP
-- ============================================

-- Enable SSL
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/ssl/server.crt';
ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/ssl/server.key';
SELECT pg_reload_conf();

-- ============================================
-- CREATE TABLES
-- ============================================

CREATE TABLE users (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  full_name VARCHAR(100),
  email VARCHAR(100),
  role VARCHAR(20) DEFAULT 'standard',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
  account_id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id INT NOT NULL,
  account_number VARCHAR(16) UNIQUE NOT NULL,
  balance DECIMAL(10,2) DEFAULT 0.00,
  status VARCHAR(20) DEFAULT 'active',
  FOREIGN KEY (id) REFERENCES users(id)
);

CREATE TABLE transactions (
  transaction_id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id INT NOT NULL,
  transaction_type VARCHAR(20) NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  description VARCHAR(255),
  FOREIGN KEY (account_id) REFERENCES accounts(account_id)
);

-- ============================================
-- INSERT SAMPLE DATA
-- ============================================

INSERT INTO users (username, password, full_name, email, role) VALUES
('admin','f7b61c56f7f8e5bbf86c7dc421d3a3cfb7a59c994a854b62561254b85b52d4b6','System Administrator','admin@secure.local','admin'),
('shobbs','2902ad0fe43409fce9628f183fcd9c298f37e109fc724c13dd978117e1efc69c','Gerald Walker','fpowell@yahoo.com','standard'),
('glara','27ce6cb3932b841e34bbbd1004d25c69f202e1f9043f8a8e2082b28915977275','Robert Parks MD','thompsonjason@pugh.com','standard'),
('barnold','0ed97f6872c65ef5407c9836adb64d9caed3c6c7df6ea91da41849b7fe9ef256','Nathan Griffin','lbailey@yahoo.com','standard'),
('riverasusan','82b28fca939e70ce9d59cf327a9c3da4a337ed99a5ae95bf8854d238b4e4171d','Laurie Burns','emily16@gmail.com','standard'),
('wpearson','5c6f4ccc470a19175c0833a8a995b03df596f5843efb4f1055d1ca2134761b50','Ian Mcclure','kingmichael@hotmail.com','standard'),
('joshua28','4bb586d9a0295fab2101c021d61c0719c42777972f6b5499185e6ddf166a1610','Martin Williams','rlawson@solomon-miller.com','standard'),
('kennethsmith','ac235c240ae74320dc3b87de8d0b76bfdcdffac62622391c92a33dfa7dbc0f68','Jeffrey Conrad','cherryann@gmail.com','standard'),
('brianna87','6df22be680151a62b6f357e0763d5919811eb6f5590ddc2cf2c65cffb396edf0','Katie Bryant','sbradley@gmail.com','standard'),
('guerrerodaniel','fe6cb2849a8831d4caa945ebb605961853a74f376ead0ade0d98ee55ace4f58a','Joshua Montgomery','faulknereric@hotmail.com','standard'),
('steven38','bfae625125407fd1ac638a59804bd7a1fbae1c6076fbeae1051bcc245c617402','Jennifer Wells','gwilson@nelson-harris.com','standard'),
('ryanfowler','1f1e9da5cc870295d13e24d41ae74bab6ef47a882c9b126534bf807a3ee3bd03','James Castro','timothywall@yahoo.com','standard'),
('steinkelly','022eb72a4de83e4618e950c7da62283b2551ee37277ceb0d6a95afd29d5e864e','Amy Contreras','owenswayne@martinez-juarez.org','standard'),
('xcole','7a91a50f839cae5211db8c4a2a02b3f82913209b7bce5df046803db5f790ae16','Michael Mercado','jennifer17@oneill-larsen.com','standard'),
('christinamayo','1740622734f1230e061e30b5065b3e00484fc0806f2d9e351eaac5c37d5637b8','Jasmine Bowen','james13@gmail.com','standard'),
('megan92','b310c73ea84f7594419062bc26649e2a17f7bb28397f3db57e0b1682aca577d7','Joshua Mathews','moranangela@yahoo.com','standard'),
('robinsonpatrick','25a4c1207332fa1ab1405fc1e86c152f9ca3632e3818d0c2e7ed09cc437d95ea','Donald Mitchell','pbeck@hotmail.com','standard'),
('hessmelissa','7d719f0c64f8d20c08d4cf4d92092d8b42a16cb3fb8941f9eb68d543b70e4a65','Keith Anderson','msmith@gmail.com','standard'),
('ksmith','6a65efb26267358d524855b657cf4730da5f6e60b7387929868353b4419780b4','Andrew Herrera','nathanrobertson@yahoo.com','standard'),
('danielsmith','e373a9ee6f45ddc10383cc56f3114d8b5c55c5c9b998f3760e0bd8cd47e80008','Lisa Murillo','iedwards@hotmail.com','standard'),
('ilewis','57e4b455173919ca15c1ab1432b7e49641df72adb0ad8300cf5f2dcc3a242963','Donna Gonzalez','mariawilliams@carter.com','standard');

INSERT INTO accounts (id, account_number, balance, status) VALUES
(2,'ACC2002',2185.98,'active'),
(3,'ACC2003',177.76,'active'),
(4,'ACC2004',1205.18,'active'),
(5,'ACC2005',1509.59,'active'),
(6,'ACC2006',1038.77,'active'),
(7,'ACC2007',2053.55,'active'),
(8,'ACC2008',4802.7,'active'),
(9,'ACC2009',691.91,'active'),
(10,'ACC2010',4720.5,'active'),
(11,'ACC2011',1666.96,'active'),
(12,'ACC2012',1446.22,'suspended'),
(13,'ACC2013',2939.77,'active'),
(14,'ACC2014',4195.24,'suspended'),
(15,'ACC2015',558.51,'active'),
(16,'ACC2016',4236.61,'active'),
(17,'ACC2017',4708.71,'active'),
(18,'ACC2018',2333.57,'active'),
(19,'ACC2019',1822.35,'active'),
(20,'ACC2020',3930.69,'active'),
(21,'ACC2021',649.39,'active');

INSERT INTO transactions (account_id, transaction_type, amount, description) VALUES
(19,'withdrawal',802.87,'Can beautiful on street throw organization.'),
(8,'deposit',534.01,'Financial shoulder crime.'),
(6,'transfer',99.79,'Available yes where between.'),
(16,'transfer',266.68,'Improve institution lot hair arrive.'),
(17,'transfer',440.27,'Early not protect situation.'),
(6,'transfer',365.04,'North look too necessary model.'),
(2,'deposit',331.41,'Management part message spring leg social.'),
(5,'transfer',132.91,'Law rest cell evidence production question.'),
(16,'deposit',916.26,'Smile reveal whole represent contain ten stand order.'),
(8,'deposit',101.19,'Different on picture hand rule what girl.'),
(2,'deposit',908.15,'Recent while our especially good federal.'),
(2,'deposit',614.68,'Like record analysis year these stay goal use.'),
(11,'deposit',359.13,'Learn we point right others commercial new.'),
(10,'withdrawal',227.82,'Data whether local stop executive different.'),
(18,'withdrawal',926.23,'View go sport heavy worker his article add.'),
(19,'withdrawal',124.85,'Student full us six kitchen kid leader.'),
(3,'transfer',615.76,'Religious movie account before within newspaper.'),
(7,'deposit',512.9,'Voice your above wrong fight.'),
(18,'deposit',566.35,'Turn field alone red issue.'),
(17,'deposit',646.34,'Indeed smile agreement heart similar include.'),
(10,'transfer',666.67,'Ago road lawyer room operation trial.'),
(6,'withdrawal',578.49,'Line political return just seek material lot.'),
(20,'withdrawal',959.82,'Leader from science drive well audience draw.'),
(19,'deposit',205.4,'Production anyone race.'),
(5,'transfer',467.12,'Thus material dark training sea.'),
(2,'withdrawal',433.27,'How understand vote clear indeed total produce particular.'),
(7,'deposit',331.08,'Billion always nice four.'),
(1,'deposit',112.88,'Western beautiful coach relate accept visit natural.'),
(12,'deposit',497.48,'Travel table again test computer.'),
(16,'deposit',86.09,'Win sport should baby nearly improve.'),
(19,'transfer',221.46,'Allow which activity like several.'),
(13,'withdrawal',745.84,'Question miss take.'),
(18,'withdrawal',906.8,'Possible husband pay company.'),
(16,'deposit',348.18,'Success name radio grow like already discussion.'),
(6,'transfer',838.41,'Amount forward place drive agree cup action.'),
(11,'deposit',570.98,'Fast toward goal next.'),
(12,'deposit',384.97,'Produce order maintain million put material politics section.'),
(7,'transfer',256.44,'Name focus purpose claim picture movement.'),
(13,'deposit',147.54,'Consider thank market each about much.'),
(2,'deposit',932.37,'Reach financial turn born later try.');

-- ============================================
-- CREATE RESTRICTED DATABASE USERS
-- ============================================

-- Admin user with full privileges
CREATE USER admin_user WITH PASSWORD 'AdminPass123!';
GRANT ALL PRIVILEGES ON DATABASE secure_system TO admin_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO admin_user;

-- App user with restricted privileges (read-only plus limited write)
CREATE USER app_user WITH PASSWORD 'AppPass456!';
GRANT CONNECT ON DATABASE secure_system TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_user;
GRANT INSERT, UPDATE ON users TO app_user;
GRANT INSERT, UPDATE ON accounts TO app_user;
GRANT INSERT ON transactions TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM app_user;

-- Display created users
\du

-- ============================================
-- VERIFICATION
-- ============================================

-- Show table counts
SELECT 'users' as table_name, COUNT(*) as row_count FROM users
UNION ALL
SELECT 'accounts', COUNT(*) FROM accounts
UNION ALL
SELECT 'transactions', COUNT(*) FROM transactions;

-- Show SSL status
SHOW ssl;