-- Schema for Internal Vulnerability Report System
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS admin_secrets;

CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(100) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('user','reviewer','admin') DEFAULT 'user',
  last_export DATETIME DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  title VARCHAR(100) NOT NULL,
  description TEXT,
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS admin_secrets (
  id INT PRIMARY KEY,
  flag VARCHAR(100) NOT NULL
);

-- Seed flag 2 in DB
INSERT INTO admin_secrets (id, flag) VALUES (1, 'FLAG{st0r3d_pr0c3dur3_1nj3ct10n_m4st3r}');

-- Seed admin account
INSERT INTO users (username, password_hash, role) VALUES
  ('admin', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'admin');

DROP PROCEDURE IF EXISTS GetTopReporter;
