DROP DATABASE IF EXISTS `unrequitedhumor`;

DROP USER IF EXISTS 'unrequitedhumor'@'localhost';
CREATE USER 'unrequitedhumor'@'localhost' IDENTIFIED BY 'password';

CREATE DATABASE `unrequitedhumor` CHARACTER SET UTF8mb4 COLLATE utf8mb4_bin;
GRANT ALL PRIVILEGES ON `unrequitedhumor`.* TO 'unrequitedhumor'@'localhost';

FLUSH PRIVILEGES;
USE `unrequitedhumor`;

CREATE TABLE `users` (
  id INT NOT NULL AUTO_INCREMENT,
  email VARCHAR(320) NOT NULL,
  emailVerified BOOLEAN DEFAULT FALSE,
  firstName VARCHAR(32),
  lastName VARCHAR(32),
  googleUserId VARCHAR(32),
  passwordHash VARCHAR(60),
  PRIMARY KEY (id)
);