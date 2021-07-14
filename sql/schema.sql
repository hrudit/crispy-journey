PRAGMA foreign_keys = ON;

CREATE TABLE users(
  username VARCHAR(20) NOT NULL,
  fullname VARCHAR(40) NOT NULL,
  email VARCHAR(40) NOT NULL,
  password VARCHAR(256) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  phone_number VARCHAR(64) NULL,
  verified INTEGER DEFAULT 0,
  PRIMARY KEY(username)
);

CREATE TABLE trips(
    tripid INTEGER NOT NULL,
    source VARCHAR(64) NOT NULL,
    destination VARCHAR(64) NOT NULL,
    threshhold REAL NOT NULL,
    month VARCHAR(64) NOT NULL,
    owner VARCHAR(20) NOT NULL,
    is_sent INTEGER DEFAULT 0,
    date_sent VARCHAR(20),
    PRIMARY KEY(tripid),
    FOREIGN KEY (owner) REFERENCES users(username)
    ON DELETE CASCADE ON UPDATE CASCADE
);
