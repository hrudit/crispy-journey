PRAGMA foreign_keys = ON;

CREATE TABLE users(
  username VARCHAR(20) NOT NULL,
  fullname VARCHAR(40) NOT NULL,
  email VARCHAR(40) NOT NULL,
  filename VARCHAR(64),
  password VARCHAR(256) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(username)
);
 
CREATE TABLE trips(
    tripid INTEGER NOT NULL,
    source VARCHAR(64) NOT NULL,
    destination VARCHAR(64) NOT NULL,
    threshhold REAL NOT NULL,
    month VARCHAR(64) NOT NULL,
    owner VARCHAR(20) NOT NULL,
    PRIMARY KEY(tripid),
    FOREIGN KEY (owner) REFERENCES users(username)
    ON DELETE CASCADE ON UPDATE CASCADE
);
