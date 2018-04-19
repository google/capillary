/*
To create initial SQLite database, run the following in command line:
  sqlite3 demo.db -init demo-schema.sql
*/

CREATE TABLE PublicKeys (
 user_id TEXT NOT NULL,
 algorithm INTEGER NOT NULL,
 is_auth INTEGER NOT NULL,
 key_bytes BLOB NOT NULL,
 PRIMARY KEY(user_id, algorithm, is_auth)
);

CREATE TABLE Users (
 user_id TEXT NOT NULL,
 token TEXT NOT NULL,
 PRIMARY KEY(user_id)
);
