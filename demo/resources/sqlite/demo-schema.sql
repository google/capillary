/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
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
