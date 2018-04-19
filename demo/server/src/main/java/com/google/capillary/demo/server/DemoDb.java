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

package com.google.capillary.demo.server;

import com.google.capillary.NoSuchKeyException;
import com.google.capillary.demo.common.AddOrUpdatePublicKeyRequest;
import com.google.capillary.demo.common.AddOrUpdateUserRequest;
import com.google.capillary.demo.common.KeyAlgorithm;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Provides an interface to store and retrieve app data in a SQLite database.
 */
final class DemoDb {

  private static final String CMD_PUT_PUBLIC_KEY =
      "INSERT OR REPLACE INTO PublicKeys(user_id, algorithm, is_auth, key_bytes) "
          + "VALUES(?, ?, ?, ?)";
  private static final String CMD_GET_KEY_BYTES =
      "SELECT key_bytes FROM PublicKeys "
          + "WHERE user_id = ? AND algorithm = ? AND is_auth = ?";
  private static final String CMD_PUT_USER =
      "INSERT OR REPLACE INTO Users(user_id, token) "
          + "VALUES(?, ?)";
  private static final String CMD_GET_TOKEN =
      "SELECT token FROM Users "
          + "WHERE user_id = ?";

  private final String databasePath;

  /**
   * Initializes a new {@link DemoDb}.
   */
  DemoDb(String databasePath) {
    this.databasePath = databasePath;
  }

  /**
   * Inserts or updates the given recipient Capillary public key in the SQLite database.
   */
  void addOrUpdatePublicKey(AddOrUpdatePublicKeyRequest request) throws SQLException {
    try (
        Connection connection = DriverManager.getConnection(databasePath);
        PreparedStatement statement = connection.prepareStatement(CMD_PUT_PUBLIC_KEY)
    ) {
      statement.setString(1, request.getUserId());
      statement.setInt(2, request.getAlgorithmValue());
      statement.setInt(3, request.getIsAuth() ? 1 : 0);
      statement.setBytes(4, request.getKeyBytes().toByteArray());
      statement.executeUpdate();
    }
  }

  /**
   * Returns the Capillary public key of the given user and key parameters.
   */
  byte[] getKeyBytes(String userId, KeyAlgorithm algorithm, boolean isAuth)
      throws SQLException, NoSuchKeyException {
    try (
        Connection connection = DriverManager.getConnection(databasePath);
        PreparedStatement statement = connection.prepareStatement(CMD_GET_KEY_BYTES)
    ) {
      statement.setString(1, userId);
      statement.setInt(2, algorithm.getNumber());
      statement.setInt(3, isAuth ? 1 : 0);
      try (ResultSet resultSet = statement.executeQuery()) {
        if (!resultSet.next()) {
          throw new NoSuchKeyException(
              String.format(
                  "no public key found for user_id = %s, algorithm = %s, and is_auth = %s",
                  userId, algorithm.name(), isAuth));
        }
        return resultSet.getBytes(1);
      }
    }
  }

  /**
   * Inserts or updates the given user info in the SQLite database.
   */
  void addOrUpdateUser(AddOrUpdateUserRequest request) throws SQLException {
    try (
        Connection connection = DriverManager.getConnection(databasePath);
        PreparedStatement statement = connection.prepareStatement(CMD_PUT_USER)
    ) {
      statement.setString(1, request.getUserId());
      statement.setString(2, request.getToken());
      statement.executeUpdate();
    }
  }

  /**
   * Returns the FCM token of the given user ID.
   */
  String getToken(String userId) throws SQLException, NoSuchUserException {
    try (
        Connection connection = DriverManager.getConnection(databasePath);
        PreparedStatement statement = connection.prepareStatement(CMD_GET_TOKEN)
    ) {
      statement.setString(1, userId);
      try (ResultSet resultSet = statement.executeQuery()) {
        if (!resultSet.next()) {
          throw new NoSuchUserException(String.format("no user found for user_id = %s", userId));
        }
        return resultSet.getString(1);
      }
    }
  }
}
