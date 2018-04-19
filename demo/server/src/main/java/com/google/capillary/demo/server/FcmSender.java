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

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * Provides an interface to send arbitrary data maps to devices via FCM notifications.
 */
final class FcmSender {

  private static final Logger logger = Logger.getLogger(FcmSender.class.getName());
  private static final String BASE_URL = "https://fcm.googleapis.com";
  private static final String FCM_SEND_ENDPOINT_PATTERN = "/v1/projects/%s/messages:send";
  private static final String MESSAGING_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
  private static final String[] SCOPES = {MESSAGING_SCOPE};

  private final String fcmSendEndpoint;
  private final GoogleCredential googleCredential;

  /**
   * Initializes a new {@link FcmSender} with the given FCM service account credentials.
   */
  FcmSender(String projectId, String serviceAccountCredentialsPath) throws IOException {
    fcmSendEndpoint = String.format(FCM_SEND_ENDPOINT_PATTERN, projectId);
    try (FileInputStream serviceAccountCredentials =
        new FileInputStream(serviceAccountCredentialsPath)) {
      googleCredential = GoogleCredential
          .fromStream(serviceAccountCredentials)
          .createScoped(Arrays.asList(SCOPES));
    }
  }

  /**
   * Sends notification message to FCM for delivery to registered devices.
   */
  void sendDataMessage(String token, Map<String, String> dataMap) throws IOException {
    JsonObject requestJson = buildRequest(token, dataMap);
    logger.info("FCM request JSON for data message:");
    prettyPrint(requestJson);
    sendMessage(requestJson);
  }

  private static JsonObject buildRequest(String token, Map<String, String> dataMap) {
    JsonObject dataJson = new JsonObject();
    for (Map.Entry<String, String> entry : dataMap.entrySet()) {
      dataJson.addProperty(entry.getKey(), entry.getValue());
    }

    JsonObject messageJson = new JsonObject();
    messageJson.addProperty("token", token);
    messageJson.add("data", dataJson);

    JsonObject requestJson = new JsonObject();
    requestJson.add("message", messageJson);

    return requestJson;
  }

  private static void prettyPrint(JsonObject jsonObject) {
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    logger.info(gson.toJson(jsonObject));
  }

  private void sendMessage(JsonObject requestJson) throws IOException {
    HttpURLConnection connection = getConnection();
    connection.setDoOutput(true);
    DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
    outputStream.writeBytes(requestJson.toString());
    outputStream.flush();
    outputStream.close();

    int responseCode = connection.getResponseCode();
    if (responseCode == 200) {
      String response = inputstreamToString(connection.getInputStream());
      logger.info("Message sent to Firebase for delivery, response:");
      logger.info(response);
    } else {
      logger.info("Unable to send message to Firebase:");
      String response = inputstreamToString(connection.getErrorStream());
      logger.info(response);
    }
  }

  private HttpURLConnection getConnection() throws IOException {
    URL url = new URL(BASE_URL + fcmSendEndpoint);
    HttpURLConnection httpUrlConnection = (HttpURLConnection) url.openConnection();
    httpUrlConnection.setRequestProperty("Authorization", "Bearer " + getAccessToken());
    httpUrlConnection.setRequestProperty("Content-Type", "application/json; UTF-8");
    return httpUrlConnection;
  }

  private static String inputstreamToString(InputStream inputStream) throws IOException {
    StringBuilder stringBuilder = new StringBuilder();
    Scanner scanner = new Scanner(inputStream);
    while (scanner.hasNext()) {
      stringBuilder.append(scanner.nextLine());
    }
    return stringBuilder.toString();
  }

  private String getAccessToken() throws IOException {
    googleCredential.refreshToken();
    return googleCredential.getAccessToken();
  }
}
