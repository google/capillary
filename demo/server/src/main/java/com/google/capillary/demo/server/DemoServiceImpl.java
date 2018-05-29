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

import com.google.capillary.EncrypterManager;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.demo.common.AddOrUpdatePublicKeyRequest;
import com.google.capillary.demo.common.AddOrUpdateUserRequest;
import com.google.capillary.demo.common.Constants;
import com.google.capillary.demo.common.DemoServiceGrpc;
import com.google.capillary.demo.common.KeyAlgorithm;
import com.google.capillary.demo.common.SendMessageRequest;
import com.google.crypto.tink.subtle.Base64;
import com.google.protobuf.Empty;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * The implementation of DemoService service.
 *
 * <p>See capillary_demo_common.proto for details of the methods.
 */
final class DemoServiceImpl extends DemoServiceGrpc.DemoServiceImplBase {

  private static final Logger logger = Logger.getLogger(DemoServiceImpl.class.getName());

  private final DemoDb db;
  private final EncrypterManager rsaEcdsaEncrypterManager;
  private final EncrypterManager webPushEncrypterManager;
  private final FcmSender fcmSender;
  private final ScheduledExecutorService executorService =
      Executors.newSingleThreadScheduledExecutor();

  /**
   * Initialize gRPC service implementation.
   */
  DemoServiceImpl(
      DemoDb db,
      EncrypterManager rsaEcdsaEncrypterManager,
      EncrypterManager webPushEncrypterManager,
      FcmSender fcmSender) {
    this.db = db;
    this.rsaEcdsaEncrypterManager = rsaEcdsaEncrypterManager;
    this.webPushEncrypterManager = webPushEncrypterManager;
    this.fcmSender = fcmSender;
  }

  @Override
  public void addOrUpdateUser(AddOrUpdateUserRequest req, StreamObserver<Empty> responseObserver) {
    logger.info("addOrUpdateUser called with:");
    logger.info(req.toString());

    try {
      db.addOrUpdateUser(req);
    } catch (SQLException e) {
      e.printStackTrace();
      responseObserver.onError(
          Status.INTERNAL.withDescription("unable to add user").asException());
      return;
    }

    responseObserver.onNext(Empty.getDefaultInstance());
    responseObserver.onCompleted();
  }

  @Override
  public void addOrUpdatePublicKey(
      AddOrUpdatePublicKeyRequest req, StreamObserver<Empty> responseObserver) {
    logger.info("addOrUpdatePublicKey called with:");
    logger.info(req.toString());

    try {
      db.addOrUpdatePublicKey(req);
    } catch (SQLException e) {
      e.printStackTrace();
      responseObserver.onError(
          Status.INTERNAL.withDescription("unable to add public key").asException());
      return;
    }

    responseObserver.onNext(Empty.getDefaultInstance());
    responseObserver.onCompleted();
  }

  @Override
  public void sendMessage(SendMessageRequest req, StreamObserver<Empty> responseObserver) {
    logger.info("sendMessage called with:");
    logger.info(req.toString());

    try {
      // Get public key.
      byte[] publicKey = db.getKeyBytes(req.getUserId(), req.getKeyAlgorithm(), req.getIsAuthKey());

      // Generate ciphertext.
      EncrypterManager encrypterManager = getEncrypterManager(req.getKeyAlgorithm());
      encrypterManager.loadPublicKey(publicKey);
      byte[] ciphertext = encrypterManager.encrypt(req.getData().toByteArray());
      encrypterManager.clearPublicKey();
      String ciphertextString = Base64.encode(ciphertext);

      // Get FCM token.
      String token = db.getToken(req.getUserId());

      // Create the data map to be sent as a JSON object.
      Map<String, String> dataMap = new HashMap<>();
      dataMap.put(Constants.CAPILLARY_CIPHERTEXT_KEY, ciphertextString);
      dataMap.put(Constants.CAPILLARY_KEY_ALGORITHM_KEY, req.getKeyAlgorithm().name());

      // Send the data map after the requested delay.
      executorService.schedule(() -> {
        try {
          fcmSender.sendDataMessage(token, dataMap);
        } catch (IOException e) {
          e.printStackTrace();
        }
      }, req.getDelaySeconds(), TimeUnit.SECONDS);
    } catch (NoSuchUserException | NoSuchKeyException e) {
      e.printStackTrace();
      responseObserver.onError(Status.NOT_FOUND.withDescription(e.getMessage()).asException());
      return;
    } catch (GeneralSecurityException | SQLException e) {
      e.printStackTrace();
      responseObserver.onError(
          Status.INTERNAL.withDescription("unable to send message").asException());
      return;
    }

    responseObserver.onNext(Empty.getDefaultInstance());
    responseObserver.onCompleted();
  }

  private EncrypterManager getEncrypterManager(KeyAlgorithm keyAlgorithm) {
    switch (keyAlgorithm) {
      case RSA_ECDSA:
        return rsaEcdsaEncrypterManager;
      case WEB_PUSH:
        return webPushEncrypterManager;
      default:
        throw new IllegalArgumentException("unsupported key algorithm");
    }
  }
}
