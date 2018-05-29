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

package com.google.capillary.demo.android;

import android.util.Log;
import com.google.capillary.android.DecrypterManager;
import com.google.capillary.demo.common.Constants;
import com.google.capillary.demo.common.KeyAlgorithm;
import com.google.crypto.tink.subtle.Base64;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;
import io.grpc.ManagedChannel;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * Extends {@link FirebaseMessagingService} to retrieve Capillary ciphertexts that are received
 * as FCM data messages, and pass these ciphertexts to {@link DecrypterManager} to decrypt.
 */
public final class DemoFmService extends FirebaseMessagingService {

  private static final String TAG = DemoFmService.class.getSimpleName();

  @Override
  public void onMessageReceived(RemoteMessage remoteMessage) {
    // Check if message contains a data payload.
    if (remoteMessage.getData().size() > 0) {
      Log.d(TAG, "data message received with payload: " + remoteMessage.getData());
      handleDataMessage(remoteMessage.getData());
    }

    // Check if message contains a notification payload.
    if (remoteMessage.getNotification() != null) {
      Log.d(TAG, "notification message received with body: "
          + remoteMessage.getNotification().getBody());
    }
  }

  private void handleDataMessage(Map<String, String> dataMap) {
    try {
      Utils.initialize(this);

      // Get the encryption algorithm and the ciphertext bytes.
      KeyAlgorithm keyAlgorithm =
          KeyAlgorithm.valueOf(dataMap.get(Constants.CAPILLARY_KEY_ALGORITHM_KEY));
      byte[] ciphertext = Base64.decode(dataMap.get(Constants.CAPILLARY_CIPHERTEXT_KEY));

      // Create the gRPC channel.
      ManagedChannel channel = Utils.createGrpcChannel(this);

      // Create the DemoCapillaryHandler.
      DemoCapillaryHandler handler = new DemoCapillaryHandler(this, channel);

      // Handle ciphertext.
      Utils.getKeyManager(this, keyAlgorithm)
          .getDecrypterManager().decrypt(ciphertext, handler, keyAlgorithm);

      // Close the gRPC channel.
      channel.shutdown();
    } catch (GeneralSecurityException | IOException e) {
      e.printStackTrace();
    }
  }
}
