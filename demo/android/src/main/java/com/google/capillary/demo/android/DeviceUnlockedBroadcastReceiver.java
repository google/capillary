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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.google.capillary.demo.common.KeyAlgorithm;
import io.grpc.ManagedChannel;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Upon device unlock event, attempts to decrypt any Capillary ciphertexts that were previously
 * saved due to authenticated Capillary decryption keys not being available.
 */
public final class DeviceUnlockedBroadcastReceiver extends BroadcastReceiver {

  @Override
  public void onReceive(Context context, Intent intent) {
    // Check if this is the right intent action.
    if (!Intent.ACTION_USER_PRESENT.equals(intent.getAction())) {
      return;
    }

    try {
      Utils.initialize(context);

      // Create the gRPC channel.
      ManagedChannel channel = Utils.createGrpcChannel(context);

      // Create the DemoCapillaryHandler.
      DemoCapillaryHandler handler = new DemoCapillaryHandler(context, channel);

      // Process any saved RsaEcdsa ciphertexts.
      Utils.getKeyManager(context, KeyAlgorithm.RSA_ECDSA)
          .getDecrypterManager().decryptSaved(handler, KeyAlgorithm.RSA_ECDSA);

      // Process any saved WebPush ciphertexts.
      Utils.getKeyManager(context, KeyAlgorithm.WEB_PUSH)
          .getDecrypterManager().decryptSaved(handler, KeyAlgorithm.WEB_PUSH);

      // Close the gRPC channel.
      channel.shutdown();
    } catch (GeneralSecurityException | IOException e) {
      e.printStackTrace();
    }
  }
}
