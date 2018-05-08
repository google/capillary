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

import android.content.Context;
import android.util.Log;
import com.google.capillary.android.CapillaryHandler;
import com.google.capillary.android.CapillaryHandlerErrorCode;
import com.google.capillary.demo.common.AddOrUpdatePublicKeyRequest;
import com.google.capillary.demo.common.DemoServiceGrpc;
import com.google.capillary.demo.common.DemoServiceGrpc.DemoServiceBlockingStub;
import com.google.capillary.demo.common.KeyAlgorithm;
import com.google.capillary.demo.common.SecureNotification;
import com.google.capillary.demo.common.SendMessageRequest;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.ManagedChannel;

/**
 * Implements the {@link CapillaryHandler} interface to register generated Capillary public keys
 * with the server and to show decrypted messages as notifications. The communication with the
 * application is done via gRPC.
 */
final class DemoCapillaryHandler implements CapillaryHandler {

  private static final String TAG = DemoCapillaryHandler.class.getSimpleName();

  private final Context context;
  private final DemoServiceBlockingStub blockingStub;

  /**
   * Creates a new handler instance.
   */
  DemoCapillaryHandler(Context context, ManagedChannel channel) {
    this.context = context;
    this.blockingStub = DemoServiceGrpc.newBlockingStub(channel);
  }

  /**
   * Shows the decrypted message as an Android notification.
   */
  @Override
  public void handleData(boolean isAuthKey, byte[] data, Object extra) {
    try {
      SecureNotification secureNotification = SecureNotification.parseFrom(data);
      Utils.showNotification(context, secureNotification);
    } catch (InvalidProtocolBufferException e) {
      e.printStackTrace();
    }
  }

  /**
   * Sends the generated Capillary ciphertext to the server.
   */
  @Override
  public void handlePublicKey(boolean isAuthKey, byte[] publicKey, Object extra) {
    AddOrUpdatePublicKeyRequest request = AddOrUpdatePublicKeyRequest.newBuilder()
        .setUserId(Utils.getUserId(context))
        .setAlgorithm((KeyAlgorithm) extra)
        .setIsAuth(isAuthKey)
        .setKeyBytes(ByteString.copyFrom(publicKey)).build();
    blockingStub.addOrUpdatePublicKey(request);
  }

  /**
   * This Capillary public key was generated due to a failure in decrypting a Capillary ciphertext.
   * Therefore, this method first registers the new Capillary public key with the application
   * server, and then requests the Capillary ciphertext to be resend.
   */
  @Override
  public void handlePublicKey(
      boolean isAuthKey, byte[] publicKey, byte[] ciphertext, Object extra) {
    handlePublicKey(isAuthKey, publicKey, extra);
    KeyAlgorithm keyAlgorithm = (KeyAlgorithm) extra;
    SendMessageRequest request = SendMessageRequest.newBuilder()
        .setUserId(Utils.getUserId(context))
        .setKeyAlgorithm(keyAlgorithm)
        .setIsAuthKey(isAuthKey)
        .setData(Utils.createSecureMessageBytes("retry msg", keyAlgorithm, isAuthKey)).build();
    blockingStub.sendMessage(request);
  }

  /**
   * This indicates that a Capillary ciphertext was saved to be decrypted later.
   */
  @Override
  public void authCiphertextSavedForLater(byte[] ciphertext, Object extra) {
    KeyAlgorithm keyAlgorithm = (KeyAlgorithm) extra;
    Log.d(TAG, String.format("ciphertext saved: KeyAlgorithm=%s", keyAlgorithm));
  }

  /**
   * This indicates an error.
   */
  @Override
  public void error(CapillaryHandlerErrorCode errorCode, byte[] ciphertext, Object extra) {
    KeyAlgorithm keyAlgorithm = (KeyAlgorithm) extra;
    Log.d(TAG, String.format("error occurred: code=%s, KeyAlgorithm=%s", errorCode, keyAlgorithm));
  }
}
