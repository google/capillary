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

package com.google.capillary.demo.android.callables;

import com.google.capillary.demo.android.Utils;
import com.google.capillary.demo.common.DemoServiceGrpc;
import com.google.capillary.demo.common.DemoServiceGrpc.DemoServiceBlockingStub;
import com.google.capillary.demo.common.KeyAlgorithm;
import com.google.capillary.demo.common.SendMessageRequest;
import io.grpc.ManagedChannel;
import java.util.concurrent.Callable;

/**
 * Requests the application server to send a demo notification message.
 */
public final class RequestMessage implements Callable<String> {

  private final ManagedChannel channel;
  private final KeyAlgorithm keyAlgorithm;
  private final String userId;
  private final boolean isAuthKey;
  private final int delay;

  /**
   * Initializes a new {@link RequestMessage}.
   *
   * @param channel the gRPC channel to use.
   * @param keyAlgorithm the algorithm to be used to encrypt the demo notification.
   * @param userId the user ID of the current app instance.
   * @param isAuthKey whether the demo notification should be encrypted using an authenticated key.
   * @param delay the amount of time the application server should wait before sending the
   *     notification.
   */
  public RequestMessage(
      ManagedChannel channel,
      KeyAlgorithm keyAlgorithm,
      String userId,
      boolean isAuthKey,
      int delay) {
    this.channel = channel;
    this.keyAlgorithm = keyAlgorithm;
    this.userId = userId;
    this.isAuthKey = isAuthKey;
    this.delay = delay;
  }

  @Override
  public String call() throws Exception {
    DemoServiceBlockingStub blockingStub = DemoServiceGrpc.newBlockingStub(channel);
    SendMessageRequest request = SendMessageRequest.newBuilder()
        .setUserId(userId)
        .setKeyAlgorithm(keyAlgorithm)
        .setIsAuthKey(isAuthKey)
        .setDelaySeconds(delay)
        .setData(Utils.createSecureMessageBytes("new msg", keyAlgorithm, isAuthKey)).build();
    blockingStub.sendMessage(request);
    return String.format("requested message with:\n%s", request);
  }
}
