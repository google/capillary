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

import com.google.capillary.demo.common.AddOrUpdateUserRequest;
import com.google.capillary.demo.common.DemoServiceGrpc;
import com.google.capillary.demo.common.DemoServiceGrpc.DemoServiceBlockingStub;
import com.google.firebase.iid.FirebaseInstanceId;
import io.grpc.ManagedChannel;
import java.util.concurrent.Callable;

/**
 * Registers the current user with the application server.
 */
public final class RegUser implements Callable<String> {

  private final ManagedChannel channel;
  private final String userId;

  /**
   * Initializes a new {@link RegUser}.
   *
   * @param channel the Capillary handler to use.
   * @param userId the user ID.
   */
  public RegUser(ManagedChannel channel, String userId) {
    this.channel = channel;
    this.userId = userId;
  }

  @Override
  public String call() throws Exception {
    DemoServiceBlockingStub blockingStub = DemoServiceGrpc.newBlockingStub(channel);
    AddOrUpdateUserRequest request = AddOrUpdateUserRequest.newBuilder()
        .setUserId(userId)
        .setToken(FirebaseInstanceId.getInstance().getToken()).build();
    blockingStub.addOrUpdateUser(request);
    return String.format("registered user with:\n%s", request);
  }
}
