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
import com.google.capillary.demo.common.AddOrUpdateUserRequest;
import com.google.capillary.demo.common.DemoServiceGrpc;
import com.google.capillary.demo.common.DemoServiceGrpc.DemoServiceBlockingStub;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.FirebaseInstanceIdService;
import io.grpc.ManagedChannel;
import java.io.IOException;

/**
 * Extends the {@link FirebaseInstanceIdService} to register refreshed IID tokens with the server.
 * The communication with the server is done via gRPC.
 */
public final class DemoFiidService extends FirebaseInstanceIdService {

  private static final String TAG = DemoFiidService.class.getSimpleName();

  @Override
  public void onTokenRefresh() {
    String newToken = FirebaseInstanceId.getInstance().getToken();
    Log.d(TAG, "new token received: " + newToken);

    sendRegistrationToServer(newToken);
  }

  private void sendRegistrationToServer(String token) {
    try {
      Utils.initialize(this);

      // Create the gRPC channel and stub.
      ManagedChannel channel = Utils.createGrpcChannel(this);
      DemoServiceBlockingStub blockingStub = DemoServiceGrpc.newBlockingStub(channel);

      // Create and send the AddOrUpdateUserRequest.
      AddOrUpdateUserRequest request = AddOrUpdateUserRequest.newBuilder()
          .setUserId(Utils.getUserId(this))
          .setToken(token)
          .build();
      blockingStub.addOrUpdateUser(request);

      // Close the gRPC channel.
      channel.shutdown();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}
