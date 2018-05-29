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

package com.google.capillary;

import com.google.capillary.internal.WrappedWebPushPublicKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.apps.webpush.WebPushHybridEncrypt;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * An implementation of {@link EncrypterManager} that supports Web Push encryption.
 */
public final class WebPushEncrypterManager extends EncrypterManager {

  @Override
  HybridEncrypt rawLoadPublicKey(byte[] publicKey) throws GeneralSecurityException {
    WrappedWebPushPublicKey wrappedWebPushPublicKey;
    try {
      wrappedWebPushPublicKey = WrappedWebPushPublicKey.parseFrom(publicKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("unable to parse public key", e);
    }
    return new WebPushHybridEncrypt.Builder()
        .withAuthSecret(wrappedWebPushPublicKey.getAuthSecret().toByteArray())
        .withRecipientPublicKey(wrappedWebPushPublicKey.getKeyBytes().toByteArray())
        .build();
  }
}
