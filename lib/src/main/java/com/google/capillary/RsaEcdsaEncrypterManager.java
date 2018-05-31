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

import com.google.capillary.internal.WrappedRsaEcdsaPublicKey;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * An implementation of {@link EncrypterManager} that supports RSA-ECDSA encryption.
 */
public final class RsaEcdsaEncrypterManager extends EncrypterManager {

  private final PublicKeySign senderSigner;

  /**
   * Constructs a new RSA-ECDSA EncrypterManager.
   *
   * <p>Please note that the {@link InputStream} {@code senderSigningKey} will not be closed.
   *
   * @param senderSigningKey the serialized Tink signing key.
   * @throws GeneralSecurityException if the initialization fails.
   * @throws IOException if the given sender signing key cannot be read.
   */
  public RsaEcdsaEncrypterManager(InputStream senderSigningKey)
      throws GeneralSecurityException, IOException {
    KeysetHandle signingKeyHandle = CleartextKeysetHandle
        .read(BinaryKeysetReader.withInputStream(senderSigningKey));
    senderSigner = PublicKeySignFactory.getPrimitive(signingKeyHandle);
  }

  @Override
  HybridEncrypt rawLoadPublicKey(byte[] publicKey) throws GeneralSecurityException {
    WrappedRsaEcdsaPublicKey wrappedRsaEcdsaPublicKey;
    try {
      wrappedRsaEcdsaPublicKey = WrappedRsaEcdsaPublicKey.parseFrom(publicKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("unable to parse public key", e);
    }
    PublicKey recipientPublicKey = KeyFactory.getInstance("RSA").generatePublic(
        new X509EncodedKeySpec(wrappedRsaEcdsaPublicKey.getKeyBytes().toByteArray()));
    return new RsaEcdsaHybridEncrypt.Builder()
        .withSenderSigner(senderSigner)
        .withRecipientPublicKey(recipientPublicKey)
        .withPadding(RsaEcdsaConstants.Padding.valueOf(wrappedRsaEcdsaPublicKey.getPadding()))
        .build();
  }
}
