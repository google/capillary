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

import com.google.capillary.internal.CapillaryCiphertext;
import com.google.capillary.internal.CapillaryPublicKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Encapsulates the process of encrypting plaintexts into Capillary ciphertexts.
 *
 * <p>Any class that extends EncrypterManager allows the following usage pattern:
 * <pre>{@code
 * EncrypterManager encrypterManager = new EncrypterManagerImpl(params);
 * encrypterManager.loadPublicKey(publicKey);
 * byte[] ciphertext = encrypterManager.encrypt(plaintext);
 * encrypterManager.clearPublicKey();
 * }</pre>
 */
public abstract class EncrypterManager {

  private boolean isLoaded;
  private CapillaryPublicKey capillaryPublicKey;
  private HybridEncrypt encrypter;

  /**
   * Loads a serialized Capillary public key.
   *
   * @param publicKey the serialized Capillary public key.
   * @throws GeneralSecurityException if the given Capillary public key cannot be loaded.
   */
  public synchronized void loadPublicKey(byte[] publicKey) throws GeneralSecurityException {
    try {
      capillaryPublicKey = CapillaryPublicKey.parseFrom(publicKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("unable to parse public key", e);
    }
    encrypter = rawLoadPublicKey(capillaryPublicKey.getKeyBytes().toByteArray());
    isLoaded = true;
  }

  /**
   * Creates a {@link HybridEncrypt} for a raw public key embedded in a Capillary public key.
   */
  abstract HybridEncrypt rawLoadPublicKey(byte[] rawPublicKey) throws GeneralSecurityException;

  /**
   * Encryptes the given plaintext into a Capillary ciphertext.
   *
   * @param data the plaintext.
   * @return the Capillary ciphertext.
   * @throws GeneralSecurityException if the encryption fails.
   */
  public synchronized byte[] encrypt(byte[] data) throws GeneralSecurityException {
    if (!isLoaded) {
      throw new GeneralSecurityException("public key is not loaded");
    }
    byte[] ciphertext = encrypter.encrypt(data, null);
    return CapillaryCiphertext.newBuilder()
        .setKeychainUniqueId(capillaryPublicKey.getKeychainUniqueId())
        .setKeySerialNumber((capillaryPublicKey.getSerialNumber()))
        .setIsAuthKey(capillaryPublicKey.getIsAuth())
        .setCiphertext(ByteString.copyFrom(ciphertext))
        .build().toByteArray();
  }

  /**
   * Clears the loaded Capillary public key.
   */
  public synchronized void clearPublicKey() {
    isLoaded = false;
    capillaryPublicKey = null;
    encrypter = null;
  }
}
