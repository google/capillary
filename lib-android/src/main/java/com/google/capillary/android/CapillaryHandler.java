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

package com.google.capillary.android;

/**
 * Defines the interface for generating Capillary public keys and decrypting Capillary ciphertexts.
 *
 * <p>One should implement {@link CapillaryHandler} and pass an instance to:
 * <ul>
 * <li>{@link DecrypterManager} to decrypt Capillary ciphertexts.</li>
 * <li>{@link KeyManager} to generate Capillary public keys.</li>
 * </ul>
 *
 * <p>The implemented {@link CapillaryHandler} should finish the execution of its methods as soon as
 * possible. Any long-running tasks, such as network requests, should be done in separate threads.
 */
public interface CapillaryHandler {

  /**
   * Provides the plaintext after decrypting a Capillary ciphertext.
   *
   * @param isAuthKey whether the decryption was done using a public key requiring authentication.
   * @param data the plaintext.
   * @param extra the extra parameter originally passed to {@link DecrypterManager}.
   */
  void handleData(boolean isAuthKey, byte[] data, Object extra);

  /**
   * Provides the generated Capillary public key.
   *
   * @param isAuthKey whether the public key requires authentication.
   * @param publicKey the public key.
   * @param extra the extra parameter originally passed to {@link KeyManager}.
   */
  void handlePublicKey(boolean isAuthKey, byte[] publicKey, Object extra);

  /**
   * Provides the Capillary public key that was generated as a result of a decryption error.
   *
   * @param isAuthKey whether the public key requires authentication.
   * @param publicKey the public key.
   * @param ciphertext the ciphertext that caused the decryption error.
   * @param extra the extra parameter originally passed to {@link DecrypterManager}.
   */
  void handlePublicKey(boolean isAuthKey, byte[] publicKey, byte[] ciphertext, Object extra);

  /**
   * Signals that a Capillary ciphertext was saved to be decrypted after user authentication.
   *
   * @param ciphertext the saved Capillary ciphertext.
   * @param extra the extra parameter originally passed to {@link DecrypterManager}.
   */
  void authCiphertextSavedForLater(byte[] ciphertext, Object extra);

  /**
   * Signals that an error has occurred.
   *
   * @param errorCode the error code enum.
   * @param ciphertext the Capillary ciphertext that is affected by this error.
   * @param extra the extra parameter originally passed to {@link DecrypterManager}.
   */
  void error(CapillaryHandlerErrorCode errorCode, byte[] ciphertext, Object extra);
}
