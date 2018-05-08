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

import android.content.Context;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.UserNotAuthenticatedException;
import com.google.capillary.AuthModeUnavailableException;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.internal.CapillaryCiphertext;
import com.google.crypto.tink.HybridDecrypt;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.UnrecoverableKeyException;
import java.util.List;

/**
 * Encapsulates the process of decrypting Capillary ciphertexts.
 */
public final class DecrypterManager {

  private final Context context;
  private final CiphertextStorage ciphertextStorage;
  private final KeyManager keyManager;
  private final Utils utils;

  /**
   * Creates a new {@link DecrypterManager} instance backed by the given key manager instance.
   */
  DecrypterManager(
      Context context, KeyManager keyManager, CiphertextStorage ciphertextStorage, Utils utils) {
    this.context = context;
    this.ciphertextStorage = ciphertextStorage;
    this.keyManager = keyManager;
    this.utils = utils;
  }

  /**
   * Attempts to decrypt any Capillary ciphertexts that were saved to be decrypted later.
   *
   * @param handler the Capillary handler instance.
   * @param extra the extra parameters to be passed back to the provided handler.
   */
  public synchronized void decryptSaved(CapillaryHandler handler, Object extra) {
    List<byte[]> ciphertexts = ciphertextStorage.get();
    ciphertextStorage.clear();
    for (byte[] data : ciphertexts) {
      decrypt(data, handler, extra);
    }
  }

  /**
   * Attempts to decrypt the given Capillary ciphertext.
   *
   * <p>If the decryption is successful, the plaintext will be returned via the provided Capillary
   * handler. If the decryption key requires authentication, but the user has not yet authenticated,
   * the ciphertext will be saved to be decrypted later. If the decryption key is missing or
   * corrupted, a new Capillary key pair will be generated and the generated Capillary public key
   * will be passed back via handler. If any of the above steps fail, a related error code from
   * {@link CapillaryHandlerErrorCode} will be returned via the provided Capillary handler.
   *
   * @param ciphertext the Capillary ciphertext.
   * @param handler the Capillary handler instance.
   * @param extra the extra parameters to be passed back to the provided handler.
   */
  public synchronized void decrypt(byte[] ciphertext, CapillaryHandler handler, Object extra) {
    // Parse the given ciphertext bytes.
    CapillaryCiphertext capillaryCiphertext;
    try {
      capillaryCiphertext = CapillaryCiphertext.parseFrom(ciphertext);
    } catch (InvalidProtocolBufferException e) {
      handler.error(CapillaryHandlerErrorCode.MALFORMED_CIPHERTEXT, ciphertext, extra);
      return;
    }

    // Save the ciphertext for later if the decryption key is not ready.
    if (capillaryCiphertext.getIsAuthKey() && utils.isScreenLocked(context)) {
      ciphertextStorage.save(ciphertext);
      handler.authCiphertextSavedForLater(ciphertext, extra);
      return;
    }

    byte[] rawCiphertext = capillaryCiphertext.getCiphertext().toByteArray();
    byte[] data;

    // Attempt decryption.
    try {
      HybridDecrypt decrypter = keyManager.getDecrypter(
          capillaryCiphertext.getKeychainUniqueId(),
          capillaryCiphertext.getKeySerialNumber(),
          capillaryCiphertext.getIsAuthKey());
      data = decrypter.decrypt(rawCiphertext, null);
    } catch (AuthModeUnavailableException e) {
      handler.error(CapillaryHandlerErrorCode.AUTH_CIPHER_IN_NO_AUTH_DEVICE, ciphertext, extra);
      return;
    } catch (Exception e) { // Needs to catch Exception here to support multiple API levels.
      // In API levels 23 and above, this happens when the user has enabled authentication, but
      // hasn't yet authenticated in the lock screen (e.g., added a new unlock code, but hasn't
      // locked the device yet.).
      if (VERSION.SDK_INT >= VERSION_CODES.M && e instanceof UserNotAuthenticatedException) {
        ciphertextStorage.save(ciphertext);
        handler.authCiphertextSavedForLater(ciphertext, extra);
        return;
      }
      // All these exceptions refer to missing or corrupt decryption keys.
      if (e instanceof NoSuchKeyException // Thrown by Capillary library.
          // Thrown in API levels 23, 24, 25.
          || (VERSION.SDK_INT >= VERSION_CODES.M && e instanceof KeyPermanentlyInvalidatedException)
          // Thrown in API levels 26, 27.
          || (VERSION.SDK_INT >= VERSION_CODES.O && e instanceof UnrecoverableKeyException)) {
        regenerateKeyAndRequestMessage(capillaryCiphertext, handler, extra);
        return;
      }
      // Reaching here implies an unknown error has occurred.
      handler.error(CapillaryHandlerErrorCode.UNKNOWN_ERROR, ciphertext, extra);
      return;
    }

    // Return plaintext via the provided handler.
    handler.handleData(capillaryCiphertext.getIsAuthKey(), data, extra);
  }

  private void regenerateKeyAndRequestMessage(
      CapillaryCiphertext capillaryCiphertext, CapillaryHandler handler, Object extra) {
    boolean isAuthKey = capillaryCiphertext.getIsAuthKey();
    byte[] ciphertext = capillaryCiphertext.toByteArray();
    try {
      // Attempt to generate a new Capillary key pair.
      boolean isKeyPairGenerated =
          keyManager.generateKeyPair(capillaryCiphertext.getKeySerialNumber() + 1, isAuthKey);
      // Failure to generate the key here implies that the given Capillary ciphertext was generated
      // using an older Capillary public key. So, pass the appropriate error code back via the given
      // handler. The client should re-register the current Capillary public key with the
      // application server to avoid this error happening again.
      if (!isKeyPairGenerated) {
        handler.error(CapillaryHandlerErrorCode.STALE_CIPHERTEXT, ciphertext, extra);
        return;
      }
      // Return the newly generated Capillary public key via the provided handler.
      handler.handlePublicKey(isAuthKey, keyManager.getPublicKey(isAuthKey), ciphertext, extra);
    } catch (AuthModeUnavailableException | NoSuchKeyException | GeneralSecurityException e) {
      // None of these error should occur. If they do, that indicates an unknown error.
      handler.error(CapillaryHandlerErrorCode.UNKNOWN_ERROR, ciphertext, extra);
    }
  }
}
