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
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.RsaEcdsaHybridDecrypt;
import com.google.capillary.internal.WrappedRsaEcdsaPublicKey;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

/**
 * An implementation of {@link KeyManager} that supports RSA-ECDSA keys.
 */
public final class RsaEcdsaKeyManager extends KeyManager {

  // This prefix should be unique to each implementation of KeyManager.
  private static final String KEY_CHAIN_ID_PREFIX = "rsa_ecdsa_";

  private static Map<String, RsaEcdsaKeyManager> instances = new HashMap<>();

  private final KeyStore keyStore;

  private PublicKeyVerify senderVerifier;

  private RsaEcdsaKeyManager(
      Context context, Utils utils, String keychainId, InputStream senderVerificationKey)
      throws GeneralSecurityException, IOException {
    super(context, utils, KEY_CHAIN_ID_PREFIX + keychainId);
    KeysetHandle verificationKeyHandle = CleartextKeysetHandle
        .read(BinaryKeysetReader.withInputStream(senderVerificationKey));
    senderVerifier = PublicKeyVerifyFactory.getPrimitive(verificationKeyHandle);
    keyStore = utils.loadKeyStore();
  }

  /**
   * Returns the singleton {@link RsaEcdsaKeyManager} instance for the given keychain ID.
   *
   * <p>Please note that the {@link InputStream} {@code senderVerificationKey} will not be closed.
   *
   * @param context the app context.
   * @param keychainId the ID of the key manager.
   * @param senderVerificationKey the sender's ECDSA verification key.
   * @return the singleton {@link RsaEcdsaKeyManager} instance.
   * @throws GeneralSecurityException if the ECDSA verification key could not be initialized.
   * @throws IOException if the ECDSA verification key could not be read.
   */
  public static synchronized RsaEcdsaKeyManager getInstance(
      Context context, String keychainId, InputStream senderVerificationKey)
      throws GeneralSecurityException, IOException {
    if (instances.containsKey(keychainId)) {
      RsaEcdsaKeyManager instance = instances.get(keychainId);
      instance.updateSenderVerifier(senderVerificationKey);
      return instance;
    }
    RsaEcdsaKeyManager newInstance =
        new RsaEcdsaKeyManager(context, Utils.getInstance(), keychainId, senderVerificationKey);
    instances.put(keychainId, newInstance);
    return newInstance;
  }

  private synchronized void updateSenderVerifier(InputStream senderVerificationKey)
      throws GeneralSecurityException, IOException {
    KeysetHandle verificationKeyHandle = CleartextKeysetHandle
        .read(BinaryKeysetReader.withInputStream(senderVerificationKey));
    senderVerifier = PublicKeyVerifyFactory.getPrimitive(verificationKeyHandle);
  }

  @Override
  synchronized void rawGenerateKeyPair(boolean isAuth)
      throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    AndroidKeyStoreRsaUtils.generateKeyPair(context, keychainId, isAuth);
  }

  @Override
  synchronized byte[] rawGetPublicKey(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException {
    byte[] publicKeyBytes =
        AndroidKeyStoreRsaUtils.getPublicKey(keyStore, keychainId, isAuth).getEncoded();
    return WrappedRsaEcdsaPublicKey.newBuilder()
        .setPadding(AndroidKeyStoreRsaUtils.getCompatibleRsaPadding().name())
        .setKeyBytes(ByteString.copyFrom(publicKeyBytes))
        .build().toByteArray();
  }

  @Override
  synchronized HybridDecrypt rawGetDecrypter(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException {
    PrivateKey recipientPrivateKey =
        AndroidKeyStoreRsaUtils.getPrivateKey(keyStore, keychainId, isAuth);
    return new RsaEcdsaHybridDecrypt.Builder()
        .withRecipientPrivateKey(recipientPrivateKey)
        .withSenderVerifier(senderVerifier)
        .withPadding(AndroidKeyStoreRsaUtils.getCompatibleRsaPadding())
        .build();
  }

  @Override
  synchronized void rawDeleteKeyPair(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException {
    AndroidKeyStoreRsaUtils.deleteKeyPair(keyStore, keychainId, isAuth);
  }
}
