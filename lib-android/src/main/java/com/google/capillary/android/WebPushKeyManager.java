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
import android.content.SharedPreferences;
import com.google.capillary.HybridRsaUtils;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.internal.WrappedWebPushPrivateKey;
import com.google.capillary.internal.WrappedWebPushPublicKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.apps.webpush.WebPushHybridDecrypt;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

/**
 * An implementation of {@link KeyManager} that supports Web Push keys.
 */
public class WebPushKeyManager extends KeyManager {

  // This prefix should be unique to each implementation of KeyManager.
  private static final String KEY_CHAIN_ID_PREFIX = "web_push_";
  private static final String PRIVATE_KEY_KEY_SUFFIX = "_encrypted_web_push_private_key";
  private static final String PUBLIC_KEY_KEY_SUFFIX = "_web_push_public_key";
  private static final OAEPParameterSpec OAEP_PARAMETER_SPEC =
      new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSpecified.DEFAULT);

  private static Map<String, WebPushKeyManager> instances = new HashMap<>();

  private final KeyStore keyStore;
  private final SharedPreferences sharedPreferences;

  private WebPushKeyManager(
      Context context, Utils utils, String keychainId) throws GeneralSecurityException {
    super(context, utils, KEY_CHAIN_ID_PREFIX + keychainId);
    keyStore = utils.loadKeyStore();
    Context storageContext = utils.getDeviceProtectedStorageContext(context);
    String prefName = String.format("%s_%s_preferences", getClass().getCanonicalName(), keychainId);
    sharedPreferences = storageContext.getSharedPreferences(prefName, Context.MODE_PRIVATE);
  }

  /**
   * Returns the singleton {@link WebPushKeyManager} instance for the given keychain ID.
   *
   * @param context the app context.
   * @param keychainId the ID of the key manager.
   * @return the singleton {@link WebPushKeyManager} instance.
   * @throws GeneralSecurityException if a new {@link WebPushKeyManager} could not be created.
   */
  public static synchronized WebPushKeyManager getInstance(
      Context context, String keychainId) throws GeneralSecurityException {
    if (instances.containsKey(keychainId)) {
      return instances.get(keychainId);
    }
    WebPushKeyManager newInstance = new WebPushKeyManager(context, Utils.getInstance(), keychainId);
    instances.put(keychainId, newInstance);
    return newInstance;
  }

  private static String toKeyPrefKey(boolean isAuth, boolean isPublic) {
    String prefix = isAuth ? "auth" : "no_auth";
    String suffix = isPublic ? PUBLIC_KEY_KEY_SUFFIX : PRIVATE_KEY_KEY_SUFFIX;
    return prefix + suffix;
  }

  @Override
  synchronized void rawGenerateKeyPair(boolean isAuth) throws GeneralSecurityException {
    // Android Keystore does not support Web Push (i.e., ECDH) protocol. So we have to generate the
    // Web Push key pair using the Tink library, and wrap the generated Web Push private key using a
    // private key stored in Android Keystore. The only cipher that Android Keystore consistently
    // supports across API levels 19-27 is RSA. However, Tink's Web Push private keys are larger
    // than the largest RSA modulus that the Android Keystore supports for all API levels in 19-27.
    // So, we have to wrap the Tink private key using a symmetric key that can fit in the supported
    // RSA modulus size and wrap that symmetric key using a RSA key stored in Android Keystore.
    // We have chosen AES in GCM mode as the symmetric key algorithm (more info in
    // com.google.capillary.HybridRsaUtils.java.)

    // Generate RSA key pair in Android key store.
    AndroidKeyStoreRsaUtils.generateKeyPair(context, keychainId, isAuth);

    // Generate web push key pair.
    byte[] authSecret = Random.randBytes(16);
    KeyPair ecKeyPair = EllipticCurves.generateKeyPair(CurveType.NIST_P256);
    // Generate web push public key bytes.
    ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
    byte[] ecPublicKeyBytes =
        EllipticCurves.pointEncode(
            CurveType.NIST_P256, PointFormatType.UNCOMPRESSED, ecPublicKey.getW());
    WrappedWebPushPublicKey webPushPublicKey = WrappedWebPushPublicKey.newBuilder()
        .setAuthSecret(ByteString.copyFrom(authSecret))
        .setKeyBytes(ByteString.copyFrom(ecPublicKeyBytes)).build();
    byte[] webPushPublicKeyBytes = webPushPublicKey.toByteArray();
    // Generate web push private key bytes.
    ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
    byte[] ecPrivateKeyBytes = ecPrivateKey.getS().toByteArray();
    WrappedWebPushPrivateKey webPushPrivateKey = WrappedWebPushPrivateKey.newBuilder()
        .setAuthSecret(ByteString.copyFrom(authSecret))
        .setPublicKeyBytes(ByteString.copyFrom(ecPublicKeyBytes))
        .setPrivateKeyBytes(ByteString.copyFrom(ecPrivateKeyBytes)).build();
    byte[] webPushPrivateKeyBytes = webPushPrivateKey.toByteArray();

    // Encrypt web push private key bytes.
    PublicKey rsaPublicKey;
    try {
      rsaPublicKey = AndroidKeyStoreRsaUtils.getPublicKey(keyStore, keychainId, isAuth);
    } catch (NoSuchKeyException e) {
      throw new GeneralSecurityException("unable to load rsa public key", e);
    }
    // Encrypt web push private key using hybrid RSA.
    byte[] encryptedWebPushPrivateKeyBytes = HybridRsaUtils.encrypt(
        webPushPrivateKeyBytes,
        rsaPublicKey,
        AndroidKeyStoreRsaUtils.getCompatibleRsaPadding(),
        OAEP_PARAMETER_SPEC);

    // Store web push keys in shared prefs.
    sharedPreferences.edit()
        .putString(toKeyPrefKey(isAuth, true), Base64.encode(webPushPublicKeyBytes))
        .putString(toKeyPrefKey(isAuth, false), Base64.encode(encryptedWebPushPrivateKeyBytes))
        .apply();
  }

  private void checkKeyExists(boolean isAuth) throws NoSuchKeyException, KeyStoreException {
    if (!sharedPreferences.contains(toKeyPrefKey(isAuth, true))
        || !sharedPreferences.contains(toKeyPrefKey(isAuth, false))) {
      throw new NoSuchKeyException(toKeyTypeString(isAuth) + " web push key not initialized");
    }
  }

  @Override
  synchronized byte[] rawGetPublicKey(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException {
    AndroidKeyStoreRsaUtils.checkKeyExists(keyStore, keychainId, isAuth);
    checkKeyExists(isAuth);
    return Base64.decode(sharedPreferences.getString(toKeyPrefKey(isAuth, true), null));
  }

  @Override
  synchronized HybridDecrypt rawGetDecrypter(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException {
    checkKeyExists(isAuth);
    // Load encrypted web push private key.
    byte[] encryptedWebPushPrivateKeyBytes =
        Base64.decode(sharedPreferences.getString(toKeyPrefKey(isAuth, false), null));
    // Decrypt the encrypted web push private key using the rsa key stored in Android key store.
    PrivateKey rsaPrivateKey = AndroidKeyStoreRsaUtils.getPrivateKey(keyStore, keychainId, isAuth);
    byte[] webPushPrivateKeyBytes = HybridRsaUtils.decrypt(
        encryptedWebPushPrivateKeyBytes,
        rsaPrivateKey,
        AndroidKeyStoreRsaUtils.getCompatibleRsaPadding(),
        OAEP_PARAMETER_SPEC);
    // Parse the decrypted web push private key.
    WrappedWebPushPrivateKey webPushPrivateKey;
    try {
      webPushPrivateKey = WrappedWebPushPrivateKey.parseFrom(webPushPrivateKeyBytes);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("unable to load web push private key", e);
    }
    // Create and return web push hybrid decrypter.
    return new WebPushHybridDecrypt.Builder()
        .withAuthSecret(webPushPrivateKey.getAuthSecret().toByteArray())
        .withRecipientPublicKey(webPushPrivateKey.getPublicKeyBytes().toByteArray())
        .withRecipientPrivateKey(webPushPrivateKey.getPrivateKeyBytes().toByteArray())
        .build();
  }

  @Override
  synchronized void rawDeleteKeyPair(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException {
    checkKeyExists(isAuth);
    AndroidKeyStoreRsaUtils.deleteKeyPair(keyStore, keychainId, isAuth);
  }
}
