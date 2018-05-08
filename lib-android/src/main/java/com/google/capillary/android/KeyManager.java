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
import android.support.annotation.VisibleForTesting;
import com.google.capillary.AuthModeUnavailableException;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.internal.CapillaryPublicKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.UUID;

/**
 * Encapsulates the management of Capillary keys.
 */
public abstract class KeyManager {

  private static final String AUTH_KEY_SERIAL_NUMBER_KEY = "current_auth_key_serial_number";
  private static final String NO_AUTH_KEY_SERIAL_NUMBER_KEY = "current_no_auth_key_serial_number";
  private static final String KEYCHAIN_UNIQUE_ID_KEY = "keychain_unique_id";

  final Context context;
  final String keychainId;

  private final Utils utils;
  private final SharedPreferences sharedPreferences;

  private DecrypterManager decrypterManager;

  /**
   * Creates a new {@link KeyManager} instance for managing Capillary keys.
   */
  KeyManager(Context context, Utils utils, String keychainId) {
    this.context = context;
    this.utils = utils;
    this.keychainId = keychainId;
    Context storageContext = utils.getDeviceProtectedStorageContext(context);
    String prefName = String.format("%s_%s_preferences", getClass().getCanonicalName(), keychainId);
    sharedPreferences = storageContext.getSharedPreferences(prefName, Context.MODE_PRIVATE);
  }

  /**
   * Provides a {@link DecrypterManager} backed by this {@link KeyManager}.
   *
   * @return the {@link DecrypterManager} instance.
   */
  public synchronized DecrypterManager getDecrypterManager() {
    if (decrypterManager == null) {
      CiphertextStorage ciphertextStorage = new CiphertextStorage(context, utils, keychainId);
      decrypterManager = new DecrypterManager(context, this, ciphertextStorage, utils);
    }
    return decrypterManager;
  }

  private static String toSerialNumberPrefKey(boolean isAuth) {
    return isAuth ? AUTH_KEY_SERIAL_NUMBER_KEY : NO_AUTH_KEY_SERIAL_NUMBER_KEY;
  }

  /**
   * Generates both auth and no-auth key pairs.
   *
   * @throws AuthModeUnavailableException if the user has not enabled authentication
   *     (i.e., a device with no screen lock).
   * @throws GeneralSecurityException if the key generation fails.
   */
  public void generateKeyPairs() throws GeneralSecurityException, AuthModeUnavailableException {
    generateKeyPair(false);
    generateKeyPair(true);
  }

  /**
   * Generates a new Capillary key pair.
   *
   * @param isAuth whether the user must authenticate (i.e., by unlocking the device) before the
   *     generated key could be used.
   * @throws AuthModeUnavailableException if an authenticated key was requested but the user has not
   *     enabled authentication (i.e., a device with no screen lock).
   * @throws GeneralSecurityException if the key generation fails.
   */
  public synchronized void generateKeyPair(boolean isAuth)
      throws AuthModeUnavailableException, GeneralSecurityException {
    int currentSerialNumber = sharedPreferences.getInt(toSerialNumberPrefKey(isAuth), -1);
    generateKeyPair(currentSerialNumber + 1, isAuth);
  }

  /**
   * Generates a new Capillary key pair with the given key serial number.
   */
  synchronized boolean generateKeyPair(int newSerialNumber, boolean isAuth)
      throws AuthModeUnavailableException, GeneralSecurityException {
    if (isAuth) {
      utils.checkAuthModeIsAvailable(context);
    }
    int currentSerialNumber = sharedPreferences.getInt(toSerialNumberPrefKey(isAuth), -1);
    // If the requested serial number is older, do not generate the keys.
    if (newSerialNumber <= currentSerialNumber) {
      return false;
    }
    rawGenerateKeyPair(isAuth);
    sharedPreferences.edit().putInt(toSerialNumberPrefKey(isAuth), newSerialNumber).apply();
    return true;
  }

  static String toKeyTypeString(boolean isAuth) {
    return isAuth ? "Auth" : "NoAuth";
  }

  private int checkAndGetSerialNumber(boolean isAuth) throws NoSuchKeyException {
    int currentSerialNumber = sharedPreferences.getInt(toSerialNumberPrefKey(isAuth), -1);
    if (currentSerialNumber == -1) {
      throw new NoSuchKeyException(toKeyTypeString(isAuth) + " key not initialized");
    }
    return currentSerialNumber;
  }

  /**
   * Generates a raw key pair underlying a Capillary key pair.
   *
   * <p>The private key of the generated key pair should ideally be stored in the Android Keystore,
   * which attempts to bind the private keys to a secure hardware on the device.
   */
  abstract void rawGenerateKeyPair(boolean isAuth) throws GeneralSecurityException;

  /**
   * Provides a Capillary public key.
   *
   * <p>The key must have been generated using {@code generateKey}. The key will be returned via
   * the provided Capillary handler.
   *
   * @param isAuth whether the user must authenticate (i.e., by unlocking the device) before the
   *     generated key could be used.
   * @param handler the Capillary handler instance.
   * @param extra the extra parameters to be passed back to the provided handler.
   * @throws NoSuchKeyException if the requested key does not exist.
   * @throws AuthModeUnavailableException if an authenticated key was requested but the user has not
   *     enabled authentication (i.e., a device with no screen lock).
   * @throws GeneralSecurityException if the public key could not be retrieved.
   */
  public void getPublicKey(boolean isAuth, CapillaryHandler handler, Object extra)
      throws NoSuchKeyException, AuthModeUnavailableException, GeneralSecurityException {
    handler.handlePublicKey(isAuth, getPublicKey(isAuth), extra);
  }

  /**
   * Provides the Capillary public key that is serialized into a byte array.
   */
  synchronized byte[] getPublicKey(boolean isAuth)
      throws NoSuchKeyException,
      AuthModeUnavailableException,
      GeneralSecurityException {
    if (isAuth) {
      utils.checkAuthModeIsAvailable(context);
    }
    int currentSerialNumber = checkAndGetSerialNumber(isAuth);
    return CapillaryPublicKey.newBuilder()
        .setKeychainUniqueId(getKeychainUniqueId())
        .setSerialNumber(currentSerialNumber)
        .setIsAuth(isAuth)
        .setKeyBytes(ByteString.copyFrom(rawGetPublicKey(isAuth)))
        .build().toByteArray();
  }

  @VisibleForTesting
  String getKeychainUniqueId() {
    String uniqueId = sharedPreferences.getString(KEYCHAIN_UNIQUE_ID_KEY, null);
    if (uniqueId == null) {
      uniqueId = UUID.randomUUID().toString();
      sharedPreferences.edit().putString(KEYCHAIN_UNIQUE_ID_KEY, uniqueId).apply();
    }
    return uniqueId;
  }

  /**
   * Provides the raw public key underlying the specified Capillary public key.
   */
  abstract byte[] rawGetPublicKey(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException;

  /**
   * Wrapper for {@code rawGetDecrypter} method that checks if the Specified Capillary public key
   * is valid.
   */
  synchronized HybridDecrypt getDecrypter(
      String requestedUniqueId, int serialNumberInCiphertext, boolean isAuth)
      throws NoSuchKeyException, AuthModeUnavailableException, GeneralSecurityException {
    if (isAuth) {
      utils.checkAuthModeIsAvailable(context);
    }
    // Check if the given unique ID is valid. If not, it indicates a key corruption due to resetting
    // SharedPreferences.
    if (!getKeychainUniqueId().equals(requestedUniqueId)) {
      throw new NoSuchKeyException("keychain unique ID mismatch");
    }
    int serialNumberInPrefs = checkAndGetSerialNumber(isAuth);
    // Also check if the given serial number is valid. If not, it indicates that a newly generated
    // Capillary key has not been successfully received by the application server.
    if (serialNumberInPrefs != serialNumberInCiphertext) {
      throw new NoSuchKeyException(toKeyTypeString(isAuth) + " key serial number invalid");
    }
    return rawGetDecrypter(isAuth);
  }

  /**
   * Provides a {@link HybridDecrypt} instance that can decrypt ciphertexts that were generated
   * using the underlying raw public key of the specified Capillary public key.
   */
  abstract HybridDecrypt rawGetDecrypter(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException;

  /**
   * Deletes the specified Capillary key pair.
   *
   * @param isAuth whether the user must authenticate (i.e., by unlocking the device) before the
   *     generated key could be used.
   * @throws NoSuchKeyException if the specified key pair does not exist.
   * @throws AuthModeUnavailableException if an authenticated key pair was specified but the user
   *     has not enabled authentication (i.e., a device with no screen lock).
   * @throws GeneralSecurityException if the key pair could not be deleted.
   */
  public void deleteKeyPair(boolean isAuth)
      throws NoSuchKeyException,
      AuthModeUnavailableException,
      GeneralSecurityException {
    // Ideally, we should be able to delete auth keys in an unauthenticated setting. But, not every
    // Android version allows us to do so. So, we have this check here so that the Capillary library
    // interface is consistent across all Android API levels that we're supporting.
    if (isAuth) {
      utils.checkAuthModeIsAvailable(context);
    }
    checkAndGetSerialNumber(isAuth);
    rawDeleteKeyPair(isAuth);
  }

  /**
   * Deletes the raw key pair underlying the specified Capillary key pair.
   */
  abstract void rawDeleteKeyPair(boolean isAuth)
      throws NoSuchKeyException, GeneralSecurityException;
}
