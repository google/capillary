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
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.RsaEcdsaConstants.Padding;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.security.auth.x500.X500Principal;
import org.joda.time.LocalDate;

/**
 * AndroidKeyStoreRsaUtils provides utility methods to generate RSA key pairs in Android Keystore
 * and perform crypto operations with those keys. Currently, this class supports Android API levels
 * 19-27. Support for Android API levels 28+ (e.g., StrongBox Keymaster) will be added as those API
 * levels are publicly released.
 */
final class AndroidKeyStoreRsaUtils {

  private static final String AUTH_KEY_ALIAS_SUFFIX = "_capillary_rsa_auth";
  private static final String NO_AUTH_KEY_ALIAS_SUFFIX = "_capillary_rsa_no_auth";
  private static final String KEYSTORE_ANDROID = "AndroidKeyStore";
  private static final int KEY_SIZE = 2048;
  private static final int KEY_DURATION_YEARS = 100;
  // Allow any screen unlock event to be valid for up to 1 hour.
  private static final int UNLOCK_DURATION_SECONDS = 60 * 60;

  static void generateKeyPair(Context context, String keychainId, boolean isAuth)
      throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    String keyAlias = toKeyAlias(keychainId, isAuth);
    RSAKeyGenParameterSpec rsaSpec =
        new RSAKeyGenParameterSpec(KEY_SIZE, RSAKeyGenParameterSpec.F4);
    AlgorithmParameterSpec spec;

    // API levels 23 and above should use KeyGenParameterSpec to build RSA keys.
    if (VERSION.SDK_INT >= VERSION_CODES.M) {
      KeyGenParameterSpec.Builder specBuilder =
          new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT)
              .setAlgorithmParameterSpec(rsaSpec)
              .setDigests(KeyProperties.DIGEST_SHA256)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
      if (isAuth) {
        specBuilder.setUserAuthenticationRequired(true);
        specBuilder.setUserAuthenticationValidityDurationSeconds(UNLOCK_DURATION_SECONDS);
      }
      spec = specBuilder.build();
    } else { // API levels 22 and below have to use KeyPairGeneratorSpec to build RSA keys.
      LocalDate startDate = LocalDate.now();
      LocalDate endDate = startDate.plusYears(KEY_DURATION_YEARS);
      KeyPairGeneratorSpec.Builder specBuilder = new KeyPairGeneratorSpec.Builder(context)
          .setAlias(keyAlias)
          .setSubject(new X500Principal("CN=" + keyAlias))
          .setSerialNumber(BigInteger.ONE)
          .setStartDate(startDate.toDate())
          .setEndDate(endDate.toDate());
      // Only API levels 19 and above allow specifying RSA key parameters.
      if (VERSION.SDK_INT >= VERSION_CODES.KITKAT) {
        specBuilder.setAlgorithmParameterSpec(rsaSpec);
        specBuilder.setKeySize(KEY_SIZE);
      }
      if (isAuth) {
        specBuilder.setEncryptionRequired();
      }
      spec = specBuilder.build();
    }

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_ANDROID);
    keyPairGenerator.initialize(spec);
    keyPairGenerator.generateKeyPair();
  }

  static PublicKey getPublicKey(KeyStore keyStore, String keychainId, boolean isAuth)
      throws NoSuchKeyException, KeyStoreException {
    String alias = toKeyAlias(keychainId, isAuth);
    checkKeyExists(keyStore, alias);
    return keyStore.getCertificate(alias).getPublicKey();
  }

  static PrivateKey getPrivateKey(KeyStore keyStore, String keychainId, boolean isAuth)
      throws UnrecoverableKeyException,
      NoSuchAlgorithmException,
      KeyStoreException,
      NoSuchKeyException {
    String alias = toKeyAlias(keychainId, isAuth);
    checkKeyExists(keyStore, alias);
    return (PrivateKey) keyStore.getKey(alias, null);
  }

  static void deleteKeyPair(KeyStore keyStore, String keychainId, boolean isAuth)
      throws NoSuchKeyException, KeyStoreException {
    String alias = toKeyAlias(keychainId, isAuth);
    checkKeyExists(keyStore, alias);
    keyStore.deleteEntry(alias);
  }

  private static String toKeyAlias(String keychainId, boolean isAuth) {
    String suffix = isAuth ? AUTH_KEY_ALIAS_SUFFIX : NO_AUTH_KEY_ALIAS_SUFFIX;
    return keychainId + suffix;
  }

  static void checkKeyExists(KeyStore keyStore, String keychainId, boolean isAuth)
      throws NoSuchKeyException, KeyStoreException {
    checkKeyExists(keyStore, toKeyAlias(keychainId, isAuth));
  }

  private static void checkKeyExists(KeyStore keyStore, String alias)
      throws NoSuchKeyException, KeyStoreException {
    if (!keyStore.containsAlias(alias)) {
      throw new NoSuchKeyException("android key store has no rsa key pair with alias " + alias);
    }
  }

  static Padding getCompatibleRsaPadding() {
    return VERSION.SDK_INT >= VERSION_CODES.M ? Padding.OAEP : Padding.PKCS1;
  }
}
