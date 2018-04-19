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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;
import com.google.capillary.AuthModeUnavailableException;
import com.google.capillary.Config;
import com.google.capillary.EncrypterManager;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.RsaEcdsaEncrypterManager;
import com.google.capillary.WebPushEncrypterManager;
import com.google.capillary.android.TestHandler.AuthCiphertextSavedForLaterRequest;
import com.google.capillary.android.TestHandler.ErrorRequest;
import com.google.capillary.android.TestHandler.HandleDataRequest;
import com.google.capillary.android.TestHandler.HandlePublicKeyRequest;
import com.google.capillary.internal.CapillaryCiphertext;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class IntegrationTest {

  private static final String TAG = IntegrationTest.class.getSimpleName();
  private static final int USER_REQUEST_DURATION_SECONDS = 10;
  private static final String KEYCHAIN_ID = "keychain 1";

  private EncrypterManager rsaEcdsaEncrypterManager;
  private WebPushEncrypterManager webPushEncrypterManager;
  private KeyManager rsaEcdsaKeyManager;
  private KeyManager webPushKeyManager;

  /**
   * Creates a new {@link IntegrationTest} instance.
   */
  public IntegrationTest() throws GeneralSecurityException {
    Config.initialize();
  }

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() throws GeneralSecurityException, IOException {
    Context context = InstrumentationRegistry.getTargetContext();
    try (InputStream senderSigningKey =
        IntegrationTest.class.getResourceAsStream("signing_key.dat")) {
      rsaEcdsaEncrypterManager = new RsaEcdsaEncrypterManager(senderSigningKey);
    }
    try (InputStream senderVerificationKey =
        IntegrationTest.class.getResourceAsStream("verification_key.dat")) {
      rsaEcdsaKeyManager =
          RsaEcdsaKeyManager.getInstance(context, KEYCHAIN_ID, senderVerificationKey);
    }
    webPushEncrypterManager = new WebPushEncrypterManager();
    webPushKeyManager = WebPushKeyManager.getInstance(context, KEYCHAIN_ID);
    TestUtils.clearKeyStore();
  }

  @Test
  public void testRsaEcdsaKeyGenEncryptDecrypt()
      throws NoSuchKeyException,
      GeneralSecurityException,
      AuthModeUnavailableException {
    testKeyGenEncryptDecrypt(rsaEcdsaEncrypterManager, rsaEcdsaKeyManager, false);
    testKeyGenEncryptDecrypt(rsaEcdsaEncrypterManager, rsaEcdsaKeyManager, true);
  }

  @Test
  public void testWebPushKeyGenEncryptDecrypt()
      throws NoSuchKeyException,
      GeneralSecurityException,
      AuthModeUnavailableException {
    testKeyGenEncryptDecrypt(webPushEncrypterManager, webPushKeyManager, false);
    testKeyGenEncryptDecrypt(webPushEncrypterManager, webPushKeyManager, true);
  }

  private void testKeyGenEncryptDecrypt(
      EncrypterManager encrypterManager,
      KeyManager keyManager,
      boolean isAuth)
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException {
    TestHandler handler = new TestHandler();
    Object extra = new Object();
    final byte[] plaintext = "plaintext".getBytes();

    // Generate key pair.
    keyManager.generateKeyPair(isAuth);

    // Get public key.
    keyManager.getPublicKey(isAuth, handler, extra);
    assertEquals(1, handler.handlePublicKeyRequests.size());
    HandlePublicKeyRequest handlePublicKeyRequest1 = handler.handlePublicKeyRequests.get(0);
    assertEquals(isAuth, handlePublicKeyRequest1.isAuthKey);
    assertNull(handlePublicKeyRequest1.ciphertext);
    assertEquals(extra, handlePublicKeyRequest1.extra);
    byte[] publicKey = handlePublicKeyRequest1.publicKey;
    handler.reset();

    // Prepare ciphertext.
    encrypterManager.loadPublicKey(publicKey);
    byte[] ciphertext = encrypterManager.encrypt(plaintext);
    encrypterManager.clearPublicKey();

    // Try to decrypt.
    keyManager.getDecrypterManager().decrypt(ciphertext, handler, extra);
    assertEquals(1, handler.handleDataRequests.size());
    HandleDataRequest handleDataRequestWant = new HandleDataRequest(isAuth, plaintext, extra);
    HandleDataRequest handleDataRequestGot = handler.handleDataRequests.get(0);
    assertEquals(handleDataRequestWant, handleDataRequestGot);
    handler.reset();
  }

  @Test
  public void testRsaEcdsaDecryptSaved()
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException,
      InterruptedException {
    testDecryptSaved(rsaEcdsaEncrypterManager, rsaEcdsaKeyManager);
  }

  @Test
  public void testWebPushDecryptSaved()
      throws InterruptedException,
      GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException {
    testDecryptSaved(webPushEncrypterManager, webPushKeyManager);
  }

  private void testDecryptSaved(
      EncrypterManager encrypterManager,
      KeyManager keyManager)
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException,
      InterruptedException {
    TestHandler handler = new TestHandler();
    Object extra = new Object();
    final List<byte[]> plaintexts =
        new LinkedList<>(Arrays.asList("plaintext 1".getBytes(), "plaintext 2".getBytes()));

    // Clear any saved ciphertexts.
    keyManager.getDecrypterManager().decryptSaved(handler, extra);
    handler.reset();

    // Generate key pair and prepare ciphertexts.
    keyManager.generateKeyPair(true);
    keyManager.getPublicKey(true, handler, extra);
    byte[] publicKey = handler.handlePublicKeyRequests.get(0).publicKey;
    encrypterManager.loadPublicKey(publicKey);
    List<byte[]> ciphertexts = new LinkedList<>();
    for (byte[] plaintext : plaintexts) {
      ciphertexts.add(encrypterManager.encrypt(plaintext));
    }

    // Request to lock screen.
    requestUser(String.format(
        Locale.ENGLISH,
        "testDecryptSaved: lock the device in %d seconds",
        USER_REQUEST_DURATION_SECONDS));

    // Try to decrypt in a locked device.
    for (byte[] ciphertext : ciphertexts) {
      keyManager.getDecrypterManager().decrypt(ciphertext, handler, extra);
      assertEquals(1, handler.authCiphertextSavedForLaterRequests.size());
      AuthCiphertextSavedForLaterRequest authCiphertextSavedForLaterRequestWant =
          new AuthCiphertextSavedForLaterRequest(ciphertext, extra);
      AuthCiphertextSavedForLaterRequest authCiphertextSavedForLaterRequestGot =
          handler.authCiphertextSavedForLaterRequests.get(0);
      assertEquals(authCiphertextSavedForLaterRequestWant, authCiphertextSavedForLaterRequestGot);
      handler.reset();
    }

    // Try to decrypt saved ciphertexts in an locked device.
    keyManager.getDecrypterManager().decryptSaved(handler, extra);
    assertEquals(2, handler.authCiphertextSavedForLaterRequests.size());
    for (int i = 0; i < ciphertexts.size(); i++) {
      AuthCiphertextSavedForLaterRequest authCiphertextSavedForLaterRequestWant =
          new AuthCiphertextSavedForLaterRequest(ciphertexts.get(i), extra);
      AuthCiphertextSavedForLaterRequest authCiphertextSavedForLaterRequestGot =
          handler.authCiphertextSavedForLaterRequests.get(i);
      assertEquals(authCiphertextSavedForLaterRequestWant, authCiphertextSavedForLaterRequestGot);
    }
    handler.reset();

    // Request to unlock screen.
    requestUser(String.format(
        Locale.ENGLISH,
        "testDecryptSaved: unlock the device in %d seconds",
        USER_REQUEST_DURATION_SECONDS));

    // Try to decrypt saved ciphertexts in an unlocked device.
    keyManager.getDecrypterManager().decryptSaved(handler, extra);
    assertEquals(2, handler.handleDataRequests.size());
    for (int i = 0; i < plaintexts.size(); i++) {
      HandleDataRequest handleDataRequestWant =
          new HandleDataRequest(true, plaintexts.get(i), extra);
      HandleDataRequest handleDataRequestGot = handler.handleDataRequests.get(i);
      assertEquals(handleDataRequestWant, handleDataRequestGot);
    }
    handler.reset();
  }

  private void requestUser(String msg) throws InterruptedException {
    Log.i(TAG, msg);
    for (int i = USER_REQUEST_DURATION_SECONDS; i > 0; i--) {
      TimeUnit.SECONDS.sleep(1);
      Log.i(TAG, String.format("%d...", i));
    }
  }

  @Test
  public void testRsaEcdsaKeyReGeneration()
      throws NoSuchKeyException,
      GeneralSecurityException,
      AuthModeUnavailableException,
      InvalidProtocolBufferException {
    testMissingKeyStoreKeys(rsaEcdsaEncrypterManager, rsaEcdsaKeyManager, false);
    testMissingKeyStoreKeys(rsaEcdsaEncrypterManager, rsaEcdsaKeyManager, true);
    testAppDataReset(rsaEcdsaEncrypterManager, rsaEcdsaKeyManager, false);
    testAppDataReset(rsaEcdsaEncrypterManager, rsaEcdsaKeyManager, true);
  }

  @Test
  public void testWebPushKeyReGeneration()
      throws NoSuchKeyException,
      GeneralSecurityException,
      AuthModeUnavailableException,
      InvalidProtocolBufferException {
    testMissingKeyStoreKeys(webPushEncrypterManager, webPushKeyManager, false);
    testMissingKeyStoreKeys(webPushEncrypterManager, webPushKeyManager, true);
    testAppDataReset(webPushEncrypterManager, webPushKeyManager, false);
    testAppDataReset(webPushEncrypterManager, webPushKeyManager, true);
  }

  private void testMissingKeyStoreKeys(
      EncrypterManager encrypterManager,
      KeyManager keyManager,
      boolean isAuth)
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException {
    TestHandler handler = new TestHandler();
    Object extra = new Object();
    final byte[] plaintext = "plaintext".getBytes();

    // Generate key pair and prepare ciphertext.
    keyManager.generateKeyPair(isAuth);
    keyManager.getPublicKey(isAuth, handler, extra);
    byte[] publicKey = handler.handlePublicKeyRequests.get(0).publicKey;
    encrypterManager.loadPublicKey(publicKey);
    final byte[] ciphertext1 = encrypterManager.encrypt(plaintext);
    encrypterManager.clearPublicKey();
    handler.reset();

    // Delete key.
    keyManager.deleteKeyPair(isAuth);

    // Try to decrypt ciphertext.
    keyManager.getDecrypterManager().decrypt(ciphertext1, handler, extra);
    // Decryption must have failed.
    assertEquals(0, handler.handleDataRequests.size());
    // A new key must have been generated.
    assertEquals(1, handler.handlePublicKeyRequests.size());
    HandlePublicKeyRequest handlePublicKeyRequest = handler.handlePublicKeyRequests.get(0);
    assertEquals(isAuth, handlePublicKeyRequest.isAuthKey);
    assertArrayEquals(ciphertext1, handlePublicKeyRequest.ciphertext);
    assertEquals(extra, handlePublicKeyRequest.extra);
    handler.reset();

    // Try to decrypt a ciphertext generated with the old public key.
    encrypterManager.loadPublicKey(publicKey);
    final byte[] ciphertext2 = encrypterManager.encrypt(plaintext);
    encrypterManager.clearPublicKey();
    keyManager.getDecrypterManager().decrypt(ciphertext2, handler, extra);
    // Decryption must have failed.
    assertEquals(0, handler.handleDataRequests.size());
    // No new key must have been generated.
    assertEquals(0, handler.handlePublicKeyRequests.size());
    // A stale ciphertext error must have been received.
    assertEquals(1, handler.errorRequests.size());
    ErrorRequest errorRequestWant =
        new ErrorRequest(CapillaryHandlerErrorCode.STALE_CIPHERTEXT, ciphertext2, extra);
    ErrorRequest errorRequestGot = handler.errorRequests.get(0);
    assertEquals(errorRequestGot, errorRequestWant);
    handler.reset();
  }

  private void testAppDataReset(
      EncrypterManager encrypterManager,
      KeyManager keyManager,
      boolean isAuth)
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException,
      InvalidProtocolBufferException {
    TestHandler handler = new TestHandler();
    Object extra = new Object();
    final byte[] plaintext = "plaintext".getBytes();

    // Generate key pair and prepare ciphertext.
    keyManager.generateKeyPair(isAuth);
    keyManager.getPublicKey(isAuth, handler, extra);
    byte[] publicKey = handler.handlePublicKeyRequests.get(0).publicKey;
    encrypterManager.loadPublicKey(publicKey);
    byte[] ciphertext = encrypterManager.encrypt(plaintext);
    encrypterManager.clearPublicKey();
    handler.reset();

    // Emulate app data reset by changing key manager unique ID in the ciphertext.
    ciphertext = CapillaryCiphertext.parseFrom(ciphertext).toBuilder()
        .setKeychainUniqueId("some other unique ID").build().toByteArray();

    // Try to decrypt emulated ciphertext
    keyManager.getDecrypterManager().decrypt(ciphertext, handler, extra);
    // Decryption must have failed.
    assertEquals(0, handler.handleDataRequests.size());
    // A new key must have been generated.
    assertEquals(1, handler.handlePublicKeyRequests.size());
    HandlePublicKeyRequest handlePublicKeyRequest = handler.handlePublicKeyRequests.get(0);
    assertEquals(isAuth, handlePublicKeyRequest.isAuthKey);
    assertArrayEquals(ciphertext, handlePublicKeyRequest.ciphertext);
    assertEquals(extra, handlePublicKeyRequest.extra);
    handler.reset();
  }
}
