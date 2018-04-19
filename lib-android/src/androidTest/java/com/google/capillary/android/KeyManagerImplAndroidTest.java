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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import com.google.capillary.Config;
import com.google.capillary.NoSuchKeyException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class KeyManagerImplAndroidTest {

  private static final String KEYCHAIN_ID = "keychain 1";

  private Context context;
  private KeyManager rsaEcdsaKeyManager;
  private KeyManager webPushKeyManager;

  /**
   * Creates a new {@link KeyManagerImplAndroidTest} instance.
   */
  public KeyManagerImplAndroidTest() throws GeneralSecurityException {
    Config.initialize();
  }

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() throws GeneralSecurityException, IOException {
    context = InstrumentationRegistry.getTargetContext();
    try (InputStream senderVerificationKey =
        IntegrationTest.class.getResourceAsStream("verification_key.dat")) {
      rsaEcdsaKeyManager =
          RsaEcdsaKeyManager.getInstance(context, KEYCHAIN_ID, senderVerificationKey);
    }
    webPushKeyManager = WebPushKeyManager.getInstance(context, KEYCHAIN_ID);
    TestUtils.clearKeyStore();
  }

  @Test
  public void testRsaEcdsaGenerateKeys() throws GeneralSecurityException {
    testGenerateKeys(rsaEcdsaKeyManager);
  }

  @Test
  public void testWebPushGenerateKeys() throws GeneralSecurityException {
    testGenerateKeys(webPushKeyManager);
  }

  private void testGenerateKeys(KeyManager keyManager) throws GeneralSecurityException {
    KeyStore keyStore = Utils.getInstance().loadKeyStore();

    assertEquals(0, keyStore.size());

    keyManager.rawGenerateKeyPair(true);
    keyManager.rawGenerateKeyPair(false);

    assertEquals(2, keyStore.size());
  }

  @Test
  public void testRsaEcdsaGetPublicKey() throws GeneralSecurityException, NoSuchKeyException {
    testGetPublicKey(rsaEcdsaKeyManager);
  }

  @Test
  public void testWebPushGetPublicKey() throws GeneralSecurityException, NoSuchKeyException {
    testGetPublicKey(webPushKeyManager);
  }

  private void testGetPublicKey(KeyManager keyManager)
      throws GeneralSecurityException, NoSuchKeyException {
    try {
      keyManager.rawGetPublicKey(false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    keyManager.rawGenerateKeyPair(false);

    assertNotNull(keyManager.rawGetPublicKey(false));
  }

  @Test
  public void testRsaEcdsaGetDecrypter() throws GeneralSecurityException, NoSuchKeyException {
    testGetDecrypter(rsaEcdsaKeyManager);
  }

  @Test
  public void testWebPushGetDecrypter() throws GeneralSecurityException, NoSuchKeyException {
    testGetDecrypter(webPushKeyManager);
  }

  private void testGetDecrypter(KeyManager keyManager)
      throws GeneralSecurityException, NoSuchKeyException {
    try {
      keyManager.rawGetDecrypter(false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    keyManager.rawGenerateKeyPair(false);

    assertNotNull(keyManager.rawGetDecrypter(false));
  }

  @Test
  public void testRsaEcdsaDeleteKey() throws GeneralSecurityException, NoSuchKeyException {
    testDeleteKey(rsaEcdsaKeyManager);
  }

  @Test
  public void testWebPushDeleteKey() throws GeneralSecurityException, NoSuchKeyException {
    testDeleteKey(webPushKeyManager);
  }

  private void testDeleteKey(KeyManager keyManager)
      throws GeneralSecurityException, NoSuchKeyException {
    try {
      keyManager.rawDeleteKeyPair(false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    keyManager.rawGenerateKeyPair(false);

    keyManager.rawDeleteKeyPair(false);
  }

  @Test
  public void testRsaEcdsaMultipleInstances() throws GeneralSecurityException, IOException {
    KeyManager rsaEcdsaKeyManagerSecond;
    try (InputStream senderVerificationKey =
        IntegrationTest.class.getResourceAsStream("verification_key.dat")) {
      rsaEcdsaKeyManagerSecond =
          RsaEcdsaKeyManager.getInstance(context, KEYCHAIN_ID, senderVerificationKey);
    }

    // Only 1 instance should exist per keychain ID.
    assertEquals(rsaEcdsaKeyManager, rsaEcdsaKeyManagerSecond);
  }

  @Test
  public void testWebPushMultipleInstances() throws GeneralSecurityException {
    KeyManager webPushKeyManagerSecond = WebPushKeyManager.getInstance(context, KEYCHAIN_ID);

    // Only 1 instance should exist per keychain ID.
    assertEquals(webPushKeyManager, webPushKeyManagerSecond);
  }

  @Test
  public void testRsaEcdsaMultipleKeychainIds()
      throws GeneralSecurityException, IOException, NoSuchKeyException {
    KeyManager rsaEcdsaKeyManagerSecond;
    try (InputStream senderVerificationKey =
        IntegrationTest.class.getResourceAsStream("verification_key.dat")) {
      rsaEcdsaKeyManagerSecond =
          RsaEcdsaKeyManager.getInstance(context, "keychain 2", senderVerificationKey);
    }

    testMultipleKeychainIds(rsaEcdsaKeyManager, rsaEcdsaKeyManagerSecond);
  }

  @Test
  public void testWebPushMultipleKeychainIds() throws GeneralSecurityException, NoSuchKeyException {
    KeyManager webPushKeyManagerSecond = WebPushKeyManager.getInstance(context, "keychain 2");

    testMultipleKeychainIds(webPushKeyManager, webPushKeyManagerSecond);

  }

  private void testMultipleKeychainIds(KeyManager keyManager1, KeyManager keyManager2)
      throws GeneralSecurityException, NoSuchKeyException {
    // Key managers with difference keychain IDs should be distinct instances.
    assertNotEquals(keyManager1, keyManager2);

    // Generate key in keyManager1.
    keyManager1.rawGenerateKeyPair(false);

    // keyManager1 should have a key.
    assertNotNull(keyManager1.rawGetPublicKey(false));
    assertNotNull(keyManager1.rawGetDecrypter(false));

    // keyManager2 shouldn't have a key.
    try {
      keyManager2.rawGetPublicKey(false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }
    try {
      keyManager2.rawGetDecrypter(false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }
  }
}
