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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import com.google.capillary.AuthModeUnavailableException;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.internal.CapillaryPublicKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class KeyManagerAbstractAndroidTest {

  private static final String PUBLIC_KEY_AUTH = "public key auth";
  private static final String PUBLIC_KEY_NO_AUTH = "public key no auth";

  private Context context;
  private KeyManager keyManager;
  private String keyManagerUniqueId;
  private int noAuthKeySerialNumber;
  private int authKeySerialNumber;

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp()
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException,
      InvalidProtocolBufferException {
    context = InstrumentationRegistry.getTargetContext();
    keyManager = createTestKeyManager(context, "keychain 1");
    keyManagerUniqueId = keyManager.getKeychainUniqueId();
    // Generate key pair and get current key serial numbers.
    keyManager.generateKeyPair(false);
    keyManager.generateKeyPair(true);
    noAuthKeySerialNumber = getKeySerialNumber(keyManager.getPublicKey(false));
    authKeySerialNumber = getKeySerialNumber(keyManager.getPublicKey(true));
  }

  private static KeyManager createTestKeyManager(Context context, String keychainId) {
    return new KeyManager(context, Utils.getInstance(), keychainId) {
      @Override
      void rawGenerateKeyPair(boolean isAuth) throws GeneralSecurityException {
      }

      @Override
      byte[] rawGetPublicKey(boolean isAuth) throws NoSuchKeyException, GeneralSecurityException {
        return isAuth ? PUBLIC_KEY_AUTH.getBytes() : PUBLIC_KEY_NO_AUTH.getBytes();
      }

      @Override
      HybridDecrypt rawGetDecrypter(boolean isAuth)
          throws NoSuchKeyException, GeneralSecurityException {
        return null;
      }

      @Override
      void rawDeleteKeyPair(boolean isAuth) throws NoSuchKeyException, GeneralSecurityException {
      }
    };
  }

  @Test
  public void testDecrypterManagerSingleton() {
    DecrypterManager decrypterManager1 = keyManager.getDecrypterManager();
    DecrypterManager decrypterManager2 = keyManager.getDecrypterManager();

    assertEquals(decrypterManager1, decrypterManager2);
  }

  @Test
  public void testMultipleKeychainIds() {
    String keychainId1 = "keychain id 1";
    String keychainId2 = "keychain id 2";
    KeyManager keyManager1a = createTestKeyManager(context, keychainId1);
    KeyManager keyManager1b = createTestKeyManager(context, keychainId1);
    KeyManager keyManager2 = createTestKeyManager(context, keychainId2);

    // Same keychain IDs should have same unique ID.
    assertEquals(keyManager1a.getKeychainUniqueId(), keyManager1b.getKeychainUniqueId());
    // Different keychain IDs should have different unique IDs.
    assertNotEquals(keyManager1a.getKeychainUniqueId(), keyManager2.getKeychainUniqueId());
  }

  private static int getKeySerialNumber(byte[] publicKeyBytes)
      throws InvalidProtocolBufferException {
    CapillaryPublicKey publicKey = CapillaryPublicKey.parseFrom(publicKeyBytes);
    return publicKey.getSerialNumber();
  }

  // Must be run on a device with a screen lock enabled and unlocked.
  @Test
  public void testGenerateKey()
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException,
      InvalidProtocolBufferException {
    // Newly generated key pair should increment key serial numbers.
    keyManager.generateKeyPair(false);
    assertEquals(noAuthKeySerialNumber + 1, getKeySerialNumber(keyManager.getPublicKey(false)));
    assertEquals(authKeySerialNumber, getKeySerialNumber(keyManager.getPublicKey(true)));
    keyManager.generateKeyPair(true);
    assertEquals(noAuthKeySerialNumber + 1, getKeySerialNumber(keyManager.getPublicKey(false)));
    assertEquals(authKeySerialNumber + 1, getKeySerialNumber(keyManager.getPublicKey(true)));
  }

  @Test
  public void testGenerateKeyWithSerialNumber()
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException,
      InvalidProtocolBufferException {
    // Older serial numbers shouldn't generate keys.
    assertFalse(keyManager.generateKeyPair(noAuthKeySerialNumber, false));
    assertEquals(noAuthKeySerialNumber, getKeySerialNumber(keyManager.getPublicKey(false)));
    assertFalse(keyManager.generateKeyPair(noAuthKeySerialNumber - 1, false));
    assertEquals(noAuthKeySerialNumber, getKeySerialNumber(keyManager.getPublicKey(false)));
    assertFalse(keyManager.generateKeyPair(authKeySerialNumber, true));
    assertEquals(authKeySerialNumber, getKeySerialNumber(keyManager.getPublicKey(true)));
    assertFalse(keyManager.generateKeyPair(authKeySerialNumber - 1, true));
    assertEquals(authKeySerialNumber, getKeySerialNumber(keyManager.getPublicKey(true)));

    // New serial numbers should generate keys.
    assertTrue(keyManager.generateKeyPair(noAuthKeySerialNumber + 1, false));
    assertEquals(noAuthKeySerialNumber + 1, getKeySerialNumber(keyManager.getPublicKey(false)));
    assertTrue(keyManager.generateKeyPair(authKeySerialNumber + 1, true));
    assertEquals(authKeySerialNumber + 1, getKeySerialNumber(keyManager.getPublicKey(true)));
  }

  @Test
  public void testGetPublicKey()
      throws NoSuchKeyException,
      GeneralSecurityException,
      AuthModeUnavailableException,
      InvalidProtocolBufferException {
    CapillaryPublicKey noAuthPk = CapillaryPublicKey.parseFrom(keyManager.getPublicKey(false));
    CapillaryPublicKey authPk = CapillaryPublicKey.parseFrom(keyManager.getPublicKey(true));

    // Check if the key parameters are correctly set.
    assertEquals(keyManagerUniqueId, noAuthPk.getKeychainUniqueId());
    assertEquals(keyManagerUniqueId, authPk.getKeychainUniqueId());
    assertEquals(noAuthKeySerialNumber, noAuthPk.getSerialNumber());
    assertEquals(authKeySerialNumber, authPk.getSerialNumber());
    assertFalse(noAuthPk.getIsAuth());
    assertTrue(authPk.getIsAuth());
    assertArrayEquals(PUBLIC_KEY_NO_AUTH.getBytes(), noAuthPk.getKeyBytes().toByteArray());
    assertArrayEquals(PUBLIC_KEY_AUTH.getBytes(), authPk.getKeyBytes().toByteArray());
  }

  @Test
  public void testGetDecrypter()
      throws GeneralSecurityException, AuthModeUnavailableException, NoSuchKeyException {
    // Invalid key manager unique ID.
    try {
      keyManager.getDecrypter("invalid id", noAuthKeySerialNumber, false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    // Invalid key serial number.
    try {
      keyManager.getDecrypter(keyManagerUniqueId, noAuthKeySerialNumber + 1, false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    try {
      keyManager.getDecrypter(keyManagerUniqueId, noAuthKeySerialNumber - 1, false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    // Matching key manager unique ID and key serial number.
    keyManager.getDecrypter(keyManagerUniqueId, noAuthKeySerialNumber, false);
  }

  @Test
  public void testDeleteKey()
      throws GeneralSecurityException,
      AuthModeUnavailableException,
      NoSuchKeyException,
      InvalidProtocolBufferException {
    // Key deletions shouldn't reset key serial numbers.
    keyManager.deleteKeyPair(false);
    keyManager.deleteKeyPair(true);

    keyManager.generateKeyPair(false);
    keyManager.generateKeyPair(true);

    assertEquals(noAuthKeySerialNumber + 1, getKeySerialNumber(keyManager.getPublicKey(false)));
    assertEquals(authKeySerialNumber + 1, getKeySerialNumber(keyManager.getPublicKey(true)));
  }
}
