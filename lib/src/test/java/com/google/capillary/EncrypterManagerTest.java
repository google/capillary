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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.capillary.internal.CapillaryCiphertext;
import com.google.capillary.internal.CapillaryPublicKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class EncrypterManagerTest {

  private static final String MOCK_CIPHERTEXT = "mock ciphertext";
  private static final String PLAINTEXT = "plaintext";

  private final CapillaryPublicKey publicKey = CapillaryPublicKey.newBuilder()
      .setKeychainUniqueId("demo_keychain")
      .setSerialNumber(22)
      .setIsAuth(true)
      .build();

  private EncrypterManager encrypterManager;

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() {
    encrypterManager = new EncrypterManager() {
      @Override
      HybridEncrypt rawLoadPublicKey(byte[] rawPublicKey) throws GeneralSecurityException {
        return (plaintext, contextInfo) -> MOCK_CIPHERTEXT.getBytes();
      }
    };
  }

  @Test
  public void testLoadValidPublicKey() throws GeneralSecurityException {
    encrypterManager.loadPublicKey(publicKey.toByteArray());
  }

  @Test
  public void testLoadMalformedPublicKey() {
    byte[] publicKey = "malformed public key".getBytes();

    try {
      encrypterManager.loadPublicKey(publicKey);
      fail("Did not throw GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // This is expected.
    }
  }

  @Test
  public void testClearPublicKey() throws GeneralSecurityException {
    encrypterManager.loadPublicKey(publicKey.toByteArray());

    encrypterManager.clearPublicKey();
  }

  @Test
  public void testEncryptionWithPublicKey()
      throws GeneralSecurityException, InvalidProtocolBufferException {
    encrypterManager.loadPublicKey(publicKey.toByteArray());

    byte[] capillaryCipher = encrypterManager.encrypt(PLAINTEXT.getBytes());

    CapillaryCiphertext capillaryCipherParsed = CapillaryCiphertext.parseFrom(capillaryCipher);
    assertEquals(publicKey.getKeychainUniqueId(), capillaryCipherParsed.getKeychainUniqueId());
    assertEquals(publicKey.getSerialNumber(), capillaryCipherParsed.getKeySerialNumber());
    assertEquals(publicKey.getIsAuth(), capillaryCipherParsed.getIsAuthKey());
    assertArrayEquals(
        MOCK_CIPHERTEXT.getBytes(), capillaryCipherParsed.getCiphertext().toByteArray());
  }

  @Test
  public void testEncryptionWithNoPublicKey() {
    try {
      encrypterManager.encrypt(PLAINTEXT.getBytes());
      fail("Did not throw GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // This is expected.
    }
  }

  @Test
  public void testEncryptionWithUnloadedPublicKey() throws GeneralSecurityException {
    encrypterManager.loadPublicKey(publicKey.toByteArray());
    encrypterManager.clearPublicKey();

    try {
      encrypterManager.encrypt(PLAINTEXT.getBytes());
      fail("Did not throw GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // This is expected.
    }
  }
}
