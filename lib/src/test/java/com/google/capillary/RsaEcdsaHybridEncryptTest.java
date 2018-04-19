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
import static org.junit.Assert.fail;

import com.google.capillary.RsaEcdsaConstants.Padding;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.subtle.Random;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaEcdsaHybridEncryptTest {

  private final PublicKeySign senderSigner;
  private final PublicKey recipientPublicKey;

  /**
   * Creates a new {@link RsaEcdsaHybridEncryptTest} instance.
   */
  public RsaEcdsaHybridEncryptTest() throws GeneralSecurityException, IOException {
    Config.initialize();
    senderSigner = TestUtils.createTestSenderSigner();
    recipientPublicKey = TestUtils.createTestRsaPublicKey();
  }

  @Test
  public void testEncryptDecrypt() throws IOException, GeneralSecurityException {
    PublicKeyVerify senderVerifier = TestUtils.createTestSenderVerifier();
    PrivateKey recipientPrivateKey = TestUtils.createTestRsaPrivateKey();

    // Try Encryption/Decryption for each padding mode.
    for (Padding padding : Padding.values()) {
      // Try Encryption/Decryption for plaintext sizes 64, 128, 256, 512, and 1048 bytes.
      for (int plaintextSize : new int[]{64, 128, 256, 512, 1048}) {
        byte[] plaintext = Random.randBytes(plaintextSize);
        HybridEncrypt hybridEncrypt = new RsaEcdsaHybridEncrypt.Builder()
            .withSenderSigner(senderSigner)
            .withRecipientPublicKey(recipientPublicKey)
            .withPadding(padding)
            .build();
        byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null);
        HybridDecrypt hybridDecrypt = new RsaEcdsaHybridDecrypt.Builder()
            .withSenderVerifier(senderVerifier)
            .withRecipientPrivateKey(recipientPrivateKey)
            .withPadding(padding)
            .build();
        byte[] decryptedPlaintext = hybridDecrypt.decrypt(ciphertext, null);
        assertArrayEquals(plaintext, decryptedPlaintext);
      }
    }
  }

  @Test
  public void testNonNullContextInfo() {
    HybridEncrypt hybridEncrypt = new RsaEcdsaHybridEncrypt.Builder()
        .withSenderSigner(senderSigner)
        .withRecipientPublicKey(recipientPublicKey)
        .withPadding(Padding.PKCS1)
        .build();

    byte[] plaintext = Random.randBytes(20);
    byte[] contextInfo = new byte[0];

    try {
      hybridEncrypt.encrypt(plaintext, contextInfo);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException ex) {
      // This is expected.
    }
  }
}
