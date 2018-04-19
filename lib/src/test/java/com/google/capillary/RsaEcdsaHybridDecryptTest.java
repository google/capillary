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
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaEcdsaHybridDecryptTest {

  private final PublicKeySign senderSigner;
  private final PublicKeyVerify senderVerifier;
  private final PublicKey recipientPublicKey;
  private final PrivateKey recipientPrivateKey;

  /**
   * Creates a new {@link RsaEcdsaHybridDecryptTest} instance.
   */
  public RsaEcdsaHybridDecryptTest() throws GeneralSecurityException, IOException {
    Config.initialize();
    senderSigner = TestUtils.createTestSenderSigner();
    senderVerifier = TestUtils.createTestSenderVerifier();
    recipientPublicKey = TestUtils.createTestRsaPublicKey();
    recipientPrivateKey = TestUtils.createTestRsaPrivateKey();
  }

  @Test
  public void testModifyCiphertext() throws GeneralSecurityException {
    byte[] plaintext = Random.randBytes(20);

    // Try Encryption/Decryption for each padding mode.
    for (Padding padding : Padding.values()) {
      HybridEncrypt hybridEncrypt = new RsaEcdsaHybridEncrypt.Builder()
          .withSenderSigner(senderSigner)
          .withRecipientPublicKey(recipientPublicKey)
          .withPadding(padding)
          .build();
      HybridDecrypt hybridDecrypt = new RsaEcdsaHybridDecrypt.Builder()
          .withSenderVerifier(senderVerifier)
          .withRecipientPrivateKey(recipientPrivateKey)
          .withPadding(padding)
          .build();
      byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null);

      // Flip bits.
      for (int b = 0; b < ciphertext.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
          modified[b] = (byte) (modified[b] ^ (1 << bit));
          try {
            hybridDecrypt.decrypt(modified, null);
            // 3rd and 5th bytes of tink ECDSA signatures are malleable.
            int tinkSignatureBytePos = b - RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH + 1;
            if (tinkSignatureBytePos == 3 || tinkSignatureBytePos == 5) {
              continue;
            }
            fail("Decrypting modified ciphertext should fail.");
          } catch (GeneralSecurityException ex) {
            // This is expected.
          }
        }
      }

      // Truncate ciphertext.
      for (int length = 0; length < ciphertext.length; length++) {
        byte[] modified = Arrays.copyOf(ciphertext, length);
        try {
          hybridDecrypt.decrypt(modified, null);
          fail("Decrypting modified ciphertext should fail");
        } catch (GeneralSecurityException ex) {
          // This is expected.
        }
      }
    }
  }

  @Test
  public void testNonNullContextInfo() throws GeneralSecurityException {
    HybridEncrypt hybridEncrypt = new RsaEcdsaHybridEncrypt.Builder()
        .withSenderSigner(senderSigner)
        .withRecipientPublicKey(recipientPublicKey)
        .withPadding(Padding.PKCS1)
        .build();
    HybridDecrypt hybridDecrypt = new RsaEcdsaHybridDecrypt.Builder()
        .withSenderVerifier(senderVerifier)
        .withRecipientPrivateKey(recipientPrivateKey)
        .withPadding(Padding.PKCS1)
        .build();

    byte[] plaintext = Random.randBytes(20);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null);
    byte[] contextInfo = new byte[0];

    try {
      hybridDecrypt.decrypt(ciphertext, contextInfo);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException ex) {
      // This is expected.
    }
  }
}
