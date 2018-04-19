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

import com.google.capillary.RsaEcdsaConstants.Padding;
import com.google.crypto.tink.subtle.Random;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class HybridRsaUtilsTest {

  /**
   * Creates a new {@link HybridRsaUtilsTest} instance.
   */
  public HybridRsaUtilsTest() throws GeneralSecurityException {
    Config.initialize();
  }

  @Test
  public void testEncryptDecrypt() throws GeneralSecurityException, IOException {
    PublicKey publicKey = TestUtils.createTestRsaPublicKey();
    PrivateKey privateKey = TestUtils.createTestRsaPrivateKey();

    // Try Encryption/Decryption for each padding mode.
    for (Padding padding : Padding.values()) {
      // Try Encryption/Decryption for plaintext sizes 64, 128, 256, 512, and 1048 bytes.
      for (int plaintextSize : new int[]{64, 128, 256, 512, 1048}) {
        byte[] plaintext = Random.randBytes(plaintextSize);
        byte[] ciphertext = HybridRsaUtils.encrypt(
            plaintext, publicKey, padding, RsaEcdsaConstants.OAEP_PARAMETER_SPEC);
        byte[] decryptedPlaintext = HybridRsaUtils.decrypt(
            ciphertext, privateKey, padding, RsaEcdsaConstants.OAEP_PARAMETER_SPEC);
        assertArrayEquals(plaintext, decryptedPlaintext);
      }
    }
  }
}
