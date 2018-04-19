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
import com.google.capillary.internal.WrappedRsaEcdsaPublicKey;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaEcdsaEncrypterManagerTest {

  private RsaEcdsaEncrypterManager encrypterManager;

  /**
   * Creates a new {@link RsaEcdsaEncrypterManagerTest} instance.
   */
  public RsaEcdsaEncrypterManagerTest() throws GeneralSecurityException {
    Config.initialize();
  }

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() throws IOException, GeneralSecurityException {
    try (InputStream senderSigner =
        RsaEcdsaEncrypterManagerTest.class.getResourceAsStream("signing_key.dat")) {
      encrypterManager = new RsaEcdsaEncrypterManager(senderSigner);
    }
  }

  @Test
  public void testLoadMalformedRawPublicKey() {
    byte[] rawPublicKey = "malformed raw public key".getBytes();

    try {
      encrypterManager.rawLoadPublicKey(rawPublicKey);
      fail("Did not throw GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // This is expected.
    }
  }

  @Test
  public void testLoadValidRawPublicKey() throws IOException, GeneralSecurityException {
    byte[] testRsaPublicKey = TestUtils.getBytes("rsa_public_key.dat");
    byte[] rawPublicKey = WrappedRsaEcdsaPublicKey.newBuilder()
        .setPadding(Padding.OAEP.name())
        .setKeyBytes(ByteString.copyFrom(testRsaPublicKey))
        .build().toByteArray();

    encrypterManager.rawLoadPublicKey(rawPublicKey);
  }
}
