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

import com.google.capillary.internal.WrappedWebPushPublicKey;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class WebPushEncrypterManagerTest {

  private WebPushEncrypterManager encrypterManager;

  /**
   * Creates a new {@link WebPushEncrypterManagerTest} instance.
   */
  public WebPushEncrypterManagerTest() throws GeneralSecurityException {
    Config.initialize();
  }

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() throws IOException, GeneralSecurityException {
    encrypterManager = new WebPushEncrypterManager();
  }

  @Test
  public void stub() {
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
    byte[] authSecret = Random.randBytes(16);
    byte[] ecPublicKeyBytes = TestUtils.getBytes("ec_public_key.dat");
    byte[] rawPublicKey = WrappedWebPushPublicKey.newBuilder()
        .setAuthSecret(ByteString.copyFrom(authSecret))
        .setKeyBytes(ByteString.copyFrom(ecPublicKeyBytes))
        .build().toByteArray();

    encrypterManager.rawLoadPublicKey(rawPublicKey);
  }
}
