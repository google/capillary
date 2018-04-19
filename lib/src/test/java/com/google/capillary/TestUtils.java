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

import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

final class TestUtils {

  static PublicKeySign createTestSenderSigner()
      throws GeneralSecurityException, IOException {
    KeysetHandle signingKeyHandle = CleartextKeysetHandle
        .read(BinaryKeysetReader.withBytes(TestUtils.getBytes("signing_key.dat")));
    return PublicKeySignFactory.getPrimitive(signingKeyHandle);
  }

  static PublicKeyVerify createTestSenderVerifier()
      throws GeneralSecurityException, IOException {
    KeysetHandle verificationKeyHandle = CleartextKeysetHandle
        .read(BinaryKeysetReader.withBytes(TestUtils.getBytes("verification_key.dat")));
    return PublicKeyVerifyFactory.getPrimitive(verificationKeyHandle);
  }

  static PublicKey createTestRsaPublicKey()
      throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
    return KeyFactory.getInstance("RSA").generatePublic(
        new X509EncodedKeySpec(TestUtils.getBytes("rsa_public_key.dat")));
  }

  static PrivateKey createTestRsaPrivateKey()
      throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
    return KeyFactory.getInstance("RSA").generatePrivate(
        new PKCS8EncodedKeySpec(TestUtils.getBytes("rsa_private_key.dat")));
  }

  static byte[] getBytes(String fileName) throws IOException {
    InputStream in = null;
    try {
      in = TestUtils.class.getResourceAsStream(fileName);
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      byte[] buf = new byte[1024];
      int nread;
      while ((nread = in.read(buf)) > 0) {
        bout.write(buf, 0, nread);
      }
      bout.close();
      return bout.toByteArray();
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (IOException expected) {
          // This is expected.
        }
      }
    }
  }
}
