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

import com.google.capillary.RsaEcdsaConstants.Padding;
import com.google.capillary.internal.HybridRsaCiphertext;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;

public final class HybridRsaUtils {

  private static final KeyTemplate SYMMETRIC_KEY_TEMPLATE = AeadKeyTemplates.AES128_GCM;
  private static final byte[] emptyEad = new byte[0];

  /**
   * Encrypts the given plaintext using RSA hybrid encryption.
   *
   * @param plaintext the plaintext to encrypt.
   * @param publicKey the RSA public key.
   * @param padding the RSA padding to use.
   * @param oaepParams the {@link OAEPParameterSpec} to use for OAEP padding.
   * @return the ciphertext.
   * @throws GeneralSecurityException if encryption fails.
   */
  public static byte[] encrypt(
      byte[] plaintext, PublicKey publicKey, Padding padding, OAEPParameterSpec oaepParams)
      throws GeneralSecurityException {
    // Initialize RSA encryption cipher.
    Cipher rsaCipher = Cipher.getInstance(padding.getTransformation());
    if (padding == Padding.OAEP) {
      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
    } else {
      rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
    }

    // Generate symmetric key and its ciphertext.
    KeysetHandle symmetricKeyHandle = KeysetHandle.generateNew(SYMMETRIC_KEY_TEMPLATE);
    ByteArrayOutputStream symmetricKeyOutputStream = new ByteArrayOutputStream();
    try {
      CleartextKeysetHandle.write(
          symmetricKeyHandle, BinaryKeysetWriter.withOutputStream(symmetricKeyOutputStream));
    } catch (IOException e) {
      throw new GeneralSecurityException("hybrid rsa encryption failed: ", e);
    }
    byte[] symmetricKeyBytes = symmetricKeyOutputStream.toByteArray();
    byte[] symmetricKeyCiphertext = rsaCipher.doFinal(symmetricKeyBytes);

    // Generate payload ciphertext.
    Aead aead = AeadFactory.getPrimitive(symmetricKeyHandle);
    byte[] payloadCiphertext = aead.encrypt(plaintext, emptyEad);

    return HybridRsaCiphertext.newBuilder()
        .setSymmetricKeyCiphertext(ByteString.copyFrom(symmetricKeyCiphertext))
        .setPayloadCiphertext(ByteString.copyFrom(payloadCiphertext))
        .build().toByteArray();
  }

  /**
   * Decrypts the given ciphertext using RSA hybrid decryption.
   *
   * @param ciphertext the ciphertext to decrypt.
   * @param privateKey the RSA private key.
   * @param padding the RSA padding to use.
   * @param oaepParams the {@link OAEPParameterSpec} to use for OAEP padding.
   * @return the plaintext.
   * @throws GeneralSecurityException if decryption fails.
   */
  public static byte[] decrypt(
      byte[] ciphertext, PrivateKey privateKey, Padding padding, OAEPParameterSpec oaepParams)
      throws GeneralSecurityException {
    // Parse encrypted payload bytes.
    HybridRsaCiphertext hybridRsaCiphertext;
    try {
      hybridRsaCiphertext = HybridRsaCiphertext.parseFrom(ciphertext);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("hybrid rsa decryption failed: ", e);
    }

    // Initialize RSA decryption cipher.
    Cipher rsaCipher = Cipher.getInstance(padding.getTransformation());
    if (padding == Padding.OAEP) {
      rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
    } else {
      rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    // Retrieve symmetric key.
    byte[] symmetricKeyCiphertext = hybridRsaCiphertext.getSymmetricKeyCiphertext().toByteArray();
    byte[] symmetricKeyBytes = rsaCipher.doFinal(symmetricKeyCiphertext);
    KeysetHandle symmetricKeyHandle;
    try {
      symmetricKeyHandle =
          CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(symmetricKeyBytes));
    } catch (IOException e) {
      throw new GeneralSecurityException("hybrid rsa decryption failed: ", e);
    }

    // Retrieve and return plaintext.
    Aead aead = AeadFactory.getPrimitive(symmetricKeyHandle);
    byte[] payloadCiphertext = hybridRsaCiphertext.getPayloadCiphertext().toByteArray();
    return aead.decrypt(payloadCiphertext, emptyEad);
  }
}
