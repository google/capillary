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
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.PublicKeySign;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import javax.crypto.spec.OAEPParameterSpec;

/**
 * A {@link HybridEncrypt} implementation for an authenticated hybrid encryption scheme, which is
 * called RSA-ECDSA for simplicity, that is based on RSA public-key encryption, AES symmetric key
 * encryption in GCM mode (AES-GCM), and ECDSA signature algorithm.
 *
 * <p>Sample usage:
 * <pre>{@code
 * import com.google.capillary.RsaEcdsaConstants.Padding;
 * import com.google.crypto.tink.HybridDecrypt;
 * import com.google.crypto.tink.HybridEncrypt;
 * import com.google.crypto.tink.PublicKeySign;
 * import com.google.crypto.tink.PublicKeyVerify;
 * import java.security.PrivateKey;
 * import java.security.PublicKey;
 *
 * // Encryption.
 * PublicKeySign senderSigner = ...;
 * PublicKey recipientPublicKey = ...;
 * HybridEncrypt hybridEncrypt = new RsaEcdsaHybridEncrypt.Builder()
 *   .withSenderSigner(senderSigner)
 *   .withRecipientPublicKey(recipientPublicKey)
 *   .withPadding(Padding.OAEP)
 *   .build();
 * byte[] plaintext = ...;
 * byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null);
 *
 * // Decryption.
 * PublicKeyVerify senderVerifier = ...;
 * PrivateKey recipientPrivateKey = ...;
 * HybridDecrypt hybridDecrypt = new RsaEcdsaHybridDecrypt.Builder()
 *   .withSenderVerifier(senderVerifier)
 *   .withRecipientPrivateKey(recipientPrivateKey)
 *   .withPadding(Padding.OAEP)
 *   .build();
 * byte[] ciphertext = ...;
 * byte[] plaintext = hybridDecrypt.decrypt(ciphertext, null);
 * }</pre>
 *
 * <p>The encryption algorithm consists of the following steps:
 * <ol>
 * <li>Generate an AES-GCM symmetric key.</li>
 * <li>Encrypt the AES-GCM key using RSA.</li>
 * <li>Encrypt the message using the AES-GCM key.</li>
 * <li>Encode the encrypted AES-GCM key and the encrypted message into a byte array A1.</li>
 * <li>Sign A1 using ECDSA.</li>
 * <li>Combine A1 and its signature into a byte array A2.</li>
 * <li>Output A2 as the RSA-ECDSA ciphertext.</li>
 * </ol>
 *
 * <p>The format of the RsaEcdsa ciphertext is the following:
 * <pre>{@code
 * +------------------------------------------+
 * | ECDSA Signature Length (4 bytes)         |
 * +------------------------------------------+
 * | ECDSA Signature                          |
 * +------------------------------------------+
 * | RSA+AES-GCM hybrid-encryption ciphertext |
 * +------------------------------------------+
 * }</pre>
 *
 * <p>This implementation of RSA-ECDSA depends on the <a href="https://github.com/google/tink"
 * target="_blank">Tink</a> crypto library to perform AES-GCM and ECDSA operations.
 */
public final class RsaEcdsaHybridEncrypt implements HybridEncrypt {

  private final PublicKeySign senderSigner;
  private final PublicKey recipientPublicKey;
  private final Padding padding;
  private final OAEPParameterSpec oaepParameterSpec;

  /**
   * Builder for {@link RsaEcdsaHybridEncrypt}.
   */
  public static final class Builder {

    private PublicKeySign senderSigner = null;
    private PublicKey recipientPublicKey = null;
    private Padding padding = null;
    private OAEPParameterSpec oaepParameterSpec = RsaEcdsaConstants.OAEP_PARAMETER_SPEC;

    /**
     * Create a new builder.
     */
    public Builder() {
    }

    /**
     * Sets the ECDSA signature creation primitive of the sender.
     *
     * @param val the Tink ECDSA signer.
     * @return the builder.
     */
    public Builder withSenderSigner(PublicKeySign val) {
      senderSigner = val;
      return this;
    }

    /**
     * Sets the RSA public key of the receiver.
     *
     * @param val the RSA public key.
     * @return the builder.
     */
    public Builder withRecipientPublicKey(PublicKey val) {
      recipientPublicKey = val;
      return this;
    }

    /**
     * Sets the RSA padding scheme to use.
     *
     * @param val the RSA padding scheme.
     * @return the builder.
     */
    public Builder withPadding(Padding val) {
      padding = val;
      return this;
    }

    /**
     * Sets the {@link OAEPParameterSpec} for RSA OAEP padding.
     *
     * <p>Setting this parameter is optional. If it is not specified, {@code
     * RsaEcdsaConstants.OAEP_PARAMETER_SPEC} will be used.
     *
     * @param val the {@link OAEPParameterSpec} instance.
     * @return the builder.
     */
    public Builder withOaepParameterSpec(OAEPParameterSpec val) {
      oaepParameterSpec = val;
      return this;
    }

    /**
     * Creates the {@link RsaEcdsaHybridEncrypt} instance for this builder.
     *
     * @return the created {@link RsaEcdsaHybridEncrypt} instance.
     */
    public RsaEcdsaHybridEncrypt build() {
      return new RsaEcdsaHybridEncrypt(this);
    }
  }

  private RsaEcdsaHybridEncrypt(Builder builder) {
    if (builder.senderSigner == null) {
      throw new IllegalArgumentException(
          "must set sender's signer with Builder.withSenderSigner");
    }
    senderSigner = builder.senderSigner;

    if (builder.recipientPublicKey == null) {
      throw new IllegalArgumentException(
          "must set recipient's public key with Builder.withRecipientPublicKeyBytes");
    }
    recipientPublicKey = builder.recipientPublicKey;

    if (builder.padding == null) {
      throw new IllegalArgumentException(
          "must set padding with Builder.withPadding");
    }
    padding = builder.padding;

    if (padding == Padding.OAEP && builder.oaepParameterSpec == null) {
      throw new IllegalArgumentException(
          "must set OAEP parameter spec with Builder.withOaepParameterSpec");
    }
    oaepParameterSpec = builder.oaepParameterSpec;
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] contextInfo /* unused */)
      throws GeneralSecurityException {
    if (contextInfo != null) {
      throw new GeneralSecurityException("contextInfo must be null because it is unused");
    }

    try {
      byte[] unsignedCiphertext =
          HybridRsaUtils.encrypt(plaintext, recipientPublicKey, padding, oaepParameterSpec);
      return signAndSerialize(unsignedCiphertext);
    } catch (IOException e) {
      throw new GeneralSecurityException("encryption failed", e);
    }
  }

  private byte[] signAndSerialize(byte[] payload) throws GeneralSecurityException, IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    // Generate signature.
    byte[] signature = senderSigner.sign(payload);
    // Write signature length.
    ByteBuffer signatureLengthBytes =
        ByteBuffer.allocate(RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH);
    signatureLengthBytes.putInt(signature.length);
    outputStream.write(signatureLengthBytes.array());
    // Write signature.
    outputStream.write(signature);
    // Write payload.
    outputStream.write(payload);
    // Return serialized bytes.
    return outputStream.toByteArray();
  }
}
