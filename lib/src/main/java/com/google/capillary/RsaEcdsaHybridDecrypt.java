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
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import javax.crypto.spec.OAEPParameterSpec;

/**
 * A {@link HybridDecrypt} implementation for an authenticated hybrid encryption scheme, which is
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
 * <p>The decryption algorithm consists of the following steps:
 * <ol>
 * <li>Parse the ciphertext bytes into a signed byte array B1 and a signature.</li>
 * <li>Verify that the signature validates for B1. If not, abort.</li>
 * <li>Parse B1 into an encrypted AES-GCM key B2 and an encrypted message B3.</li>
 * <li>Decrypt B2 using RSA algorithm to obtain a AES-GCM key K1.</li>
 * <li>Decrypt B3 using K1 to obtain the plaintext.</li>
 * <li>Output the plaintext.</li>
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
public final class RsaEcdsaHybridDecrypt implements HybridDecrypt {

  private final PublicKeyVerify senderVerifier;
  private final PrivateKey recipientPrivateKey;
  private final Padding padding;
  private final OAEPParameterSpec oaepParameterSpec;

  /**
   * Builder for {@link RsaEcdsaHybridDecrypt}.
   */
  public static final class Builder {

    private PublicKeyVerify senderVerifier = null;
    private PrivateKey recipientPrivateKey = null;
    private Padding padding = null;
    private OAEPParameterSpec oaepParameterSpec = RsaEcdsaConstants.OAEP_PARAMETER_SPEC;

    /**
     * Create a new builder.
     */
    public Builder() {
    }

    /**
     * Sets the ECDSA signature verification primitive of the sender.
     *
     * @param val the Tink ECDSA verifier.
     * @return the builder.
     */
    public Builder withSenderVerifier(PublicKeyVerify val) {
      senderVerifier = val;
      return this;
    }

    /**
     * Sets the RSA private key of the receiver.
     *
     * @param val the RSA public key.
     * @return the builder.
     */
    public Builder withRecipientPrivateKey(PrivateKey val) {
      recipientPrivateKey = val;
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
     * Creates the {@link RsaEcdsaHybridDecrypt} instance for this builder.
     *
     * @return the created {@link RsaEcdsaHybridDecrypt} instance.
     */
    public RsaEcdsaHybridDecrypt build() {
      return new RsaEcdsaHybridDecrypt(this);
    }
  }

  private RsaEcdsaHybridDecrypt(Builder builder) {
    if (builder.senderVerifier == null) {
      throw new IllegalArgumentException(
          "must set sender's verifier with Builder.withSenderVerificationKey");
    }
    senderVerifier = builder.senderVerifier;

    if (builder.recipientPrivateKey == null) {
      throw new IllegalArgumentException(
          "must set recipient's private key with Builder.withRecipientPrivateKey");
    }
    recipientPrivateKey = builder.recipientPrivateKey;

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
  public byte[] decrypt(byte[] ciphertext, byte[] contextInfo) throws GeneralSecurityException {
    if (contextInfo != null) {
      throw new GeneralSecurityException("contextInfo must be null because it is unused");
    }

    try {
      byte[] verifiedCiphertext = deserializeAndVerify(ciphertext);
      return HybridRsaUtils.decrypt(
          verifiedCiphertext, recipientPrivateKey, padding, oaepParameterSpec);
    } catch (IOException e) {
      throw new GeneralSecurityException("decryption failed", e);
    }
  }

  private byte[] deserializeAndVerify(byte[] signedPayloadBytes)
      throws InvalidProtocolBufferException, GeneralSecurityException {
    // Check for minimum number of required bytes.
    if (signedPayloadBytes.length < RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH) {
      throw new GeneralSecurityException("invalid signed payload");
    }
    // Read the signature length.
    ByteBuffer signatureLengthBytes =
        ByteBuffer.allocate(RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH);
    signatureLengthBytes
        .put(signedPayloadBytes, 0, RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH);
    signatureLengthBytes.flip();
    int signatureLength = signatureLengthBytes.getInt();
    // Check that signature length is valid.
    if (signatureLength < 0
        || signatureLength
        > signedPayloadBytes.length - RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH) {
      throw new GeneralSecurityException("invalid signature length");
    }
    // Read the signature.
    byte[] signature = new byte[signatureLength];
    System.arraycopy(
        signedPayloadBytes,
        RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH,
        signature,
        0,
        signatureLength);
    // Read the payload.
    int payloadLength = signedPayloadBytes.length
        - signatureLength
        - RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH;
    byte[] payload = new byte[payloadLength];
    System.arraycopy(
        signedPayloadBytes,
        RsaEcdsaConstants.SIGNATURE_LENGTH_BYTES_LENGTH + signatureLength,
        payload,
        0,
        payloadLength);
    // Verify the signature.
    senderVerifier.verify(signature, payload);
    // Return payload if signature is verified.
    return payload;
  }
}
