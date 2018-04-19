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

import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

/**
 * Contains the constants and enums used by RSA-ECDSA encryption/decryption.
 */
public final class RsaEcdsaConstants {

  static final OAEPParameterSpec OAEP_PARAMETER_SPEC =
      new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSpecified.DEFAULT);
  static final int SIGNATURE_LENGTH_BYTES_LENGTH = 4;

  /**
   * Encapsulates the ciphertext padding modes supported by RSA-ECDSA encryption/decryption.
   */
  public enum Padding {
    OAEP("OAEPPadding"),
    PKCS1("PKCS1Padding");

    private static final String PREFIX = "RSA/ECB/";

    private final String padding;

    Padding(String val) {
      padding = val;
    }

    /**
     * Returns the current padding enum's transformation string that should be used when calling
     * {@code javax.crypto.Cipher.getInstance}.
     *
     * @return the transformation string.
     */
    public String getTransformation() {
      return PREFIX + padding;
    }
  }
}
