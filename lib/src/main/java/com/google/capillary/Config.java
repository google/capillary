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

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods to initialize Capillary library.
 */
public final class Config {

  /**
   * Initializes the Capillary library.
   *
   * <p>This should be called before using any functionality provided by Capillary.
   *
   * @throws GeneralSecurityException if the initialization fails.
   */
  public static void initialize() throws GeneralSecurityException {
    com.google.crypto.tink.Config.register(SignatureConfig.TINK_1_1_0);
    com.google.crypto.tink.Config.register(AeadConfig.TINK_1_1_0);
  }
}
