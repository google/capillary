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

package com.google.capillary.demo.android.callables;

import com.google.capillary.android.CapillaryHandler;
import com.google.capillary.android.DecrypterManager;
import com.google.capillary.demo.common.KeyAlgorithm;
import java.util.concurrent.Callable;

/**
 * Processes any saved Capillary ciphertexts.
 */
public final class DecryptSavedCiphertexts implements Callable<String> {

  private final CapillaryHandler handler;
  private final DecrypterManager decrypterManager;
  private final KeyAlgorithm keyAlgorithm;

  /**
   * Initializes a new {@link DecryptSavedCiphertexts}.
   *
   * @param handler the Capillary handler to use.
   * @param decrypterManager the decrypter manager to use.
   * @param keyAlgorithm the key algorithm of the saved ciphertexts.
   */
  public DecryptSavedCiphertexts(
      CapillaryHandler handler, DecrypterManager decrypterManager, KeyAlgorithm keyAlgorithm) {
    this.handler = handler;
    this.decrypterManager = decrypterManager;
    this.keyAlgorithm = keyAlgorithm;
  }

  @Override
  public String call() throws Exception {
    decrypterManager.decryptSaved(handler, keyAlgorithm);
    return String.format("decrypted saved ciphertexts with\nKeyAlgorithm=%s", keyAlgorithm);
  }
}
