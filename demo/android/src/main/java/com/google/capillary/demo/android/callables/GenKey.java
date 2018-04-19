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

import com.google.capillary.android.KeyManager;
import com.google.capillary.demo.common.KeyAlgorithm;
import java.util.concurrent.Callable;

/**
 * Generates a Capillary key pair.
 */
public final class GenKey implements Callable<String> {

  private final KeyManager keyManager;
  private final KeyAlgorithm algorithm;
  private final boolean isAuth;

  /**
   * Initializes a new {@link GenKey}.
   *
   * @param keyManager the key manager to use.
   * @param algorithm the algorithm of the generated key.
   * @param isAuth whether the generated key requires authenticated.
   */
  public GenKey(KeyManager keyManager, KeyAlgorithm algorithm, boolean isAuth) {
    this.keyManager = keyManager;
    this.algorithm = algorithm;
    this.isAuth = isAuth;
  }

  @Override
  public String call() throws Exception {
    keyManager.generateKeyPair(isAuth);
    return String.format("generated key pair with\nKeyAlgorithm=%s\nIsAuth=%s", algorithm, isAuth);
  }
}
