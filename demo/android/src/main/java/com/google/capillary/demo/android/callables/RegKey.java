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
import com.google.capillary.android.KeyManager;
import com.google.capillary.demo.common.KeyAlgorithm;
import java.util.concurrent.Callable;

/**
 * Registers the specified Capillary public key with the application server.
 */
public final class RegKey implements Callable<String> {

  private final CapillaryHandler handler;
  private final KeyManager keyManager;
  private final KeyAlgorithm algorithm;
  private final boolean isAuth;

  /**
   * Initializes a new {@link RegKey}.
   *
   * @param handler the Capillary handler to use.
   * @param keyManager the key manager to use.
   * @param algorithm the algorithm of the registered key.
   * @param isAuth whether the registered key requires authenticated.
   */
  public RegKey(
      CapillaryHandler handler, KeyManager keyManager, KeyAlgorithm algorithm, boolean isAuth) {
    this.handler = handler;
    this.keyManager = keyManager;
    this.algorithm = algorithm;
    this.isAuth = isAuth;
  }

  @Override
  public String call() throws Exception {
    keyManager.getPublicKey(isAuth, handler, algorithm);
    return String
        .format("registered key pair with:\nKeyAlgorithm=%s\nIsAuth=%s", algorithm, isAuth);
  }
}
