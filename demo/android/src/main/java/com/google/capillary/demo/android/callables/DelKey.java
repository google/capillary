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
 * Deletes the specified Capillary key pair from the device.
 */
public final class DelKey implements Callable<String> {

  private final KeyManager keyManager;
  private final KeyAlgorithm algorithm;
  private final boolean isAuth;

  /**
   * Initializes a new {@link DelKey}.
   *
   * @param keyManager the key manager to use.
   * @param algorithm the algorithm of the deleted key.
   * @param isAuth whether the deleted key requires authenticated.
   */
  public DelKey(KeyManager keyManager, KeyAlgorithm algorithm, boolean isAuth) {
    this.keyManager = keyManager;
    this.algorithm = algorithm;
    this.isAuth = isAuth;
  }

  @Override
  public String call() throws Exception {
    keyManager.deleteKeyPair(isAuth);
    return String.format("deleted key pair with\nKeyAlgorithm=%s\nIsAuth=%s", algorithm, isAuth);
  }
}
