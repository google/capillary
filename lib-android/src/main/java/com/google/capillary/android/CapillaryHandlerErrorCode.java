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

package com.google.capillary.android;

/**
 * These are the common errors that can occur in Capillary library.
 */
public enum CapillaryHandlerErrorCode {
  // A ciphertext that was encrypted using an authenticated Capillary public key was received in a
  // device that does not have authentication enabled.
  AUTH_CIPHER_IN_NO_AUTH_DEVICE,
  // A malformed ciphertext was received.
  MALFORMED_CIPHERTEXT,
  // A ciphertext that was encrypted using an older Capillary public key was received. The client
  // should re-register the current Capillary public key with the application server to avoid
  // this error happening again.
  STALE_CIPHERTEXT,
  // An error other than the above has occurred.
  UNKNOWN_ERROR
}
