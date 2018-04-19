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

package com.google.capillary.demo.server;

/**
 * A checked exception to notify that a user ID is missing.
 */
final class NoSuchUserException extends Exception {

  /**
   * Creates a new {@link NoSuchUserException} object.
   *
   * @param msg the exception message.
   */
  NoSuchUserException(String msg) {
    super(msg);
  }
}
