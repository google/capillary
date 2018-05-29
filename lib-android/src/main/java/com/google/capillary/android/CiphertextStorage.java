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

import android.content.Context;
import android.content.SharedPreferences;
import com.google.crypto.tink.subtle.Base64;
import java.util.LinkedList;
import java.util.List;

/**
 * Allows storing Capillary ciphertext in {@link SharedPreferences} to be decrypted later.
 */
class CiphertextStorage {

  private static final String DATA_COUNT_KEY = "current_count";

  private final SharedPreferences dataSharedPreferences;
  private final SharedPreferences metaSharedPreferences;

  /**
   * Initializes a {@link SharedPreferences} backed ciphertext storage for the given keychain ID.
   */
  CiphertextStorage(Context context, Utils utils, String keychainId) {
    Context storageContext = utils.getDeviceProtectedStorageContext(context);
    String dataPrefName =
        String.format("%s_%s_data_preferences", getClass().getCanonicalName(), keychainId);
    String metaPrefName =
        String.format("%s_%s_meta_preferences", getClass().getCanonicalName(), keychainId);
    dataSharedPreferences = storageContext.getSharedPreferences(dataPrefName, Context.MODE_PRIVATE);
    metaSharedPreferences = storageContext.getSharedPreferences(metaPrefName, Context.MODE_PRIVATE);
  }

  /**
   * Saves the given ciphertext.
   */
  synchronized void save(byte[] ciphertext) {
    String ciphertextString = Base64.encode(ciphertext);
    int nextCount = metaSharedPreferences.getInt(DATA_COUNT_KEY, 0) + 1;
    dataSharedPreferences.edit().putString(String.valueOf(nextCount), ciphertextString).apply();
    metaSharedPreferences.edit().putInt(DATA_COUNT_KEY, nextCount).apply();
  }

  /**
   * Returns all saved ciphertexts.
   */
  List<byte[]> get() {
    List<byte[]> ciphertextList = new LinkedList<>();
    for (Object ciphertextString : dataSharedPreferences.getAll().values()) {
      byte[] ciphertextBytes = Base64.decode(ciphertextString.toString());
      ciphertextList.add(ciphertextBytes);
    }
    return ciphertextList;
  }

  /**
   * Clears all saved ciphertexts.
   */
  synchronized void clear() {
    dataSharedPreferences.edit().clear().apply();
    metaSharedPreferences.edit().putInt(DATA_COUNT_KEY, 0).apply();
  }
}
