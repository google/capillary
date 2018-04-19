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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class CiphertextStorageAndroidTest {

  private Context context;

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() {
    context = InstrumentationRegistry.getTargetContext();
  }

  @Test
  public void testSaveAndGet() {
    byte[][] mockCiphers = new byte[][]{"cipher 1".getBytes(), "cipher 2".getBytes()};
    CiphertextStorage storage =
        new CiphertextStorage(context, Utils.getInstance(), "keychain 1");
    // Clear any remaining ciphertexts from previous tests.
    storage.clear();

    // Empty storage shouldn't have any ciphertexts.
    assertTrue(storage.get().isEmpty());

    // Saved ciphers should be returned in the order they were saved.
    for (byte[] mockCipher : mockCiphers) {
      storage.save(mockCipher);
    }
    List<byte[]> gotCiphers = storage.get();
    for (int i = 0; i < gotCiphers.size(); i++) {
      assertArrayEquals(mockCiphers[i], gotCiphers.get(i));
    }

    // After calling clear, the storage should be empty.
    storage.clear();
    assertTrue(storage.get().isEmpty());
  }

  @Test
  public void testMultipleKeychainIds() {
    CiphertextStorage storage1 =
        new CiphertextStorage(context, Utils.getInstance(), "keychain 1");
    CiphertextStorage storage2 =
        new CiphertextStorage(context, Utils.getInstance(), "keychain 2");
    // Clear any remaining ciphertexts from previous tests.
    storage1.clear();
    storage2.clear();

    // Initially both stores should be empty.
    assertTrue(storage1.get().isEmpty());
    assertTrue(storage2.get().isEmpty());

    // Save and get with store 1.
    byte[] mockCipher = "cipher 1".getBytes();
    storage1.save(mockCipher);
    assertEquals(1, storage1.get().size());

    // Store 2 still shouldn't have any ciphers.
    assertTrue(storage2.get().isEmpty());

    // Clear store 1.
    storage1.clear();
    assertTrue(storage1.get().isEmpty());
  }
}
