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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Base64Test {

  @Test
  public void testEncodeDecode() {
    // Test vectors from RFCs.
    final String[] pairs = {
        "", "",
        "f", "Zg",
        "fo", "Zm8",
        "foo", "Zm9v",
        "foob", "Zm9vYg",
        "fooba", "Zm9vYmE",
        "foobar", "Zm9vYmFy",
    };
    for (int i = 0; i < pairs.length; i += 2) {
      verify(pairs[i + 1], pairs[i].getBytes(StandardCharsets.UTF_8));
    }
    verify("FPucA9l-", new byte[]{
        (byte) 0x14, (byte) 0xfb, (byte) 0x9c,
        (byte) 0x03, (byte) 0xd9, (byte) 0x7e
    });
    verify("FPucA9k", new byte[]{
        (byte) 0x14, (byte) 0xfb, (byte) 0x9c,
        (byte) 0x03, (byte) 0xd9
    });
    verify("FPucAw", new byte[]{
        (byte) 0x14, (byte) 0xfb, (byte) 0x9c,
        (byte) 0x03
    });
    // Misc corner cases.
    verify("AQ", new byte[]{
        (byte) 0x01
    });
    verify("AA", new byte[]{
        (byte) 0x00
    });
    verify("_w", new byte[]{
        (byte) 0xff
    });
    verify("__8", new byte[]{
        (byte) 0xff, (byte) 0xff
    });
  }

  private void verify(String encoded, byte[] decoded) {
    assertArrayEquals(decoded, Base64.decode(encoded));
    assertEquals(encoded, Base64.encode(decoded));
  }

  @Test
  public void testIncorrect() {
    // Invalid characters
    try {
      Base64.decode("A$");
      fail("Did not catch problem.");
    } catch (IllegalArgumentException expected) {
      // expected
    }
    // Incorrect length.
    try {
      Base64.decode("A");
      fail("Did not catch problem.");
    } catch (IllegalArgumentException expected) {
      // expected
    }
    // Cannot have this encoding with two characters.
    try {
      Base64.decode("AB");
      fail("Did not catch problem.");
    } catch (IllegalArgumentException expected) {
      // expected
    }
    // Cannot have this encoding with three characters.
    try {
      Base64.decode("AAB");
      fail("Did not catch problem.");
    } catch (IllegalArgumentException expected) {
      // expected
    }
    // Cannot have this encoding with three characters.
    try {
      Base64.decode("__9");
      fail("Did not catch problem.");
    } catch (IllegalArgumentException expected) {
      // expected
    }
  }
}