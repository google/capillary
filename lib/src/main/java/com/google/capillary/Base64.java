/*
 * Copyright (C) 2010 The Android Open Source Project
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

import java.util.Arrays;

/**
 * An implementation of url-safe base64 encoding, as this is not a standard in Java 7.
 *
 * <p>This is a copy of android.util.Base64, with minor modifications.
 */
public final class Base64 {

  // URLSafe encoding table: 6-bit int -> char.
  private static final char[] ENCODE_TABLE = (
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          + "abcdefghijklmnopqrstuvwxyz"
          + "0123456789-_").toCharArray();
  // URLSafe decoding table: char -> 6-bit int. Invalid characters map to -1.
  private static final int[] DECODE_TABLE;

  static {
    DECODE_TABLE = new int[256];
    Arrays.fill(DECODE_TABLE, -1);
    for (int i = 0; i < ENCODE_TABLE.length; i++) {
      DECODE_TABLE[ENCODE_TABLE[i]] = i;
    }
  }

  private Base64() {
  }

  /**
   * Encodes a byte array into a url-safe base64 encoded string.
   *
   * @param bytes the byte array to encode.
   * @return the encoded string.
   */
  public static String encode(byte[] bytes) {
    return encode(bytes, 0, bytes.length);
  }

  private static String encode(byte[] bytes, int offset, int len) {
    int outLength = (len / 3) * 4;
    switch (len % 3) {
      case 0:
        break;
      case 1:
        outLength += 2;
        break;
      case 2:
        outLength += 3;
        break;
      default:
        throw new IllegalStateException("should not happen");
    }
    char[] result = new char[outLength];
    // Process input in groups of 3 bytes.
    int max = offset + len - 2;
    int in = offset;
    int out = 0;
    int value;
    while (in < max) {
      // Shift three bytes (24 bits) into an integer.
      value = ((bytes[in++] & 0xff) << 16)
          | ((bytes[in++] & 0xff) << 8)
          | (bytes[in++] & 0xff);
      // Encode integer in 4 groups of 6 bits.
      result[out++] = ENCODE_TABLE[(value >> 18) & 0x3f];
      result[out++] = ENCODE_TABLE[(value >> 12) & 0x3f];
      result[out++] = ENCODE_TABLE[(value >> 6) & 0x3f];
      result[out++] = ENCODE_TABLE[value & 0x3f];
    }
    // Encode any remaining bytes.
    switch (len % 3) {
      case 0:
        break;
      case 1:
        // Pad with two extra zeros, encode as two values.
        value = (bytes[in++] & 0xff) << 16;
        result[out++] = ENCODE_TABLE[(value >> 18) & 0x3f];
        result[out++] = ENCODE_TABLE[(value >> 12) & 0x3f];
        break;
      case 2:
        // Pad with one extra zero, encode into three values.
        value = ((bytes[in++] & 0xff) << 16)
            | ((bytes[in++] & 0xff) << 8);
        result[out++] = ENCODE_TABLE[(value >> 18) & 0x3f];
        result[out++] = ENCODE_TABLE[(value >> 12) & 0x3f];
        result[out++] = ENCODE_TABLE[(value >> 6) & 0x3f];
        break;
      default:
        throw new IllegalStateException("should not happen");
    }
    return new String(result);
  }

  /**
   * Decodes a url-safe base64 encoded string into a byte array.
   *
   * @param string the string to decode.
   * @return the decoded byte array.
   */
  public static byte[] decode(String string) {
    char[] chars = string.toCharArray();
    int outLength = (chars.length / 4) * 3;
    switch (chars.length % 4) {
      case 0:
        break;
      case 2:
        outLength += 1;
        break;
      case 3:
        outLength += 2;
        break;
      default:
        throw new IllegalArgumentException("invalid base64 string");
    }
    byte[] result = new byte[outLength];
    // Process input in groups of 4 characters.
    int max = chars.length - 3;
    int in = 0;
    int out = 0;
    int value;
    while (in < max) {
      // Decode 4 characters into 24-bits (6 bits per character).
      value = (decode(chars[in++]) << 18)
          | (decode(chars[in++]) << 12)
          | (decode(chars[in++]) << 6)
          | decode(chars[in++]);
      // Copy integer into 3 bytes, 8 bits at a time.
      result[out++] = (byte) ((value >> 16) & 0xff);
      result[out++] = (byte) ((value >> 8) & 0xff);
      result[out++] = (byte) (value & 0xff);
    }
    // Decode any remaining characters.
    switch (chars.length % 4) {
      case 0:
        break;
      case 2:
        // Decode two characters into one byte.
        // The second character must only encode values for the leading 2 of its 6 bits.
        value = decode(chars[in++]) << 2 | decode(chars[in++], 0x30) >> 4;
        result[out++] = (byte) (value & 0xff);
        break;
      case 3:
        // Decode three characters into two bytes.
        // The third character must only encode values for the leading 4 of its 6 bits.
        value = decode(chars[in++]) << 10
            | decode(chars[in++]) << 4
            | decode(chars[in++], 0x3c) >> 2;
        result[out++] = (byte) ((value >> 8) & 0xff);
        result[out++] = (byte) (value & 0xff);
        break;
      default:
        throw new IllegalStateException("should not happen");
    }
    return result;
  }

  // Decode a encoded character into its 6-bit equivalent.
  private static int decode(char encoded) {
    int decoded = DECODE_TABLE[encoded];
    if (decoded < 0) {
      throw new IllegalArgumentException("invalid base64 encoding");
    }
    return decoded;
  }

  // Decode an encoded character into its 6-bit equivalent, and verify that only the bits in the
  // provided mask are set.
  private static int decode(char encoded, int mask) {
    int decoded = decode(encoded);
    if ((decoded & mask) != decoded) {
      throw new IllegalArgumentException("invalid base64 encoding");
    }
    return decoded;
  }
}