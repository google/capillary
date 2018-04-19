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

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Implementation of {@link CapillaryHandler} for integration testing.
 */
final class TestHandler implements CapillaryHandler {

  List<HandleDataRequest> handleDataRequests = new LinkedList<>();
  List<HandlePublicKeyRequest> handlePublicKeyRequests = new LinkedList<>();
  List<AuthCiphertextSavedForLaterRequest> authCiphertextSavedForLaterRequests = new LinkedList<>();
  List<ErrorRequest> errorRequests = new LinkedList<>();

  static class HandleDataRequest {

    boolean isAuthKey;
    byte[] data;
    Object extra;

    HandleDataRequest(boolean isAuthKey, byte[] data, Object extra) {
      this.isAuthKey = isAuthKey;
      this.data = data;
      this.extra = extra;
    }

    @Override
    public int hashCode() {
      int result = (isAuthKey ? 1 : 0);
      result = 31 * result + Arrays.hashCode(data);
      result = 31 * result + extra.hashCode();
      return result;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      HandleDataRequest that = (HandleDataRequest) o;

      return isAuthKey == that.isAuthKey
          && Arrays.equals(data, that.data)
          && extra.equals(that.extra);
    }
  }

  static class HandlePublicKeyRequest {

    boolean isAuthKey;
    byte[] publicKey;
    byte[] ciphertext;
    Object extra;

    HandlePublicKeyRequest(
        boolean isAuthKey, byte[] publicKey, byte[] ciphertext, Object extra) {
      this(isAuthKey, publicKey, extra);
      this.ciphertext = ciphertext;
    }

    HandlePublicKeyRequest(boolean isAuthKey, byte[] publicKey, Object extra) {
      this.isAuthKey = isAuthKey;
      this.publicKey = publicKey;
      this.extra = extra;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      HandlePublicKeyRequest that = (HandlePublicKeyRequest) o;

      return isAuthKey == that.isAuthKey
          && Arrays.equals(publicKey, that.publicKey)
          && Arrays.equals(ciphertext, that.ciphertext)
          && extra.equals(that.extra);
    }

    @Override
    public int hashCode() {
      int result = (isAuthKey ? 1 : 0);
      result = 31 * result + Arrays.hashCode(publicKey);
      result = 31 * result + Arrays.hashCode(ciphertext);
      result = 31 * result + extra.hashCode();
      return result;
    }
  }

  static class AuthCiphertextSavedForLaterRequest {

    byte[] ciphertext;
    Object extra;

    AuthCiphertextSavedForLaterRequest(byte[] ciphertext, Object extra) {
      this.ciphertext = ciphertext;
      this.extra = extra;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      AuthCiphertextSavedForLaterRequest that = (AuthCiphertextSavedForLaterRequest) o;

      return Arrays.equals(ciphertext, that.ciphertext) && extra.equals(that.extra);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(ciphertext);
      result = 31 * result + extra.hashCode();
      return result;
    }
  }

  static class ErrorRequest {

    CapillaryHandlerErrorCode errorCode;
    byte[] ciphertext;
    Object extra;

    ErrorRequest(CapillaryHandlerErrorCode errorCode, byte[] ciphertext, Object extra) {
      this.errorCode = errorCode;
      this.ciphertext = ciphertext;
      this.extra = extra;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      ErrorRequest that = (ErrorRequest) o;

      return errorCode == that.errorCode
          && Arrays.equals(ciphertext, that.ciphertext)
          && extra.equals(that.extra);
    }

    @Override
    public int hashCode() {
      int result = errorCode.hashCode();
      result = 31 * result + Arrays.hashCode(ciphertext);
      result = 31 * result + extra.hashCode();
      return result;
    }
  }

  @Override
  public void handleData(boolean isAuthKey, byte[] data, Object extra) {
    handleDataRequests.add(new HandleDataRequest(isAuthKey, data, extra));
  }

  @Override
  public void handlePublicKey(boolean isAuthKey, byte[] publicKey, Object extra) {
    handlePublicKeyRequests.add(new HandlePublicKeyRequest(isAuthKey, publicKey, extra));
  }

  @Override
  public void handlePublicKey(
      boolean isAuthKey, byte[] publicKey, byte[] ciphertext, Object extra) {
    handlePublicKeyRequests.add(
        new HandlePublicKeyRequest(isAuthKey, publicKey, ciphertext, extra));
  }

  @Override
  public void authCiphertextSavedForLater(byte[] ciphertext, Object extra) {
    authCiphertextSavedForLaterRequests
        .add(new AuthCiphertextSavedForLaterRequest(ciphertext, extra));
  }

  @Override
  public void error(CapillaryHandlerErrorCode errorCode, byte[] ciphertext, Object extra) {
    errorRequests.add(new ErrorRequest(errorCode, ciphertext, extra));
  }

  void reset() {
    handleDataRequests.clear();
    handlePublicKeyRequests.clear();
    authCiphertextSavedForLaterRequests.clear();
    errorRequests.clear();
  }
}
