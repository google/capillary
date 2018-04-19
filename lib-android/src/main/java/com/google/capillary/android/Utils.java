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

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import com.google.capillary.AuthModeUnavailableException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * Provides some useful Android-specific helper functions.
 */
class Utils {

  private static final String KEYSTORE_ANDROID = "AndroidKeyStore";

  private static Utils instance;

  private Utils() {
  }

  /**
   * Returns the singleton instance.
   */
  static synchronized Utils getInstance() {
    if (instance == null) {
      instance = new Utils();
    }
    return instance;
  }

  /**
   * Creates a storage context that is protected by device-specific credentials.
   *
   * <p>This method only has an effect on API levels 24 and above.
   */
  Context getDeviceProtectedStorageContext(Context context) {
    if (VERSION.SDK_INT >= VERSION_CODES.N) {
      return context.createDeviceProtectedStorageContext();
    }
    return context;
  }

  /**
   * Checks if the device supports generating authenticated Capillary keys or throws an exception if
   * it doesn't.
   */
  void checkAuthModeIsAvailable(Context context) throws AuthModeUnavailableException {
    boolean isScreenLockEnabled = isScreenLockEnabled(context);
    if (isScreenLockEnabled && !isScreenLocked(context)) {
      return;
    }
    if (!isScreenLockEnabled) {
      throw new AuthModeUnavailableException(
          "the device is not secured with a PIN, pattern, or password");
    }
    throw new AuthModeUnavailableException("the device is locked");
  }

  /**
   * Checks if the device screen lock is enabled. Returns the status as a boolean.
   */
  private boolean isScreenLockEnabled(Context context) {
    KeyguardManager keyguardManager =
        (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    assert keyguardManager != null;
    if (VERSION.SDK_INT >= VERSION_CODES.M) {
      return keyguardManager.isDeviceSecure();
    }
    return keyguardManager.isKeyguardSecure();
  }

  /**
   * Checks if the device is locked. Returns the status as a boolean.
   */
  boolean isScreenLocked(Context context) {
    KeyguardManager keyguardManager =
        (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    assert keyguardManager != null;
    if (VERSION.SDK_INT >= VERSION_CODES.M) {
      return keyguardManager.isDeviceLocked();
    }
    return keyguardManager.isKeyguardLocked();
  }

  KeyStore loadKeyStore() throws GeneralSecurityException {
    KeyStore keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
    try {
      keyStore.load(null);
    } catch (IOException e) {
      throw new GeneralSecurityException("unable to load keystore", e);
    }
    return keyStore;
  }
}
