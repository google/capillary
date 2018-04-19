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

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import android.content.Context;
import com.google.capillary.NoSuchKeyException;
import com.google.crypto.tink.HybridDecrypt;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class KeyManagerTest {

  @Test
  public void testStorageContextIsPrivate() {
    Context context = mock(Context.class);
    new KeyManager(context, Utils.getInstance(), "keychain id") {
      @Override
      void rawGenerateKeyPair(boolean isAuth) throws GeneralSecurityException {
      }

      @Override
      byte[] rawGetPublicKey(boolean isAuth) throws NoSuchKeyException, GeneralSecurityException {
        return new byte[0];
      }

      @Override
      HybridDecrypt rawGetDecrypter(boolean isAuth)
          throws NoSuchKeyException, GeneralSecurityException {
        return null;
      }

      @Override
      void rawDeleteKeyPair(boolean isAuth) throws NoSuchKeyException, GeneralSecurityException {
      }
    };

    // There should be one call to getSharedPreferences with Context.MODE_PRIVATE.
    verify(context).getSharedPreferences(anyString(), eq(Context.MODE_PRIVATE));
  }
}
