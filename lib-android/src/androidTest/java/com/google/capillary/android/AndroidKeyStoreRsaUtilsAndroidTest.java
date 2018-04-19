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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import com.google.capillary.NoSuchKeyException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class AndroidKeyStoreRsaUtilsAndroidTest {

  private static final String KEYCHAIN_ID = "keychain 1";

  private Context context;
  private KeyStore keyStore;

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() throws GeneralSecurityException {
    keyStore = Utils.getInstance().loadKeyStore();
    context = InstrumentationRegistry.getTargetContext();
    TestUtils.clearKeyStore();
  }

  @Test
  public void testGenerateKeyPair()
      throws KeyStoreException,
      InvalidAlgorithmParameterException,
      NoSuchAlgorithmException,
      NoSuchProviderException {
    String keychainId1 = KEYCHAIN_ID;
    final String keychainId2 = "keychain 2";

    assertEquals(0, keyStore.size());

    AndroidKeyStoreRsaUtils.generateKeyPair(context, keychainId1, false);
    assertEquals(1, keyStore.size());

    AndroidKeyStoreRsaUtils.generateKeyPair(context, keychainId1, true);
    assertEquals(2, keyStore.size());

    AndroidKeyStoreRsaUtils.generateKeyPair(context, keychainId2, false);
    assertEquals(3, keyStore.size());

    AndroidKeyStoreRsaUtils.generateKeyPair(context, keychainId2, true);
    assertEquals(4, keyStore.size());
  }

  @Test
  public void testGetPublicKey()
      throws KeyStoreException,
      InvalidAlgorithmParameterException,
      NoSuchAlgorithmException,
      NoSuchProviderException,
      NoSuchKeyException {
    try {
      AndroidKeyStoreRsaUtils.getPublicKey(keyStore, KEYCHAIN_ID, false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    AndroidKeyStoreRsaUtils.generateKeyPair(context, KEYCHAIN_ID, false);

    assertNotNull(AndroidKeyStoreRsaUtils.getPublicKey(keyStore, KEYCHAIN_ID, false));
  }

  @Test
  public void testGetPrivateKey()
      throws UnrecoverableKeyException,
      NoSuchAlgorithmException,
      KeyStoreException,
      NoSuchProviderException,
      InvalidAlgorithmParameterException,
      NoSuchKeyException {
    try {
      AndroidKeyStoreRsaUtils.getPrivateKey(keyStore, KEYCHAIN_ID, false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    AndroidKeyStoreRsaUtils.generateKeyPair(context, KEYCHAIN_ID, false);

    assertNotNull(AndroidKeyStoreRsaUtils.getPrivateKey(keyStore, KEYCHAIN_ID, false));
  }

  @Test
  public void testDeleteKeyPair()
      throws KeyStoreException,
      InvalidAlgorithmParameterException,
      NoSuchAlgorithmException,
      NoSuchProviderException,
      NoSuchKeyException {
    try {
      AndroidKeyStoreRsaUtils.deleteKeyPair(keyStore, KEYCHAIN_ID, false);
      fail("Did not throw NoSuchKeyException");
    } catch (NoSuchKeyException e) {
      // This is expected.
    }

    AndroidKeyStoreRsaUtils.generateKeyPair(context, KEYCHAIN_ID, false);
    assertEquals(1, keyStore.size());

    AndroidKeyStoreRsaUtils.deleteKeyPair(keyStore, KEYCHAIN_ID, false);
    assertEquals(0, keyStore.size());
  }

}
