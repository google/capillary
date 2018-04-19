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

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.os.Build.VERSION_CODES;
import android.security.keystore.UserNotAuthenticatedException;
import com.google.capillary.AuthModeUnavailableException;
import com.google.capillary.NoSuchKeyException;
import com.google.capillary.internal.CapillaryCiphertext;
import com.google.crypto.tink.HybridDecrypt;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.LinkedList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class DecrypterManagerTest {

  private static final String PLAINTEXT = "plaintext";
  private static final String CIPHERTEXT = "ciphertext";
  private static final String PUBLIC_KEY = "public key";

  private final Context context = mock(Context.class);
  private final KeyManager keyManager = mock(KeyManager.class);
  private final HybridDecrypt hybridDecrypt = mock(HybridDecrypt.class);
  private final CiphertextStorage ciphertextStorage = mock(CiphertextStorage.class);
  private final Utils utils = mock(Utils.class);

  private DecrypterManager decrypterManager;
  private CapillaryCiphertext.Builder ciphertextBuilder;
  private CapillaryHandler handler;
  private Object extra;

  /**
   * Creates a new {@link DecrypterManagerTest} instance.
   */
  public DecrypterManagerTest()
      throws NoSuchKeyException, GeneralSecurityException, AuthModeUnavailableException {
    when(hybridDecrypt.decrypt(any(byte[].class), any(byte[].class)))
        .thenReturn(PLAINTEXT.getBytes());
    when(keyManager.getDecrypter(anyString(), anyInt(), anyBoolean())).thenReturn(hybridDecrypt);
    when(keyManager.getPublicKey(anyBoolean())).thenReturn(PUBLIC_KEY.getBytes());
  }

  /**
   * Initializes test case-specific state.
   */
  @Before
  public void setUp() {
    decrypterManager = new DecrypterManager(context, keyManager, ciphertextStorage, utils);
    ciphertextBuilder = CapillaryCiphertext.newBuilder()
        .setIsAuthKey(false)
        .setKeychainUniqueId("1")
        .setKeySerialNumber(1)
        .setCiphertext(ByteString.copyFromUtf8(CIPHERTEXT));
    handler = mock(CapillaryHandler.class);
    extra = new Object();
  }

  @Test
  public void testRegularDecryption()
      throws NoSuchKeyException, GeneralSecurityException, AuthModeUnavailableException {
    // Decrypt no-auth ciphertext.
    ciphertextBuilder.setIsAuthKey(false);
    decrypterManager.decrypt(ciphertextBuilder.build().toByteArray(), handler, extra);
    verify(handler).handleData(false, PLAINTEXT.getBytes(), extra);

    // Decrypt auth ciphertext.
    ciphertextBuilder.setIsAuthKey(true);
    decrypterManager.decrypt(ciphertextBuilder.build().toByteArray(), handler, extra);
    verify(handler).handleData(true, PLAINTEXT.getBytes(), extra);
    verifyNoMoreInteractions(handler);
  }

  @Test
  public void testAuthCiphertextsSaved() {
    // Lock the screen.
    when(utils.isScreenLocked(context)).thenReturn(true);

    // Try to decrypt auth ciphertext while screen is locked.
    ciphertextBuilder.setIsAuthKey(true);
    byte[] ciphertextBytes = ciphertextBuilder.build().toByteArray();
    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).authCiphertextSavedForLater(ciphertextBytes, extra);

    // Try to decrypt no-auth ciphertext while screen is locked.
    ciphertextBuilder.setIsAuthKey(false);
    decrypterManager.decrypt(ciphertextBuilder.build().toByteArray(), handler, extra);
    verify(handler).handleData(false, PLAINTEXT.getBytes(), extra);
    verifyNoMoreInteractions(handler);
  }

  @Test
  public void testAuthCiphertextsSavedWithNewScreenLock() throws Exception {
    // Emulate a newly added screen lock on a device with API level 23 or later.
    TestUtils.setBuildVersion(VERSION_CODES.M);
    when(hybridDecrypt.decrypt(any(byte[].class), any(byte[].class)))
        .thenThrow(new UserNotAuthenticatedException());

    ciphertextBuilder.setIsAuthKey(true);
    byte[] ciphertextBytes = ciphertextBuilder.build().toByteArray();

    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).authCiphertextSavedForLater(ciphertextBytes, extra);
    verifyNoMoreInteractions(handler);
  }

  private static void saveCiphertexts(byte[] ciphertext, int count, CiphertextStorage storage) {
    List<byte[]> savedCiphertexts = new LinkedList<>();
    for (int i = 0; i < count; i++) {
      savedCiphertexts.add(ciphertext);
    }
    when(storage.get()).thenReturn(savedCiphertexts);
  }

  @Test
  public void testSavedDecryption() {
    // No saved ciphertexts.
    decrypterManager.decryptSaved(handler, extra);
    verifyZeroInteractions(handler);

    // Save ciphertexts.
    int ciphertextCount = 10;
    ciphertextBuilder.setIsAuthKey(true);
    byte[] ciphertextBytes = ciphertextBuilder.build().toByteArray();
    saveCiphertexts(ciphertextBytes, ciphertextCount, ciphertextStorage);

    // Try to decrypt saved ciphertexts.
    decrypterManager.decryptSaved(handler, extra);
    verify(handler, times(ciphertextCount)).handleData(true, PLAINTEXT.getBytes(), extra);
    verifyNoMoreInteractions(handler);
  }

  @Test
  public void testSavedDecryptionWithScreenLock() {
    // Lock the screen.
    when(utils.isScreenLocked(context)).thenReturn(true);

    // No saved ciphertexts.
    decrypterManager.decryptSaved(handler, extra);
    verifyZeroInteractions(handler);

    // Save ciphertexts.
    int ciphertextCount = 10;
    ciphertextBuilder.setIsAuthKey(true);
    byte[] ciphertextBytes = ciphertextBuilder.build().toByteArray();
    saveCiphertexts(ciphertextBytes, ciphertextCount, ciphertextStorage);

    // Try to decrypt saved ciphertexts.
    decrypterManager.decryptSaved(handler, extra);
    verify(handler, times(ciphertextCount)).authCiphertextSavedForLater(ciphertextBytes, extra);
    verifyNoMoreInteractions(handler);
  }

  @Test
  public void testMalformedCiphertext() {
    byte[] ciphertextBytes = "malformed ciphertext".getBytes();
    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).error(CapillaryHandlerErrorCode.MALFORMED_CIPHERTEXT, ciphertextBytes, extra);

    verifyNoMoreInteractions(handler);
  }

  @Test
  public void testMissingKey()
      throws NoSuchKeyException, GeneralSecurityException, AuthModeUnavailableException {
    when(keyManager.getDecrypter(anyString(), anyInt(), anyBoolean()))
        .thenThrow(new NoSuchKeyException("no such key"));

    byte[] ciphertextBytes = ciphertextBuilder.build().toByteArray();

    // New key pair generated.
    when(keyManager.generateKeyPair(anyInt(), anyBoolean())).thenReturn(true);
    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).handlePublicKey(
        ciphertextBuilder.getIsAuthKey(), PUBLIC_KEY.getBytes(), ciphertextBytes, extra);

    // New key pair not generated.
    when(keyManager.generateKeyPair(anyInt(), anyBoolean())).thenReturn(false);
    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).error(CapillaryHandlerErrorCode.STALE_CIPHERTEXT, ciphertextBytes, extra);

    // Key pair generation failed.
    when(keyManager.generateKeyPair(anyInt(), anyBoolean()))
        .thenThrow(new GeneralSecurityException("unknown exception"));
    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).error(CapillaryHandlerErrorCode.UNKNOWN_ERROR, ciphertextBytes, extra);
    verifyNoMoreInteractions(handler);
  }

  @Test
  public void testAuthModeUnavailable()
      throws GeneralSecurityException, NoSuchKeyException, AuthModeUnavailableException {
    when(keyManager.getDecrypter(anyString(), anyInt(), anyBoolean()))
        .thenThrow(new AuthModeUnavailableException("no auth mode in device"));

    ciphertextBuilder.setIsAuthKey(true);
    byte[] ciphertextBytes = ciphertextBuilder.build().toByteArray();
    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).error(
        CapillaryHandlerErrorCode.AUTH_CIPHER_IN_NO_AUTH_DEVICE, ciphertextBytes, extra);
    verifyNoMoreInteractions(handler);
  }

  @Test
  public void testUnknownError()
      throws NoSuchKeyException, GeneralSecurityException, AuthModeUnavailableException {
    when(keyManager.getDecrypter(anyString(), anyInt(), anyBoolean()))
        .thenThrow(new GeneralSecurityException("unknown exception"));

    ciphertextBuilder.setIsAuthKey(true);
    byte[] ciphertextBytes = ciphertextBuilder.build().toByteArray();
    decrypterManager.decrypt(ciphertextBytes, handler, extra);
    verify(handler).error(
        CapillaryHandlerErrorCode.UNKNOWN_ERROR, ciphertextBytes, extra);
    verifyNoMoreInteractions(handler);
  }
}
