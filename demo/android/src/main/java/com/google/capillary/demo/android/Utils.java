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

package com.google.capillary.demo.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.security.ProviderInstaller;
import com.google.capillary.Config;
import com.google.capillary.android.KeyManager;
import com.google.capillary.android.RsaEcdsaKeyManager;
import com.google.capillary.android.WebPushKeyManager;
import com.google.capillary.demo.common.KeyAlgorithm;
import com.google.capillary.demo.common.SecureNotification;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.UUID;

/**
 * Contains common helper functions used by the Android classes.
 */
public final class Utils {

  private static final String CHANNEL_ID = "default_channel";
  private static final String PREF_NAME =
      String.format("%s_preferences", Utils.class.getCanonicalName());
  private static final String HOST_KEY = "host";
  private static final String PORT_KEY = "port";
  private static final String USER_ID_KEY = "user_id";

  /**
   * Initializes the Android security provider and the Capillary library.
   */
  static void initialize(Context context) {
    updateAndroidSecurityProvider(context);
    try {
      Config.initialize();
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
    }
  }

  private static void updateAndroidSecurityProvider(Context context) {
    try {
      ProviderInstaller.installIfNeeded(context);
    } catch (GooglePlayServicesRepairableException e) {
      // Indicates that Google Play services is out of date, disabled, etc.
      e.printStackTrace();
      // Prompt the user to install/update/enable Google Play services.
      GoogleApiAvailability.getInstance()
          .showErrorNotification(context, e.getConnectionStatusCode());
    } catch (GooglePlayServicesNotAvailableException e) {
      // Indicates a non-recoverable error; the ProviderInstaller is not able
      // to install an up-to-date Provider.
      e.printStackTrace();
    }
  }

  /**
   * Creates a demo notification message and returns its serialized bytes.
   *
   * @param title the title of the notification.
   * @param keyAlgorithm the algorithm used to encrypt the notification.
   * @param isAuthKey whether the notification was encrypted using an authenticated key.
   * @return serialized notification bytes.
   */
  public static ByteString createSecureMessageBytes(
      String title, KeyAlgorithm keyAlgorithm, boolean isAuthKey) {
    return SecureNotification.newBuilder()
        .setId((int) System.currentTimeMillis())
        .setTitle(title)
        .setBody(String.format("Algorithm=%s, IsAuth=%s", keyAlgorithm, isAuthKey))
        .build().toByteString();
  }

  /**
   * Shows the given notification message as an Android notification.
   */
  static void showNotification(Context context, SecureNotification secureNotification) {
    initNotificationManager(context);

    Intent intent = new Intent(context, MainActivity.class);
    PendingIntent pendingIntent = PendingIntent.getActivity(
        context, 0, intent, PendingIntent.FLAG_ONE_SHOT);

    Notification.Builder notificationBuilder = new Notification.Builder(context)
        .setContentTitle(secureNotification.getTitle())
        .setContentText(secureNotification.getBody())
        .setSmallIcon(R.mipmap.ic_launcher)
        .setContentIntent(pendingIntent)
        .setAutoCancel(true);
    if (VERSION.SDK_INT >= VERSION_CODES.O) {
      notificationBuilder.setChannelId(CHANNEL_ID);
    }

    NotificationManager notificationManager =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    assert notificationManager != null;
    notificationManager.notify(secureNotification.getId(), notificationBuilder.build());
  }

  private static void initNotificationManager(Context context) {
    // No initialization is required for pre-O devices.
    if (VERSION.SDK_INT < VERSION_CODES.O) {
      return;
    }

    NotificationChannel channel = new NotificationChannel(
        CHANNEL_ID,
        context.getString(R.string.channel_name),
        NotificationManager.IMPORTANCE_DEFAULT);
    channel.setDescription(context.getString(R.string.channel_description));

    NotificationManager notificationManager =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    assert notificationManager != null;
    notificationManager.createNotificationChannel(channel);
  }

  /**
   * Creates a Capillary key manager for the specified key algorithm.
   */
  static KeyManager getKeyManager(Context context, KeyAlgorithm algorithm)
      throws IOException, GeneralSecurityException {
    switch (algorithm) {
      case RSA_ECDSA:
        try (InputStream senderVerificationKey =
            context.getResources().openRawResource(R.raw.sender_verification_key)) {
          return RsaEcdsaKeyManager.getInstance(
              context, AndroidConstants.RSA_ECDSA_KEYCHAIN_ID, senderVerificationKey);
        }
      case WEB_PUSH:
        return WebPushKeyManager.getInstance(context, AndroidConstants.WEB_PUSH_KEYCHAIN_ID);
      default:
        throw new IllegalArgumentException("unsupported key algorithm");
    }
  }

  /**
   * Saves the specified gRPC channel host and port in {@link SharedPreferences}.
   */
  static void addGrpcChannelParams(Context context, String host, int port) {
    getSharedPreferences(context).edit().putString(HOST_KEY, host).putInt(PORT_KEY, port).apply();
  }

  private static SharedPreferences getSharedPreferences(Context context) {
    Context storageContext = getDeviceProtectedStorageContext(context);
    return storageContext.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
  }

  private static Context getDeviceProtectedStorageContext(Context context) {
    if (VERSION.SDK_INT >= VERSION_CODES.N) {
      return context.createDeviceProtectedStorageContext();
    }
    return context;
  }

  /**
   * Removes gRPC channel host and port in {@link SharedPreferences}.
   */
  static void clearGrpcChannelParams(Context context) {
    getSharedPreferences(context).edit().remove(HOST_KEY).remove(PORT_KEY).apply();
  }

  /**
   * Returns the saved gRPC channel host.
   */
  static String getGrpcChannelHost(Context context) {
    return getSharedPreferences(context).getString(HOST_KEY, null);
  }

  /**
   * Returns the saved gRPC channel port.
   */
  static int getGrpcChannelPort(Context context) {
    return getSharedPreferences(context).getInt(PORT_KEY, 0);
  }

  /**
   * Creates a new gRPC channel to the host and port combination stored in
   * {@link SharedPreferences}.
   */
  static ManagedChannel createGrpcChannel(Context context) throws IOException {
    SharedPreferences sharedPreferences = getSharedPreferences(context);
    String host = sharedPreferences.getString(HOST_KEY, null);
    if (host == null) {
      throw new IOException("missing host");
    }
    int port = sharedPreferences.getInt(PORT_KEY, -1);
    if (port == -1) {
      throw new IOException("missing port");
    }
    try (InputStream certStream = context.getResources().openRawResource(R.raw.tls)) {
      return TlsOkHttpChannelGenerator.generate(host, port, certStream);
    }
  }

  /**
   * Returns a demo user ID for the current app instance.
   */
  static synchronized String getUserId(Context context) {
    SharedPreferences sharedPreferences = getSharedPreferences(context);
    String userId = sharedPreferences.getString(USER_ID_KEY, null);
    if (userId == null) {
      userId = UUID.randomUUID().toString();
      sharedPreferences.edit().putString(USER_ID_KEY, userId).apply();
    }
    return userId;
  }
}
