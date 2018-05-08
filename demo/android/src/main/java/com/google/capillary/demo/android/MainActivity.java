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

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.AsyncTask;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import com.google.capillary.android.KeyManager;
import com.google.capillary.demo.android.callables.DecryptSavedCiphertexts;
import com.google.capillary.demo.android.callables.DelIid;
import com.google.capillary.demo.android.callables.DelKey;
import com.google.capillary.demo.android.callables.GenKey;
import com.google.capillary.demo.android.callables.LogToken;
import com.google.capillary.demo.android.callables.RegKey;
import com.google.capillary.demo.android.callables.RegUser;
import com.google.capillary.demo.android.callables.RequestMessage;
import com.google.capillary.demo.common.KeyAlgorithm;
import io.grpc.ManagedChannel;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.Callable;

/**
 * The main activity of the Android demo app for Capillary library.
 */
public final class MainActivity extends AppCompatActivity {

  private EditText hostEdit;
  private EditText portEdit;
  private Button connectButton;
  private Button disconnectButton;
  private Button logTokenButton;
  private Button regUserButton;
  private Button delIidButton;
  private Spinner algorithmSpinner;
  private Spinner isAuthSpinner;
  private Button genKeyButton;
  private Button delKeyButton;
  private Button regKeyButton;
  private EditText delayEdit;
  private Button reqMessageButton;
  private TextView resultText;
  private ManagedChannel channel;
  private DemoCapillaryHandler handler;
  private DeviceUnlockedBroadcastReceiver deviceUnlockedBroadcastReceiver;

  /**
   * An extension of {@link AsyncTask} that attempts complete a unit of work provided as a
   * {@link Callable} and outputs the results to the UI.
   */
  @SuppressLint("StaticFieldLeak") // These tasks are not expected take too long.
  private final class DemoAsyncTask extends AsyncTask<Void, Void, String> {

    private final Callable<String> callable;

    private DemoAsyncTask(Callable<String> callable) {
      this.callable = callable;
    }

    @Override
    protected String doInBackground(Void... nothing) {
      try {
        String logs = callable.call();
        return "Background task success!\n" + logs;
      } catch (Exception e) {
        e.printStackTrace();
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        pw.flush();
        return "Background task failure...\n" + sw;
      }
    }

    @Override
    protected void onPostExecute(String result) {
      replaceText(result);
    }
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    // Initialize references to UI elements.
    hostEdit = findViewById(R.id.host_edit_text);
    portEdit = findViewById(R.id.port_edit_text);
    connectButton = findViewById(R.id.connect_button);
    disconnectButton = findViewById(R.id.disconnect_button);
    logTokenButton = findViewById(R.id.log_token_button);
    regUserButton = findViewById(R.id.reg_user_button);
    delIidButton = findViewById(R.id.del_iid_button);
    algorithmSpinner = findViewById(R.id.algorithm_spinner);
    isAuthSpinner = findViewById(R.id.is_auth_spinner);
    genKeyButton = findViewById(R.id.gen_key_button);
    regKeyButton = findViewById(R.id.reg_key_button);
    delKeyButton = findViewById(R.id.del_key_button);
    delayEdit = findViewById(R.id.delay_edit_text);
    reqMessageButton = findViewById(R.id.req_message_button);
    resultText = findViewById(R.id.result_text);

    // Update UI elements as needed.
    resultText.setMovementMethod(new ScrollingMovementMethod());
    ArrayAdapter<KeyAlgorithm> algorithmAdapter = new ArrayAdapter<>(
        this,
        android.R.layout.simple_spinner_item,
        new ArrayList<>(Arrays.asList(KeyAlgorithm.values())));
    algorithmAdapter.remove(KeyAlgorithm.UNRECOGNIZED);
    algorithmAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    algorithmSpinner.setAdapter(algorithmAdapter);
    ArrayAdapter<Boolean> isAuthAdapter = new ArrayAdapter<>(
        this,
        android.R.layout.simple_spinner_item,
        Arrays.asList(Boolean.FALSE, Boolean.TRUE));
    isAuthAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    isAuthSpinner.setAdapter(isAuthAdapter);

    // Initialize Capillary library, gRPC channel, and the Capillary handler.
    Utils.initialize(this);
    initChannelAndDependents();

    // In API levels 26 and above, ACTION_USER_PRESENT broadcast receivers cannot be registered
    // in the manifest. So, we register it here. Alternatively, one could implement a background
    // service to listen to this event in all API levels.
    if (VERSION.SDK_INT >= VERSION_CODES.O) {
      deviceUnlockedBroadcastReceiver = new DeviceUnlockedBroadcastReceiver();
      IntentFilter filter = new IntentFilter();
      filter.addAction(Intent.ACTION_USER_PRESENT);
      registerReceiver(deviceUnlockedBroadcastReceiver, filter);
    }
  }

  private void initChannelAndDependents() {
    try {
      channel = Utils.createGrpcChannel(this);
      handler = new DemoCapillaryHandler(this, channel);
      // For API levels 26 and above, decrypt any Capillary ciphertexts that have been saved since
      // the last launch of this activity. This is not needed if the ACTION_USER_PRESENT broadcast
      // receiver were to be watched in a background service.
      if (VERSION.SDK_INT >= VERSION_CODES.O) {
        KeyManager rsaEcdsaKeyManager = Utils.getKeyManager(this, KeyAlgorithm.RSA_ECDSA);
        new DemoAsyncTask(new DecryptSavedCiphertexts(
            handler, rsaEcdsaKeyManager.getDecrypterManager(), KeyAlgorithm.RSA_ECDSA)).execute();
        KeyManager webPushKeyManager = Utils.getKeyManager(this, KeyAlgorithm.WEB_PUSH);
        new DemoAsyncTask(new DecryptSavedCiphertexts(
            handler, webPushKeyManager.getDecrypterManager(), KeyAlgorithm.WEB_PUSH)).execute();
      }
      initChannelUiElements(true);
    } catch (IOException | GeneralSecurityException e) {
      e.printStackTrace();
      initChannelUiElements(false);
    }
  }

  private void initChannelUiElements(boolean channelOpened) {
    hostEdit.setEnabled(!channelOpened);
    portEdit.setEnabled(!channelOpened);
    connectButton.setEnabled(!channelOpened);
    disconnectButton.setEnabled(channelOpened);
    logTokenButton.setEnabled(channelOpened);
    regUserButton.setEnabled(channelOpened);
    delIidButton.setEnabled(channelOpened);
    algorithmSpinner.setEnabled(channelOpened);
    isAuthSpinner.setEnabled(channelOpened);
    genKeyButton.setEnabled(channelOpened);
    regKeyButton.setEnabled(channelOpened);
    delKeyButton.setEnabled(channelOpened);
    delayEdit.setEnabled(channelOpened);
    reqMessageButton.setEnabled(channelOpened);
    if (channelOpened) {
      hostEdit.setText(Utils.getGrpcChannelHost(this));
      portEdit.setText(String.valueOf(Utils.getGrpcChannelPort(this)));
    }
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();

    if (VERSION.SDK_INT >= VERSION_CODES.O) {
      unregisterReceiver(deviceUnlockedBroadcastReceiver);
    }

    if (channel != null) {
      channel.shutdown();
    }
  }

  private void replaceText(String text) {
    resultText.setText("");
    appendText(text);
  }

  private void appendText(String text) {
    resultText.append(text + "\n");
    hideKeyboard();
  }

  private void hideKeyboard() {
    InputMethodManager inputMethodManager =
        (InputMethodManager) getSystemService(Activity.INPUT_METHOD_SERVICE);
    assert inputMethodManager != null;
    View view = getCurrentFocus();
    if (view == null) {
      view = new View(this);
    }
    inputMethodManager.hideSoftInputFromWindow(view.getWindowToken(), 0);
  }

  /**
   * Initializes a gRPC channel to supplied host and port combination.
   */
  public void connect(View view) throws IOException {
    String host = hostEdit.getText().toString();
    String portStr = portEdit.getText().toString();
    int port = TextUtils.isEmpty(portStr) ? 0 : Integer.valueOf(portStr);
    Utils.addGrpcChannelParams(this, host, port);
    initChannelAndDependents();
  }

  /**
   * Disconnects the gRPC channel and resets saved host and port combination.
   */
  public void disconnect(View view) {
    channel.shutdown();
    channel = null;
    handler = null;
    Utils.clearGrpcChannelParams(this);
    initChannelUiElements(false);
  }

  /**
   * Prints the current FCM token in the UI.
   */
  public void logToken(View view) {
    new DemoAsyncTask(new LogToken()).execute();
  }

  /**
   * Registers the current user with the application server.
   */
  public void regUser(View view) {
    String userId = Utils.getUserId(this);
    new DemoAsyncTask(new RegUser(channel, userId)).execute();
  }

  /**
   * Deletes the Firebase instance ID from the device.
   */
  public void delIid(View view) {
    new DemoAsyncTask(new DelIid()).execute();
  }

  /**
   * Generates a new Capillary key pair with the selected algorithm and isAuth values in the device.
   */
  public void genKey(View view) throws IOException, GeneralSecurityException {
    KeyAlgorithm algorithm = (KeyAlgorithm) algorithmSpinner.getSelectedItem();
    boolean isAuth = (Boolean) isAuthSpinner.getSelectedItem();
    KeyManager keyManager = Utils.getKeyManager(this, algorithm);
    new DemoAsyncTask(new GenKey(keyManager, algorithm, isAuth)).execute();
  }

  /**
   * Registers the Capillary public key with the selected algorithm and isAuth values with the
   * application server.
   */
  public void regKey(View view) throws IOException, GeneralSecurityException {
    KeyAlgorithm algorithm = (KeyAlgorithm) algorithmSpinner.getSelectedItem();
    boolean isAuth = (Boolean) isAuthSpinner.getSelectedItem();
    KeyManager keyManager = Utils.getKeyManager(this, algorithm);
    new DemoAsyncTask(new RegKey(handler, keyManager, algorithm, isAuth)).execute();
  }

  /**
   * Deletes the Capillary public key with the selected algorithm and isAuth values from the device.
   */
  public void delKey(View view) throws IOException, GeneralSecurityException {
    KeyAlgorithm algorithm = (KeyAlgorithm) algorithmSpinner.getSelectedItem();
    boolean isAuth = (Boolean) isAuthSpinner.getSelectedItem();
    KeyManager keyManager = Utils.getKeyManager(this, algorithm);
    new DemoAsyncTask(new DelKey(keyManager, algorithm, isAuth)).execute();
  }

  /**
   * Requests the application server to send a Capillary-encrypted demo message over FCM with the
   * selected algorithm and isAuth values after the specified delay.
   */
  public void reqMessage(View view) {
    KeyAlgorithm algorithm = (KeyAlgorithm) algorithmSpinner.getSelectedItem();
    boolean isAuth = (Boolean) isAuthSpinner.getSelectedItem();
    String userId = Utils.getUserId(this);
    String delayStr = delayEdit.getText().toString();
    int delay = TextUtils.isEmpty(delayStr) ? 0 : Integer.valueOf(delayStr);
    new DemoAsyncTask(new RequestMessage(channel, algorithm, userId, isAuth, delay)).execute();
  }
}
