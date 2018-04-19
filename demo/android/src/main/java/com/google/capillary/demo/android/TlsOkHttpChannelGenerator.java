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

import io.grpc.ManagedChannel;
import io.grpc.okhttp.OkHttpChannelBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

/**
 * A helper class to create an OkHttp based TLS channel.
 */
final class TlsOkHttpChannelGenerator {

  /**
   * Creates a new {@link ManagedChannel} to the given host and port with the given TLS
   * certificates.
   */
  static ManagedChannel generate(String host, int port, InputStream certStream) throws IOException {
    OkHttpChannelBuilder channelBuilder = OkHttpChannelBuilder.forAddress(host, port);
    try {
      SSLSocketFactory sslSocketFactory = getSslSocketFactory(certStream);
      channelBuilder.sslSocketFactory(sslSocketFactory);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return channelBuilder.build();
  }

  private static SSLSocketFactory getSslSocketFactory(InputStream certStream)
      throws Exception {
    if (certStream == null) {
      return (SSLSocketFactory) SSLSocketFactory.getDefault();
    }

    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, getTrustManagers(certStream), null);
    return context.getSocketFactory();
  }

  private static TrustManager[] getTrustManagers(InputStream certStream) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(certStream);
    X500Principal principal = cert.getSubjectX500Principal();
    keyStore.setCertificateEntry(principal.getName("RFC2253"), cert);
    // Set up trust manager factory to use our key store.
    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(keyStore);
    return trustManagerFactory.getTrustManagers();
  }
}
