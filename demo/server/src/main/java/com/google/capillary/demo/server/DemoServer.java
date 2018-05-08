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

package com.google.capillary.demo.server;

import com.google.capillary.Config;
import com.google.capillary.RsaEcdsaEncrypterManager;
import com.google.capillary.WebPushEncrypterManager;
import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.logging.Logger;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * The starting point of the demo app server.
 */
public final class DemoServer {

  private static final Logger logger = Logger.getLogger(DemoServer.class.getName());
  private static final String PORT_OPTION = "port";
  private static final String DATABASE_PATH_OPTION = "database_path";
  private static final String ECDSA_PRIVATE_KEY_PATH_OPTION = "ecdsa_private_key_path";
  private static final String TLS_CERT_PATH_OPTION = "tls_cert_path";
  private static final String TLS_PRIVATE_KEY_PATH_OPTION = "tls_private_key_path";
  private static final String SERVICE_ACCOUNT_CREDENTIALS_PATH_OPTION =
      "service_account_credentials_path";
  private static final String FIREBASE_PROJECT_ID_OPTION = "firebase_project_id";

  private Server server;

  /**
   * Launches the server.
   *
   * @param args the command line args.
   * @throws Exception as a catch-all exception in main method.
   */
  public static void main(String[] args) throws Exception {
    // Initialize the Capillary library.
    Config.initialize();

    // Obtain command line options.
    CommandLine cmd = generateCommandLine(args);

    // Initialize and start gRPC server.
    DemoServer server = new DemoServer();
    server.start(cmd);
    server.blockUntilShutdown();
  }

  private static CommandLine generateCommandLine(String[] commandLineArguments)
      throws ParseException {
    Option port = Option.builder()
        .longOpt(PORT_OPTION)
        .desc("The port to use.")
        .hasArg()
        .required()
        .type(Integer.class)
        .build();
    Option firebaseProjectId = Option.builder()
        .longOpt(FIREBASE_PROJECT_ID_OPTION)
        .desc("The ID of the Firebase project.")
        .hasArg()
        .required()
        .build();
    Option serviceAccountCredentialsPath = Option.builder()
        .longOpt(SERVICE_ACCOUNT_CREDENTIALS_PATH_OPTION)
        .desc("The path to Firebase service account credentials.")
        .hasArg()
        .required()
        .build();
    Option ecdsaPrivateKeyPath = Option.builder()
        .longOpt(ECDSA_PRIVATE_KEY_PATH_OPTION)
        .desc("The path to ecdsa private key.")
        .hasArg()
        .required()
        .build();
    Option tlsCertPath = Option.builder()
        .longOpt(TLS_CERT_PATH_OPTION)
        .desc("The path to tls cert.")
        .hasArg()
        .required()
        .build();
    Option tlsPrivateKeyPath = Option.builder()
        .longOpt(TLS_PRIVATE_KEY_PATH_OPTION)
        .desc("The path to tls private key.")
        .hasArg()
        .required()
        .build();
    Option databasePath = Option.builder()
        .longOpt(DATABASE_PATH_OPTION)
        .desc("The path to sqlite database.")
        .hasArg()
        .required()
        .build();

    Options options = new Options();
    options.addOption(port);
    options.addOption(firebaseProjectId);
    options.addOption(serviceAccountCredentialsPath);
    options.addOption(ecdsaPrivateKeyPath);
    options.addOption(tlsPrivateKeyPath);
    options.addOption(tlsCertPath);
    options.addOption(databasePath);

    CommandLineParser cmdLineParser = new DefaultParser();
    return cmdLineParser.parse(options, commandLineArguments);
  }

  private void start(CommandLine cmd) throws IOException, GeneralSecurityException, SQLException {
    // The port on which the server should run.
    int port = Integer.valueOf(cmd.getOptionValue(PORT_OPTION));
    // The FCM message sender.
    FcmSender fcmSender = new FcmSender(
        cmd.getOptionValue(FIREBASE_PROJECT_ID_OPTION),
        cmd.getOptionValue(SERVICE_ACCOUNT_CREDENTIALS_PATH_OPTION));
    // The Capillary encrypter managers.
    RsaEcdsaEncrypterManager rsaEcdsaEncrypterManager;
    try (FileInputStream senderSigningKey =
        new FileInputStream(cmd.getOptionValue(ECDSA_PRIVATE_KEY_PATH_OPTION))) {
      rsaEcdsaEncrypterManager = new RsaEcdsaEncrypterManager(senderSigningKey);
    }
    WebPushEncrypterManager webPushEncrypterManager = new WebPushEncrypterManager();
    // The {certificate, private key} pair to use for gRPC TLS.
    File tlsCertFile = new File(cmd.getOptionValue(TLS_CERT_PATH_OPTION));
    File tlsPrivateKeyFile = new File(cmd.getOptionValue(TLS_PRIVATE_KEY_PATH_OPTION));
    // The interface to demo SQLite DB.
    DemoDb db = new DemoDb(
        "jdbc:sqlite:" + cmd.getOptionValue(DATABASE_PATH_OPTION));
    // The demo service.
    BindableService demoService =
        new DemoServiceImpl(db, rsaEcdsaEncrypterManager, webPushEncrypterManager, fcmSender);
    // Create and start the gRPC server instance.
    server = ServerBuilder.forPort(port)
        .useTransportSecurity(tlsCertFile, tlsPrivateKeyFile)
        .addService(demoService)
        .build()
        .start();
    logger.info("Server started, listening on " + port);

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      // Use stderr here since the logger may have been reset by its JVM shutdown hook.
      System.err.println("*** shutting down gRPC server since JVM is shutting down");
      shutdown();
      System.err.println("*** server shut down");
    }));
  }

  // Await termination on the main thread since the gRPC library uses daemon threads.
  private void blockUntilShutdown() throws InterruptedException {
    if (server != null) {
      server.awaitTermination();
    }
  }

  private void shutdown() {
    if (server != null) {
      server.shutdown();
    }
  }
}
