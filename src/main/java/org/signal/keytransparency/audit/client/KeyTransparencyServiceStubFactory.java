/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.client;

import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import io.micrometer.core.instrument.Metrics;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Value;
import jakarta.inject.Singleton;
import org.signal.keytransparency.audit.metrics.MetricsUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;

@Factory
class KeyTransparencyServiceStubFactory {
  private static final Logger logger = LoggerFactory.getLogger(KeyTransparencyServiceStubFactory.class);
  private static final String DAYS_UNTIL_AUDITOR_CLIENT_CERTIFICATE_EXPIRATION_GAUGE_NAME =
      MetricsUtil.name(KeyTransparencyServiceStubFactory.class, "daysUntilAuditorClientCertificateExpiration");

  @Singleton
  KeyTransparencyServiceGrpc.KeyTransparencyServiceBlockingStub keyTransparencyServiceClient(
      @Value("${auditor.key-transparency-service-host}") String host,
      @Value("${auditor.key-transparency-service-port}") int port,
      @Value("${auditor.client-certificate}") String clientCertificate,
      @Value("${auditor.client-private-key}") String clientPrivateKey) {
    try (
        final ByteArrayInputStream clientCertificateInputStream = new ByteArrayInputStream(
            clientCertificate.getBytes(StandardCharsets.UTF_8));
        final ByteArrayInputStream clientPrivateKeyInputStream = new ByteArrayInputStream(
            clientPrivateKey.getBytes(StandardCharsets.UTF_8))) {
      final ChannelCredentials tlsChannelCredentials = TlsChannelCredentials.newBuilder()
          .keyManager(clientCertificateInputStream, clientPrivateKeyInputStream)
          .build();

      configureClientCertificateMetrics(clientCertificate);
      final ManagedChannel channel = Grpc.newChannelBuilderForAddress(host, port, tlsChannelCredentials)
          .build();
      return KeyTransparencyServiceGrpc.newBlockingStub(channel);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private void configureClientCertificateMetrics(String clientCertificate) {
    final CertificateFactory cf;
    try {
      cf = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new AssertionError("JDKs are required to support X.509 algorithms", e);
    }

    try {
      final Collection<? extends Certificate> certificates = cf.generateCertificates(
          new ByteArrayInputStream(clientCertificate.getBytes(StandardCharsets.UTF_8)));

      if (certificates.isEmpty()) {
        logger.warn("No client certificate found");
        return;
      }

      if (certificates.size() > 1) {
        throw new IllegalArgumentException("Unexpected number of client certificates: " + certificates.size());
      }

      final Certificate certificate = certificates.iterator().next();

      if (certificate instanceof X509Certificate x509Cert) {
        final Instant expiration = Instant.ofEpochMilli(x509Cert.getNotAfter().getTime());

        Metrics.gauge(DAYS_UNTIL_AUDITOR_CLIENT_CERTIFICATE_EXPIRATION_GAUGE_NAME,
            this,
            (ignored) -> Duration.between(Instant.now(), expiration).toDays());

      } else {
        logger.error("Certificate was of unexpected type: {}", certificate.getClass().getName());
      }
    } catch (final CertificateException e) {
      logger.error("Unexpected error parsing auditor client certificate", e);
      throw new RuntimeException(e);
    }
  }
}
