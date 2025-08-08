/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.client;

import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.inject.Singleton;
import org.signal.keytransparency.audit.*;
import org.signal.keytransparency.audit.AuditorProof;
import org.signal.keytransparency.audit.AuditorUpdate;
import org.signal.keytransparency.audit.metrics.MetricsUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import java.time.Duration;

/**
 * A client that talks to the key transparency service to request updates or provide a signed tree head.
 */
@Singleton
public class KeyTransparencyAuditorServiceClient {

  private final KeyTransparencyAuditorServiceGrpc.KeyTransparencyAuditorServiceBlockingStub stub;
  private final Counter sendSignedTreeHeadCounter;
  private final DistributionSummary getUpdatesDistributionSummary;
  private static final Logger logger = LoggerFactory.getLogger(KeyTransparencyAuditorServiceClient.class);

  public KeyTransparencyAuditorServiceClient(final KeyTransparencyAuditorServiceGrpc.KeyTransparencyAuditorServiceBlockingStub stub,
                                             final MeterRegistry meterRegistry) {
    this.stub = stub;
    this.sendSignedTreeHeadCounter = meterRegistry.counter(
        MetricsUtil.name(KeyTransparencyAuditorServiceClient.class, "sendSignedTreeHead"));
    this.getUpdatesDistributionSummary = DistributionSummary
        .builder(MetricsUtil.name(KeyTransparencyAuditorServiceClient.class, "getUpdates"))
        .distributionStatisticExpiry(Duration.ofHours(2))
        .register(meterRegistry);
  }

  /**
   * Fetch a stream of updates from the key transparency service.
   *
   * @param start     the index of the next update to audit in the key transparency log
   * @param batchSize the maximum number of updates to return
   * @return a stream of all updates from the key transparency service starting from the given {@code start} and
   * terminating at the last update known to the key transparency service
   */
  public Flux<AuditorUpdate> getUpdates(final long start, final int batchSize) {
    return Flux.from(fetchPage(start, batchSize))
        .expand(auditResponseAndOffset -> {
          final AuditResponse auditResponse = auditResponseAndOffset.getT1();
          final long offset = auditResponseAndOffset.getT2();

          if (auditResponse.getMore()) {
            return fetchPage(offset, batchSize);
          } else {
            return Mono.empty();
          }
        })
        .flatMapIterable(auditResponseAndOffset -> auditResponseAndOffset.getT1().getUpdatesList())
        .map(KeyTransparencyAuditorServiceClient::fromAuditorUpdateProtobuf);
  }

  private Mono<Tuple2<AuditResponse, Long>> fetchPage(final long start, final int batchSize) {
    return Mono.fromCallable(() -> stub.audit(AuditRequest.newBuilder()
            .setStart(start)
            .setLimit(batchSize)
            .build()))
        .doOnNext(auditResponse -> getUpdatesDistributionSummary.record(auditResponse.getUpdatesCount()))
        .map(auditResponse -> Tuples.of(auditResponse, start + auditResponse.getUpdatesCount()))
        .onErrorResume(throwable -> {
          logger.error("Unexpected error fetching updates", throwable);
          return Mono.empty();
        });
  }

  @VisibleForTesting
  public static AuditorUpdate fromAuditorUpdateProtobuf(
      final org.signal.keytransparency.audit.client.AuditorUpdate protobuf) {
    AuditorProof proof = switch (protobuf.getProof().getProofCase()) {
      case NEW_TREE -> new NewTreeProof();
      case DIFFERENT_KEY -> new DifferentKeyProof(
          protobuf.getProof().getDifferentKey().getOldSeed().toByteArray(),
          protobuf.getProof().getDifferentKey().getCopathList().stream().map(ByteString::toByteArray).toList());
      case SAME_KEY -> new SameKeyProof(
          protobuf.getProof().getSameKey().getCounter(),
          protobuf.getProof().getSameKey().getPosition(),
          protobuf.getProof().getSameKey().getCopathList().stream().map(ByteString::toByteArray).toList());
      case PROOF_NOT_SET -> throw new IllegalArgumentException("Unexpected proof type");
    };
    return new AuditorUpdate(protobuf.getReal(),
        protobuf.getIndex().toByteArray(),
        protobuf.getSeed().toByteArray(),
        protobuf.getCommitment().toByteArray(),
        proof);
  }

  /**
   * Send a signed, audited tree head to the key transparency service.
   *
   * @param treeSize  the number of updates in the auditor's view of the log tree
   * @param timestamp the time the signature was generated in milliseconds since the Unix epoch
   * @param signature a signature computed over the auditor's view of the log tree's current state and long-term log
   *                  configuration
   */
  public void setTreeHead(final long treeSize, final long timestamp, final byte[] signature) {
    final AuditorTreeHead treeHead = AuditorTreeHead.newBuilder()
        .setTreeSize(treeSize)
        .setTimestamp(timestamp)
        .setSignature(ByteString.copyFrom(signature))
        .build();
    try {
      stub.setAuditorHead(treeHead);
      sendSignedTreeHeadCounter.increment();
    } catch (final Exception e) {
      logger.error("Encountered error sending signed tree head to the key transparency service", e);
      throw e;
    }
  }
}
