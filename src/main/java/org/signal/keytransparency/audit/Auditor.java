/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micronaut.context.annotation.Value;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import org.signal.keytransparency.audit.client.KeyTransparencyServiceClient;
import org.signal.keytransparency.audit.metrics.MetricsUtil;
import org.signal.keytransparency.audit.storage.AuditorState;
import org.signal.keytransparency.audit.storage.AuditorStateAndSignature;
import org.signal.keytransparency.audit.storage.AuditorStateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides third-party auditing for the key transparency service by fetching and processing batches of updates and
 * periodically sending back signed tree heads. If an update contains an inconsistency with the auditor's prefix tree
 * root hash or the auditor's view of the log tree, the auditor will stop sending back signed tree heads to the key
 * transparency service.
 */
@Singleton
public class Auditor {

  private static final Logger logger = LoggerFactory.getLogger(Auditor.class);
  private static final int TREE_HEAD_BYTE_LENGTH = 153;
  private static final byte[] CIPHER_SUITE_IDENTIFIER = {0x00, 0x00};
  private static final byte THIRD_PARTY_AUDITING_MODE = 0x03;
  private static final int ED25519_KEY_LENGTH = 32;
  private final Counter updatesProcessedCounter;
  private final Counter storeAuditorStateCounter;
  private final Counter getAuditorStateCounter;
  private final Timer auditTimer;
  private final DistributionSummary updatesPerBatchDistributionSummary;
  private final AuditorConfiguration configuration;
  private final AuditorStateRepository auditorStorage;
  private final KeyTransparencyServiceClient keyTransparencyServiceClient;
  private final int sendSignaturePageSize;
  private final Duration sendSignatureInterval;
  private final ReentrantLock treeUpdateLock;
  private final Clock clock;
  private CondensedPrefixTree condensedPrefixTree;
  private CondensedLogTree condensedLogTree;
  private long totalUpdatesProcessed;
  private Instant lastTreeHeadSent;
  private long updatesSinceLastTreeHeadSent;

  public Auditor(final AuditorConfiguration configuration,
      final AuditorStateRepository auditorStorage,
      final KeyTransparencyServiceClient keyTransparencyServiceClient,
      // the auditor must be no more than 1e7 entries behind
      @Value("${auditor.signature.page-size:1000000}") int sendSignaturePageSize,
      // the auditor must be no more than 7 days behind
      @Value("${auditor.signature.interval:PT1H}") Duration sendSignatureInterval,
      final MeterRegistry meterRegistry,
      final Clock clock) throws NoSuchAlgorithmException, InvalidKeyException {
    this.configuration = configuration;
    this.auditorStorage = auditorStorage;
    this.keyTransparencyServiceClient = keyTransparencyServiceClient;
    this.sendSignaturePageSize = sendSignaturePageSize;
    this.sendSignatureInterval = sendSignatureInterval;
    this.updatesProcessedCounter = meterRegistry.counter(MetricsUtil.name(Auditor.class, "updatesProcessed"));
    this.getAuditorStateCounter = meterRegistry.counter(MetricsUtil.name(Auditor.class, "getAuditorState"));
    this.storeAuditorStateCounter = meterRegistry.counter(MetricsUtil.name(Auditor.class, "storeAuditorState"));
    this.auditTimer = meterRegistry.timer(MetricsUtil.name(Auditor.class, "batchTimer"));
    this.updatesPerBatchDistributionSummary = DistributionSummary
        .builder(MetricsUtil.name(Auditor.class, "updatesPerBatch"))
        .distributionStatisticExpiry(Duration.ofHours(2))
        .register(meterRegistry);
    this.treeUpdateLock = new ReentrantLock();
    this.clock = clock;
    this.lastTreeHeadSent = clock.instant();
    // Check if the Ed25519 algorithm is supported and if the keys are valid
    final Signature testSignature = Signature.getInstance("Ed25519");
    testSignature.initSign(configuration.privateKey());
    testSignature.initVerify(configuration.publicKey());
  }

  @PostConstruct
  @VisibleForTesting
  void loadStoredState() throws IOException, InvalidAuditorSignatureException {

    treeUpdateLock.lock();

    try {

      getAuditorStateCounter.increment();
      final Optional<byte[]> storedState = auditorStorage.getAuditorStateAndSignature();

      if (storedState.isPresent()) {
        final AuditorStateAndSignature auditorStateAndSignature = AuditorStateAndSignature.parseFrom(storedState.get());

        verifySignature(auditorStateAndSignature.getSerializedAuditorState().toByteArray(),
            auditorStateAndSignature.getSignature().toByteArray(),
            configuration.publicKey());

        final AuditorState auditorState = AuditorState.parseFrom(auditorStateAndSignature.getSerializedAuditorState());

        final Collection<LogTreeNode> logTreeNodes = auditorState.getLogTreeNodesList().stream()
            .map(Auditor::fromLogTreeNodeProtobuf).toList();
        condensedLogTree = new CondensedLogTree(logTreeNodes, auditorState.getTotalUpdatesProcessed());
        condensedPrefixTree = new CondensedPrefixTree(auditorState.getCurrentPrefixTreeRootHash().toByteArray());
        totalUpdatesProcessed = auditorState.getTotalUpdatesProcessed();
      } else {
        condensedLogTree = new CondensedLogTree();
        condensedPrefixTree = new CondensedPrefixTree();
        totalUpdatesProcessed = 0;
      }
    } finally {
      treeUpdateLock.unlock();
    }
  }

  public boolean isHealthy() {
    return true;
  }

  public boolean isReady() {
    return condensedLogTree != null && condensedPrefixTree != null;
  }

  /**
   * <p>Fetches and processes batches of updates from the key transparency service.
   * For each update in a batch, it does a few things:</p>
   * <ol>
   *   <li>If the auditor has a current prefix tree root hash, check that it matches the one used by the update
   *      as a starting point</li>
   *   <li>Calculate a new prefix tree root hash</li>
   *   <li>Calculate a new log tree leaf hash using the new prefix tree root hash and the commitment in the update</li>
   *   <li>Calculate the new log tree root hash using the new log tree leaf hash and previously stored log tree hashes</li>
   *   <li>Updates its current view of the prefix tree root hash</li>
   * </ol>
   * <p>Periodically, the auditor persists {@link AuditorState} and returns a signature
   * over the log tree head to the key transparency service,
   * indicating that its view of the state of the world up to the given update matches.</p>
   */
  @Scheduled(fixedDelay = "${auditor.interval:1m}")
  void auditKeyTransparencyService() {

    if (!treeUpdateLock.tryLock()) {
      // This should only happen at startup, if loadStoredState() hasn't completed.
      logger.warn("Lock unavailable; skipping");
      return;
    }

    final Timer.Sample sample = Timer.start();

    try {

      final long numUpdatesProcessedInThisRun =
          keyTransparencyServiceClient.getUpdates(totalUpdatesProcessed, configuration.batchSize())
              .doOnNext(update -> {

                try {
                  condensedPrefixTree.applyUpdate(update, totalUpdatesProcessed);
                } catch (final InvalidProofException e) {
                  logger.error("Encountered invalid proof", e);
                  throw new RuntimeException(e);
                }

                condensedLogTree.addLeafNode(update.commitment(), condensedPrefixTree.getRootHash().orElseThrow(),
                    totalUpdatesProcessed);
                updatesProcessedCounter.increment();
                totalUpdatesProcessed += 1;
                updatesSinceLastTreeHeadSent += 1;

                setTreeHeadAndStoreAuditorStateIfNecessary();
              })
              .count()
              .blockOptional()
              .orElse(0L);

      updatesPerBatchDistributionSummary.record(numUpdatesProcessedInThisRun);

      // In case there are no updates to process,
      // we still want to send an auditor tree head and persist state after a certain time interval.
      setTreeHeadAndStoreAuditorStateIfNecessary();
    } finally {
      treeUpdateLock.unlock();
      sample.stop(auditTimer);
    }
  }


  private void setTreeHeadAndStoreAuditorStateIfNecessary() {
    if (clock.instant().isBefore(lastTreeHeadSent.plus(sendSignatureInterval))
        && updatesSinceLastTreeHeadSent < sendSignaturePageSize) {
      return;
    }

    treeUpdateLock.lock();

    try {

      // Set tree head in key transparency service
      final long timestampInMilliseconds = clock.instant().toEpochMilli();

      keyTransparencyServiceClient.setTreeHead(totalUpdatesProcessed, timestampInMilliseconds,
          generateTreeHeadSignature(
              configuration.keyTransparencyServiceSigningPublicKey(),
              configuration.keyTransparencyServiceVrfPublicKey(),
              configuration.publicKey(),
              totalUpdatesProcessed,
              timestampInMilliseconds,
              condensedLogTree.getRootHash(),
              configuration.privateKey()
          )
      );

      try {
        // Store auditor state - only persist to storage if the remote call succeeds.
        // This prevents storing corrupted state, and allows corruption to be resolved by restarting the auditor.
        final ByteString serializedAuditorState = AuditorState.newBuilder()
            .setTotalUpdatesProcessed(totalUpdatesProcessed)
            .setCurrentPrefixTreeRootHash(ByteString.copyFrom(condensedPrefixTree.getRootHash().orElseThrow()))
            .addAllLogTreeNodes(condensedLogTree.getNodes().stream().map(Auditor::toLogTreeNodeProtobuf).toList())
            .build()
            .toByteString();

        final byte[] signature = generateSignature(serializedAuditorState.toByteArray(), configuration.privateKey());
        final AuditorStateAndSignature auditorStateAndSignature = AuditorStateAndSignature.newBuilder()
            .setSerializedAuditorState(serializedAuditorState)
            .setSignature(ByteString.copyFrom(signature))
            .build();
        auditorStorage.storeAuditorStateAndSignature(auditorStateAndSignature.toByteArray());
        storeAuditorStateCounter.increment();

      } catch (final IOException e) {
        throw new UncheckedIOException(e);
      }

      lastTreeHeadSent = clock.instant();
      updatesSinceLastTreeHeadSent = 0;
    } finally {
      treeUpdateLock.unlock();
    }
  }

  @VisibleForTesting
  static byte[] generateTreeHeadSignature(
      final EdECPublicKey keyTransparencyServicePublicSigningKey,
      final EdECPublicKey keyTransparencyServicePublicVrfKey,
      final EdECPublicKey auditorPublicKey,
      final long treeSize,
      final long timestamp,
      final byte[] logTreeRootHash,
      final EdECPrivateKey auditorPrivateKey) {
    final ByteBuffer buffer = ByteBuffer.allocate(TREE_HEAD_BYTE_LENGTH);
    buffer.put(CIPHER_SUITE_IDENTIFIER);
    buffer.put(THIRD_PARTY_AUDITING_MODE);

    final byte[] keyTransparencyServicePublicSigningKeyBytes = getRawPublicKeyBytes(
        keyTransparencyServicePublicSigningKey);
    buffer.putShort((short) keyTransparencyServicePublicSigningKeyBytes.length);
    buffer.put(keyTransparencyServicePublicSigningKeyBytes);

    final byte[] keyTransparencyServicePublicVrfKeyBytes = getRawPublicKeyBytes(keyTransparencyServicePublicVrfKey);
    buffer.putShort((short) keyTransparencyServicePublicVrfKeyBytes.length);
    buffer.put(keyTransparencyServicePublicVrfKeyBytes);

    final byte[] auditorPublicKeyBytes = getRawPublicKeyBytes(auditorPublicKey);
    buffer.putShort((short) auditorPublicKeyBytes.length);
    buffer.put(auditorPublicKeyBytes);

    buffer.putLong(treeSize);
    buffer.putLong(timestamp);
    buffer.put(logTreeRootHash);

    return generateSignature(buffer.array(), auditorPrivateKey);
  }

  @VisibleForTesting
  byte[] getLogTreeRootHash() {
    return condensedLogTree.getRootHash();
  }

  private static byte[] getRawPublicKeyBytes(final EdECPublicKey edECPublicKey) {
    final byte[] x509Bytes = edECPublicKey.getEncoded();

    // The last 32 bytes of an X.509 encoding of an Ed25519 public key are the raw bytes of the key itself
    return Arrays.copyOfRange(x509Bytes, x509Bytes.length - ED25519_KEY_LENGTH, x509Bytes.length);
  }

  @VisibleForTesting
  static byte[] generateSignature(final byte[] dataToSign, final EdECPrivateKey auditorPrivateKey) {
    try {
      final Signature signature = Signature.getInstance("Ed25519");
      signature.initSign(auditorPrivateKey);
      signature.update(dataToSign);
      return signature.sign();
    } catch (final NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      // We checked for Ed25519 support and key validity at construction time
      // and initialized the signature object for signing
      throw new AssertionError(e);
    }
  }

  @VisibleForTesting
  static void verifySignature(final byte[] dataToSign, final byte[] expectedSignature,
      final EdECPublicKey auditorPublicKey) throws InvalidAuditorSignatureException {
    try {
      final Signature signature = Signature.getInstance("Ed25519");
      signature.initVerify(auditorPublicKey);
      signature.update(dataToSign);
      if (!signature.verify(expectedSignature)) {
        logger.error("Invalid auditor signature");
        throw new InvalidAuditorSignatureException("Signature did not match");
      }
    } catch (final NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      // We checked for Ed25519 support and key validity at construction time
      // and initialized the signature object for signing
      throw new AssertionError(e);
    }
  }

  private static org.signal.keytransparency.audit.storage.LogTreeNode toLogTreeNodeProtobuf(
      final LogTreeNode logTreeNode) {
    return org.signal.keytransparency.audit.storage.LogTreeNode.newBuilder()
        .setId(logTreeNode.id())
        .setHash(ByteString.copyFrom(logTreeNode.hash()))
        .build();
  }

  private static LogTreeNode fromLogTreeNodeProtobuf(
      final org.signal.keytransparency.audit.storage.LogTreeNode protobuf) {
    return new LogTreeNode(protobuf.getId(), protobuf.getHash().toByteArray());
  }

  @VisibleForTesting
  AuditorConfiguration getConfiguration() {
    return configuration;
  }
}
