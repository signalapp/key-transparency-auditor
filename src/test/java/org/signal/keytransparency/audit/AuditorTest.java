/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.signal.keytransparency.audit.client.AuditResponse;
import org.signal.keytransparency.audit.client.KeyTransparencyServiceClient;
import org.signal.keytransparency.audit.storage.AuditorState;
import org.signal.keytransparency.audit.storage.AuditorStateRepository;
import org.signal.keytransparency.audit.storage.LogTreeNode;
import org.signal.keytransparency.audit.util.TestClock;
import reactor.core.publisher.Flux;

public class AuditorTest {
  private AuditorStateRepository auditorStateRepository;
  private KeyTransparencyServiceClient keyTransparencyServiceClient;
  private AuditorConfiguration auditorConfiguration;
  private Auditor auditor;
  private TestClock clock;

  private static TestVectors testVectors;

  @BeforeAll
  static void init() throws IOException {
    try (final InputStream testVectorInputStream = AuditorTest.class.getResourceAsStream("katie_test_vectors.pb")) {
      if (testVectorInputStream == null) {
        throw new IOException("Could not load test vectors");
      }
      testVectors = TestVectors.parseFrom(testVectorInputStream);
    }
  }

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAuditorSignatureException {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
    final KeyPair auditorKeyPair = keyPairGenerator.generateKeyPair();
    final KeyPair keyTransparencyServiceSigningKeyPair = keyPairGenerator.generateKeyPair();
    final KeyPair keyTransparencyServiceVrfKeyPair = keyPairGenerator.generateKeyPair();

    auditorStateRepository = mock(AuditorStateRepository.class);
    auditorConfiguration = new AuditorConfiguration(
        (EdECPrivateKey) auditorKeyPair.getPrivate(),
        (EdECPublicKey) auditorKeyPair.getPublic(),
        (EdECPublicKey) keyTransparencyServiceSigningKeyPair.getPublic(),
        (EdECPublicKey) keyTransparencyServiceVrfKeyPair.getPublic(),
        1
    );

    when(auditorStateRepository.getAuditorStateAndSignature()).thenReturn(Optional.empty());
    clock  = TestClock.pinned(Instant.EPOCH);
    keyTransparencyServiceClient = mock(KeyTransparencyServiceClient.class);
    auditor = new Auditor(auditorConfiguration, auditorStateRepository, keyTransparencyServiceClient, 100,
        Duration.ofMinutes(1), new SimpleMeterRegistry(), clock);
    auditor.loadStoredState();
  }

  @ParameterizedTest
  @MethodSource
  void testFailures(final AuditResponse auditResponse) throws IOException {
    when(auditorStateRepository.getAuditorStateAndSignature()).thenReturn(Optional.empty());
    when(keyTransparencyServiceClient.getUpdates(anyLong(), anyInt()))
        .thenReturn(Flux.fromIterable(auditResponse.getUpdatesList())
            .map(KeyTransparencyServiceClient::fromAuditorUpdateProtobuf));

    assertThrows(RuntimeException.class, () -> auditor.auditKeyTransparencyService());
  }

  private static Stream<Arguments> testFailures() {
    return testVectors.getShouldFailList().stream()
        .map(testVector -> Arguments.of(Named.named(
            testVector.getDescription(),
            AuditResponse.newBuilder()
                .addAllUpdates(testVector.getUpdatesList())
                .build())));
  }

  @Test
  void testSuccess() throws IOException {
    when(auditorStateRepository.getAuditorStateAndSignature()).thenReturn(Optional.empty());
    doNothing().when(auditorStateRepository).storeAuditorStateAndSignature(any());
    TestVectors.ShouldSucceedTestVector succeedTestVector = testVectors.getShouldSucceed();

    for (TestVectors.ShouldSucceedTestVector.UpdateAndHash updateAndHash : succeedTestVector.getUpdatesList()) {
      when(keyTransparencyServiceClient.getUpdates(anyLong(), anyInt()))
          .thenReturn(Flux.just(KeyTransparencyServiceClient.fromAuditorUpdateProtobuf(updateAndHash.getUpdate())));

      assertDoesNotThrow(() -> auditor.auditKeyTransparencyService());
      assertArrayEquals(updateAndHash.getLogRoot().toByteArray(), auditor.getLogTreeRootHash());
    }
  }

  @ParameterizedTest
  @MethodSource
  void testSendTreeHeadAndPersistStateAfterNumUpdates(final int numUpdates, final int expectedNumCalls)
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAuditorSignatureException {
    when(auditorStateRepository.getAuditorStateAndSignature()).thenReturn(Optional.empty());
    doNothing().when(auditorStateRepository).storeAuditorStateAndSignature(any());

    auditor = new Auditor(auditorConfiguration, auditorStateRepository, keyTransparencyServiceClient, 3,
        Duration.ofMinutes(5), new SimpleMeterRegistry(), clock);
    auditor.loadStoredState();

    TestVectors.ShouldSucceedTestVector succeedTestVector = testVectors.getShouldSucceed();

    final List<AuditorUpdate> updates = succeedTestVector.getUpdatesList()
        .subList(0, numUpdates)
        .stream()
        .map(TestVectors.ShouldSucceedTestVector.UpdateAndHash::getUpdate)
        .map(KeyTransparencyServiceClient::fromAuditorUpdateProtobuf)
        .toList();

    when(keyTransparencyServiceClient.getUpdates(anyLong(), anyInt()))
        .thenReturn(Flux.fromIterable(updates));
    assertDoesNotThrow(() -> auditor.auditKeyTransparencyService());

    verify(keyTransparencyServiceClient, times(expectedNumCalls)).setTreeHead(anyLong(), anyLong(), any());
    verify(auditorStateRepository, times(expectedNumCalls)).storeAuditorStateAndSignature(any());
  }

  private static Stream<Arguments> testSendTreeHeadAndPersistStateAfterNumUpdates() {
    return Stream.of(
        Arguments.of(1, 0),
        Arguments.of(3, 1),
        Arguments.of(10, 3)
    );
  }

  @ParameterizedTest
  @MethodSource
  void testSendTreeHeadAndPersistStateAfterInterval(final Duration timePassed, final int expectedNumCalls)
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAuditorSignatureException {
    when(auditorStateRepository.getAuditorStateAndSignature()).thenReturn(Optional.empty());
    doNothing().when(auditorStateRepository).storeAuditorStateAndSignature(any());

    auditor = new Auditor(auditorConfiguration, auditorStateRepository, keyTransparencyServiceClient, 50,
        Duration.ofMinutes(5), new SimpleMeterRegistry(), clock);
    auditor.loadStoredState();

    clock.pin(Instant.EPOCH.plus(timePassed));

    TestVectors.ShouldSucceedTestVector succeedTestVector = testVectors.getShouldSucceed();

    // There are 10 updates in the success test vector
    final List<AuditorUpdate> updates = succeedTestVector.getUpdatesList()
        .stream()
        .map(TestVectors.ShouldSucceedTestVector.UpdateAndHash::getUpdate)
        .map(KeyTransparencyServiceClient::fromAuditorUpdateProtobuf)
        .toList();

    when(keyTransparencyServiceClient.getUpdates(anyLong(), anyInt()))
        .thenReturn(Flux.fromIterable(updates));
    assertDoesNotThrow(() -> auditor.auditKeyTransparencyService());

    verify(keyTransparencyServiceClient, times(expectedNumCalls)).setTreeHead(anyLong(), anyLong(), any());
    verify(auditorStateRepository, times(expectedNumCalls)).storeAuditorStateAndSignature(any());
  }

  private static Stream<Arguments> testSendTreeHeadAndPersistStateAfterInterval() {
    return Stream.of(
        Arguments.of(Duration.ofSeconds(30), 0),
        Arguments.of(Duration.ofMinutes(5), 1),
        Arguments.of(Duration.ofMinutes(10), 1)
    );
  }

  @Test
  void testSendTreeHeadAndPersistStateAfterIntervalWithNoUpdates()
      throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAuditorSignatureException {
    when(auditorStateRepository.getAuditorStateAndSignature()).thenReturn(Optional.empty());
    doNothing().when(auditorStateRepository).storeAuditorStateAndSignature(any());

    auditor = new Auditor(auditorConfiguration, auditorStateRepository, keyTransparencyServiceClient, 50,
        Duration.ofMinutes(5), new SimpleMeterRegistry(), clock);
    auditor.loadStoredState();

    TestVectors.ShouldSucceedTestVector succeedTestVector = testVectors.getShouldSucceed();

    final AuditorUpdate update = KeyTransparencyServiceClient.fromAuditorUpdateProtobuf(
        succeedTestVector.getUpdatesList()
            .getFirst()
            .getUpdate()
    );

    when(keyTransparencyServiceClient.getUpdates(anyLong(), anyInt()))
        .thenReturn(Flux.just(update));
    assertDoesNotThrow(() -> auditor.auditKeyTransparencyService());

    verify(keyTransparencyServiceClient, times(0)).setTreeHead(anyLong(), anyLong(), any());
    verify(auditorStateRepository, times(0)).storeAuditorStateAndSignature(any());

    clock.pin(Instant.EPOCH.plus(Duration.ofMinutes(5).plusMillis(1)));

    when(keyTransparencyServiceClient.getUpdates(anyLong(), anyInt()))
        .thenReturn(Flux.empty());
    assertDoesNotThrow(() -> auditor.auditKeyTransparencyService());

    // Send tree head and persist state after a certain time interval even when there have been no updates
    verify(keyTransparencyServiceClient, times(1)).setTreeHead(anyLong(), anyLong(), any());
    verify(auditorStateRepository, times(1)).storeAuditorStateAndSignature(any());
  }

  @Test
  void testSignature() throws InvalidKeySpecException, NoSuchAlgorithmException {
    final TestVectors.SignatureTestVector signatureTestVector = testVectors.getSignature();

    final KeyFactory kf = KeyFactory.getInstance("Ed25519");
    final EdECPrivateKey auditorPrivateKey = (EdECPrivateKey) kf.generatePrivate(
        new PKCS8EncodedKeySpec(signatureTestVector.getAuditorPrivateKey().toByteArray()));
    final EdECPublicKey auditorPublicKey = (EdECPublicKey) kf.generatePublic(
        new X509EncodedKeySpec(signatureTestVector.getAuditorPublicKey().toByteArray()));
    final EdECPublicKey signingPublicKey = (EdECPublicKey) kf.generatePublic(
        new X509EncodedKeySpec(signatureTestVector.getSignaturePublicKey().toByteArray()));
    final EdECPublicKey vrfPublicKey = (EdECPublicKey) kf.generatePublic(
        new X509EncodedKeySpec(signatureTestVector.getVrfPublicKey().toByteArray()));

    assertArrayEquals(signatureTestVector.getSignature().toByteArray(),
        Auditor.generateTreeHeadSignature(signingPublicKey,
            vrfPublicKey,
            auditorPublicKey,
            signatureTestVector.getTreeSize(),
            signatureTestVector.getTimestamp(),
            signatureTestVector.getRoot().toByteArray(),
            auditorPrivateKey
        ));
  }

  @Test
  void testInvalidAuditorSignature() {
    final byte[] serializedAuditorState = AuditorState.newBuilder()
        .setTotalUpdatesProcessed(1)
        .setCurrentPrefixTreeRootHash(ByteString.copyFrom(new byte[32]))
        .addAllLogTreeNodes(List.of(LogTreeNode.newBuilder()
            .setId(0)
            .setHash(ByteString.copyFrom(new byte[32]))
            .build()
        ))
        .build()
        .toByteArray();

    final byte[] modifiedSerializedAuditorState = new byte[serializedAuditorState.length];
    System.arraycopy(serializedAuditorState, 0, modifiedSerializedAuditorState, 0, serializedAuditorState.length);
    modifiedSerializedAuditorState[0] ^= (byte) 0xFF;

    // Create an invalid signature by signing modified data
    final byte[] invalidSignature = Auditor.generateSignature(modifiedSerializedAuditorState,
        auditor.getConfiguration().privateKey());

    assertThrows(InvalidAuditorSignatureException.class, () -> Auditor.verifySignature(serializedAuditorState,
        invalidSignature, auditor.getConfiguration().publicKey()));
  }
}
