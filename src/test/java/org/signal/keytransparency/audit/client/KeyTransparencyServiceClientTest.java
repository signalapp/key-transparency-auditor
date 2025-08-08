/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.client;

import com.google.protobuf.ByteString;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.signal.keytransparency.audit.util.Util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class KeyTransparencyAuditorServiceClientTest {

  private KeyTransparencyAuditorServiceGrpc.KeyTransparencyAuditorServiceBlockingStub stub;
  private KeyTransparencyAuditorServiceClient client;

  private static final int EXISTING_UPDATE_COUNT = 13;
  private static final int BATCH_SIZE = 77;

  @BeforeEach
  void setUp() {
    stub = mock(KeyTransparencyAuditorServiceGrpc.KeyTransparencyAuditorServiceBlockingStub.class);
    client = new KeyTransparencyAuditorServiceClient(stub, new SimpleMeterRegistry());
  }

  @Test
  void getUpdates() {
    final AuditResponse firstPage = AuditResponse.newBuilder()
        .addAllUpdates(generateRandomUpdates(3))
        .setMore(true)
        .build();

    final AuditResponse secondPage = AuditResponse.newBuilder()
        .addAllUpdates(generateRandomUpdates(5))
        .setMore(true)
        .build();

    final AuditResponse thirdPage = AuditResponse.newBuilder()
        .addAllUpdates(generateRandomUpdates(7))
        .setMore(false)
        .build();

    when(stub.audit(any()))
        .thenReturn(firstPage)
        .thenReturn(secondPage)
        .thenReturn(thirdPage);

    final List<org.signal.keytransparency.audit.AuditorUpdate> expectedUpdates =
        Stream.concat(Stream.concat(firstPage.getUpdatesList().stream(), secondPage.getUpdatesList().stream()),
                thirdPage.getUpdatesList().stream())
            .map(KeyTransparencyAuditorServiceClient::fromAuditorUpdateProtobuf)
            .toList();

    final List<org.signal.keytransparency.audit.AuditorUpdate> retrievedUpdates =
        client.getUpdates(EXISTING_UPDATE_COUNT, BATCH_SIZE).collectList().block();

    assertNotNull(retrievedUpdates);
    assertEquals(expectedUpdates.size(), retrievedUpdates.size());

    for (int i = 0; i < expectedUpdates.size(); i++) {
      assertTrue(updatesEqual(expectedUpdates.get(i), retrievedUpdates.get(i)));
    }

    verify(stub).audit(AuditRequest.newBuilder()
        .setStart(EXISTING_UPDATE_COUNT)
        .setLimit(BATCH_SIZE)
        .build());

    verify(stub).audit(AuditRequest.newBuilder()
        .setStart(EXISTING_UPDATE_COUNT + firstPage.getUpdatesCount())
        .setLimit(BATCH_SIZE)
        .build());

    verify(stub).audit(AuditRequest.newBuilder()
        .setStart(EXISTING_UPDATE_COUNT + firstPage.getUpdatesCount() + secondPage.getUpdatesCount())
        .setLimit(BATCH_SIZE)
        .build());
  }

  private static boolean updatesEqual(final org.signal.keytransparency.audit.AuditorUpdate a,
      final org.signal.keytransparency.audit.AuditorUpdate b) {

    // We're always using "new tree" proofs that don't have any internal data,
    // which does not reflect the actual log entries of the key transparency service.
    // This is fine because we're only testing fetching pages of updates here;
    // proof comparison is tested separately.
    return a.isRealUpdate() == b.isRealUpdate() &&
        Arrays.equals(a.commitmentIndex(), b.commitmentIndex()) &&
        Arrays.equals(a.standInHashSeed(), b.standInHashSeed()) &&
        Arrays.equals(a.commitment(), b.commitment()) &&
        a.proof().equals(b.proof());
  }

  private List<AuditorUpdate> generateRandomUpdates(final int updateCount) {
    final List<AuditorUpdate> updates = new ArrayList<>(updateCount);

    for (int i = 0; i < updateCount; i++) {
      updates.add(AuditorUpdate.newBuilder()
          .setReal(ThreadLocalRandom.current().nextBoolean())
          .setIndex(ByteString.copyFrom(Util.generateRandomBytes(32)))
          .setSeed(ByteString.copyFrom(Util.generateRandomBytes(32)))
          .setCommitment(ByteString.copyFrom(Util.generateRandomBytes(32)))
          .setProof(AuditorProof.newBuilder()
              .setNewTree(AuditorProof.NewTree.newBuilder().build())
              .build())
          .build());
    }

    return updates;
  }
}
