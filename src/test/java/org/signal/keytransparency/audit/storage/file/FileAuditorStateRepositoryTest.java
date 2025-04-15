/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage.file;

import com.google.protobuf.ByteString;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.signal.keytransparency.audit.storage.AuditorState;
import org.signal.keytransparency.audit.storage.AuditorStateAndSignature;
import org.signal.keytransparency.audit.storage.LogTreeNode;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.signal.keytransparency.audit.util.Util.generateRandomBytes;

public class FileAuditorStateRepositoryTest {

  private File testFile;
  private FileAuditorStateRepository fileAuditorStateRepository;

  @BeforeEach
  void setUp() throws IOException {
    testFile = File.createTempFile("test", null);
    testFile.deleteOnExit();
    fileAuditorStateRepository = new FileAuditorStateRepository(testFile.getCanonicalPath());
  }

  @AfterEach
  void tearDown() {
    testFile.delete();
  }

  @Test
  void testStoreAndGetAuditorStateAndSignature() throws IOException {
    final ByteString serializedAuditorState = AuditorState.newBuilder()
        .setTotalUpdatesProcessed(1)
        .setCurrentPrefixTreeRootHash(ByteString.copyFrom(generateRandomBytes(32)))
        .addAllLogTreeNodes(List.of(
            LogTreeNode.newBuilder()
                .setHash(ByteString.copyFrom(generateRandomBytes(32)))
                .setId(0)
                .build()
        ))
        .build()
        .toByteString();

    final byte[] signature = generateRandomBytes(64);
    fileAuditorStateRepository.storeAuditorStateAndSignature(AuditorStateAndSignature.newBuilder()
        .setSerializedAuditorState(serializedAuditorState)
        .setSignature(ByteString.copyFrom(signature))
        .build()
        .toByteArray());

    final AuditorStateAndSignature auditorStateAndSignature = AuditorStateAndSignature.parseFrom(
        fileAuditorStateRepository.getAuditorStateAndSignature().get());

    assertEquals(serializedAuditorState, auditorStateAndSignature.getSerializedAuditorState());
    assertArrayEquals(signature, auditorStateAndSignature.getSignature().toByteArray());
  }

  @Test
  void testFileNotFound() throws IOException {
    testFile.delete();
    Optional<byte[]> auditorStateAndSignatureBytes = fileAuditorStateRepository.getAuditorStateAndSignature();
    assertTrue(auditorStateAndSignatureBytes.isEmpty());
  }
}
