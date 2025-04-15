/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage.dynamodb;

import com.google.protobuf.ByteString;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.signal.keytransparency.audit.storage.AuditorState;
import org.signal.keytransparency.audit.storage.AuditorStateAndSignature;
import org.signal.keytransparency.audit.storage.LogTreeNode;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.signal.keytransparency.audit.util.Util.generateRandomBytes;

@MicronautTest
@Property(name = "storage.dynamodb.table-name", value = "AuditorStateRepositoryTest")
@Property(name = "storage.dynamodb.region", value = "us-east-1")
public class DynamoDbAuditorStateRepositoryTest {

  private static final String AUDITOR_STATE_TABLE_NAME = "AuditorStateRepositoryTest";
  @RegisterExtension
  private static final DynamoDbExtension dynamoDbExtension = DynamoDbExtension.builder()
      .tableName(AUDITOR_STATE_TABLE_NAME)
      .hashKey(DynamoDbAuditorStateRepository.KEY)
      .attributeDefinition(AttributeDefinition.builder()
          .attributeName(DynamoDbAuditorStateRepository.KEY)
          .attributeType(ScalarAttributeType.S)
          .build())
      .build();

  @Replaces(DynamoDbClient.class)
  @Singleton
  DynamoDbClient dynamoDbClient() throws Exception {
    return dynamoDbExtension.createClient();
  }

  @Inject
  DynamoDbAuditorStateRepository dynamoDbAuditorStateRepository;

  @Test
  void testStoreAndRetrieveAuditorState() throws IOException {
    final Optional<byte[]> auditorStateAndSignatureBytes = dynamoDbAuditorStateRepository.getAuditorStateAndSignature();
    assertTrue(auditorStateAndSignatureBytes.isEmpty());

    final byte[] signature = generateRandomBytes(64);
    final byte[] prefixTreeRootHash = generateRandomBytes(32);
    final ByteString serializedAuditorState = AuditorState.newBuilder()
        .setTotalUpdatesProcessed(1)
        .setCurrentPrefixTreeRootHash(ByteString.copyFrom(prefixTreeRootHash))
        .addAllLogTreeNodes(List.of(LogTreeNode.newBuilder()
            .setHash(ByteString.copyFrom(generateRandomBytes(32)))
            .setId(0)
            .build()))
        .build()
        .toByteString();

    final AuditorStateAndSignature auditorStateAndSignature = AuditorStateAndSignature.newBuilder()
        .setSignature(ByteString.copyFrom(signature))
        .setSerializedAuditorState(serializedAuditorState)
        .build();

    dynamoDbAuditorStateRepository.storeAuditorStateAndSignature(auditorStateAndSignature.toByteArray());

    final AuditorStateAndSignature retrievedAuditorStateAndSignature = AuditorStateAndSignature.parseFrom(
        dynamoDbAuditorStateRepository.getAuditorStateAndSignature().get());
    assertEquals(serializedAuditorState, retrievedAuditorStateAndSignature.getSerializedAuditorState());
    assertArrayEquals(signature, retrievedAuditorStateAndSignature.getSignature().toByteArray());
  }
}

