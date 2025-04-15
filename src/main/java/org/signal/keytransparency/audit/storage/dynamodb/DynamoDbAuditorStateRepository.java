/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage.dynamodb;

import com.google.common.annotations.VisibleForTesting;
import jakarta.inject.Singleton;
import org.signal.keytransparency.audit.storage.AuditorStateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * An auditor state repository that uses DynamoDB as its backing store.
 */
@Singleton
public class DynamoDbAuditorStateRepository implements AuditorStateRepository {

  private static final Logger logger = LoggerFactory.getLogger(DynamoDbAuditorStateRepository.class);
  // we're only storing one item, so set the key to a constant value
  @VisibleForTesting
  static final AttributeValue KEY_ATTRIBUTE_VALUE = AttributeValue.builder().s("AuditorState").build();
  @VisibleForTesting
  static final String KEY = "K";
  // auditor state and signature data; bytes
  @VisibleForTesting
  static final String ATTR_AUDITOR_STATE_AND_SIGNATURE = "A";
  @VisibleForTesting
  final DynamoDbClient dynamoDbClient;
  private final DynamoDbConfiguration dynamoDbConfiguration;

  public DynamoDbAuditorStateRepository(final DynamoDbClient dynamoDbClient,
      final DynamoDbConfiguration dynamoDbConfiguration) {
    this.dynamoDbClient = dynamoDbClient;
    this.dynamoDbConfiguration = dynamoDbConfiguration;
  }

  @Override
  public Optional<byte[]> getAuditorStateAndSignature() throws IOException {
    try {
      final GetItemResponse response = dynamoDbClient.getItem(GetItemRequest.builder()
          .tableName(dynamoDbConfiguration.tableName())
          .key(Map.of(KEY, KEY_ATTRIBUTE_VALUE))
          .build());
      if (!response.hasItem()) {
        logger.info("Auditor state and signature data not found");
        return Optional.empty();
      } else {
        return Optional.of(response.item().get(ATTR_AUDITOR_STATE_AND_SIGNATURE).b().asByteArray());
      }
    } catch (final Exception e) {
      logger.error("Unexpected error getting auditor state data", e);
      throw new IOException(e);
    }
  }

  @Override
  public void storeAuditorStateAndSignature(final byte[] serializedAuditorStateAndSignature) throws IOException {
    final PutItemRequest.Builder builder = PutItemRequest.builder()
        .tableName(dynamoDbConfiguration.tableName())
        .item(Map.of(
            KEY, KEY_ATTRIBUTE_VALUE,
            ATTR_AUDITOR_STATE_AND_SIGNATURE,
            AttributeValue.builder().b(SdkBytes.fromByteArray(serializedAuditorStateAndSignature)).build()
        ));
    try {
      dynamoDbClient.putItem(builder.build());
    } catch (final AwsServiceException e) {
      logger.error("Unexpected error writing auditor state data", e);
      throw new IOException(e);
    }
  }
}

