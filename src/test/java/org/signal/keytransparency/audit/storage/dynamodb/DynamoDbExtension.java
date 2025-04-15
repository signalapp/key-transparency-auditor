/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage.dynamodb;

import com.amazonaws.services.dynamodbv2.local.embedded.DynamoDBEmbedded;
import com.amazonaws.services.dynamodbv2.local.shared.access.AmazonDynamoDBLocal;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ProvisionedThroughput;

public class DynamoDbExtension implements BeforeAllCallback, BeforeEachCallback, AfterEachCallback, AfterAllCallback {

  private static DynamoDbClient client;
  private final List<AttributeDefinition> attributeDefinitions;
  private final String tableName;
  private final String hashKeyName;

  private final long readCapacityUnits;
  private final long writeCapacityUnits;

  private AmazonDynamoDBLocal embedded;

  private DynamoDbExtension(final String tableName,
      final String hashKey,
      final List<AttributeDefinition> attributeDefinitions,
      final long readCapacityUnits,
      final long writeCapacityUnits) {
    this.tableName = tableName;
    this.hashKeyName = hashKey;
    this.attributeDefinitions = attributeDefinitions;
    this.readCapacityUnits = readCapacityUnits;
    this.writeCapacityUnits = writeCapacityUnits;
  }

  public static DynamoDbExtensionBuilder builder() {
    return new DynamoDbExtensionBuilder();
  }

  @Override
  public void beforeAll(final ExtensionContext context) {
    embedded = DynamoDBEmbedded.create(true);
  }

  @Override
  public void beforeEach(final ExtensionContext context) {
    createTable();
  }

  @Override
  public void afterEach(final ExtensionContext context) {
    deleteTable();
  }

  @Override
  public void afterAll(final ExtensionContext context) {

    try {
      embedded.shutdown();
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  public DynamoDbClient createClient() {
    if (client == null) {
      client = embedded.dynamoDbClient();
    }
    return client;
  }

  private void createTable() {
    final CreateTableRequest createTableRequest = CreateTableRequest.builder()
        .tableName(tableName)
        .keySchema(KeySchemaElement.builder().attributeName(hashKeyName).keyType(KeyType.HASH).build())
        .attributeDefinitions(attributeDefinitions)
        .provisionedThroughput(ProvisionedThroughput.builder()
            .readCapacityUnits(readCapacityUnits)
            .writeCapacityUnits(writeCapacityUnits)
            .build())
        .build();

    client.createTable(createTableRequest);
  }

  private void deleteTable() {
    client.deleteTable(DeleteTableRequest.builder()
        .tableName(tableName).build());
  }

  public static class DynamoDbExtensionBuilder {

    private String tableName;
    private String hashKey;
    private final List<AttributeDefinition> attributeDefinitions = new ArrayList<>();

    public DynamoDbExtensionBuilder tableName(String databaseName) {
      this.tableName = databaseName;
      return this;
    }

    public DynamoDbExtensionBuilder hashKey(String hashKey) {
      this.hashKey = hashKey;
      return this;
    }

    public DynamoDbExtensionBuilder attributeDefinition(AttributeDefinition attributeDefinition) {
      attributeDefinitions.add(attributeDefinition);
      return this;
    }

    public DynamoDbExtension build() {
      final long readCapacityUnits = 5L;
      final long writeCapacityUnits = 5L;
      return new DynamoDbExtension(tableName, hashKey, attributeDefinitions, readCapacityUnits,
          writeCapacityUnits);
    }
  }
}
