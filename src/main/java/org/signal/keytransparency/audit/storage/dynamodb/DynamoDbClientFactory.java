/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage.dynamodb;

import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import jakarta.inject.Singleton;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

@Factory
class DynamoDbClientFactory {

  @Bean(preDestroy = "close")
  @Singleton
  DynamoDbClient dynamoDbClient(final DynamoDbConfiguration config) {
    return DynamoDbClient.builder()
        .region(Region.of(config.region()))
        .build();
  }
}
