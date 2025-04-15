/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage.dynamodb;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Context;
import jakarta.validation.constraints.NotBlank;

@Context
@ConfigurationProperties("storage.dynamodb")
record DynamoDbConfiguration(@NotBlank String tableName, @NotBlank String region) {
}
