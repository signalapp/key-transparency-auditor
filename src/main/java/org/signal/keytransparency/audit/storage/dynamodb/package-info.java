/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

@Configuration
@Requires(property = "storage.dynamodb.table-name")
@Requires(property = "storage.dynamodb.region")
package org.signal.keytransparency.audit.storage.dynamodb;

import io.micronaut.context.annotation.Configuration;
import io.micronaut.context.annotation.Requires;
