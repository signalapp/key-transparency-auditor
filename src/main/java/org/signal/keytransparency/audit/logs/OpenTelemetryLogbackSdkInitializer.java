/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.logs;

import io.micronaut.context.annotation.Context;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.instrumentation.logback.appender.v1_0.OpenTelemetryAppender;
import jakarta.annotation.PostConstruct;

@Context
class OpenTelemetryLogbackSdkInitializer {

  private final OpenTelemetry openTelemetry;

  OpenTelemetryLogbackSdkInitializer(final OpenTelemetry openTelemetry) {
    this.openTelemetry = openTelemetry;
  }

  @PostConstruct
  void install() {
    OpenTelemetryAppender.install(openTelemetry);
  }
}
