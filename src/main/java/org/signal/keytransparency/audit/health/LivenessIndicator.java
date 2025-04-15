/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.health;

import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.health.HealthStatus;
import io.micronaut.management.health.indicator.HealthIndicator;
import io.micronaut.management.health.indicator.HealthResult;
import io.micronaut.management.health.indicator.annotation.Liveness;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.signal.keytransparency.audit.Auditor;

@Singleton
@Liveness
public class LivenessIndicator implements HealthIndicator {

  private final Auditor auditor;

  public LivenessIndicator(final Auditor auditor) {
    this.auditor = auditor;
  }

  @Override
  public Publisher<HealthResult> getResult() {
    return Publishers.just(HealthResult.builder("AuditorHealthy",
        auditor.isHealthy() ? HealthStatus.UP : HealthStatus.DOWN).build());
  }
}
