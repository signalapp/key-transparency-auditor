/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.metrics;

public class MetricsUtil {

  private static final String METRIC_NAME_PREFIX = "key_transparency_auditor";

  /**
   * Returns a qualified name for a metric contained within the given class.
   *
   * @param clazz      the class that contains the metric
   * @param metricName the name of the metrics
   * @return a qualified name for the given metric
   */
  public static String name(final Class<?> clazz, final String metricName) {
    return METRIC_NAME_PREFIX + "." + clazz.getSimpleName() + "." + metricName;
  }
}

