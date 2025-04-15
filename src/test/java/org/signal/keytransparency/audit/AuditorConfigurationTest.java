/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import io.micronaut.context.annotation.Property;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "auditor.public-key", value = AuditorConfigurationTest.BASE_64_AUDITOR_PUBLIC_KEY)
@Property(name = "auditor.private-key", value = AuditorConfigurationTest.BASE_64_AUDITOR_PRIVATE_KEY)
@Property(name = "auditor.key-transparency-service-signing-public-key", value = AuditorConfigurationTest.BASE_64_SIGNING_PUBLIC_KEY)
@Property(name = "auditor.key-transparency-service-vrf-public-key", value = AuditorConfigurationTest.BASE_64_VRF_PUBLIC_KEY)
@Property(name = "auditor.batch-size", value = "1")
@MicronautTest
public class AuditorConfigurationTest {

  public static final String BASE_64_AUDITOR_PUBLIC_KEY = "MCowBQYDK2VwAyEAK7NtsIg6wI2G/TYXD0qvsQsnX+GGPoDZdeWRAtIuTOw=";
  public static final String BASE_64_AUDITOR_PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEILoryblmKqRCHWG9V9l2cw4KuFsbO071mTrmFKq1avxc";
  public static final String BASE_64_SIGNING_PUBLIC_KEY = "MCowBQYDK2VwAyEAJTNezQ4UXzOvW5f0ghoxk537fHeZvLBDU4pbaC1Emr8=";
  public static final String BASE_64_VRF_PUBLIC_KEY = "MCowBQYDK2VwAyEAket+Qf23umGTOM3zJpTaZrAZXAYqGjEpoweHpCNBr5M=";

  @Inject
  AuditorConfiguration auditorConfiguration;

  @Test
  void testAuditorConfiguration() {
    assertEquals(BASE_64_AUDITOR_PUBLIC_KEY,
        Base64.getEncoder().encodeToString(auditorConfiguration.publicKey().getEncoded()));
    assertEquals(BASE_64_AUDITOR_PRIVATE_KEY,
        Base64.getEncoder().encodeToString(auditorConfiguration.privateKey().getEncoded()));
    assertEquals(BASE_64_SIGNING_PUBLIC_KEY,
        Base64.getEncoder().encodeToString(auditorConfiguration.keyTransparencyServiceSigningPublicKey().getEncoded()));
    assertEquals(BASE_64_VRF_PUBLIC_KEY,
        Base64.getEncoder().encodeToString(auditorConfiguration.keyTransparencyServiceVrfPublicKey().getEncoded()));
    assertEquals(1, auditorConfiguration.batchSize());
  }
}
