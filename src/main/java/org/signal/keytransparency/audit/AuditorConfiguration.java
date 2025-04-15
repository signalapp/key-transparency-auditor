/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import io.micronaut.context.annotation.ConfigurationProperties;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

/**
 * Configuration parameters for an {@link Auditor}.
 *
 * @param privateKey                             An Ed25519 private key used by the auditor to sign the tree head sent
 *                                               back to the key transparency service
 * @param publicKey                              The public counterpart to {@param privateKey}.
 * @param keyTransparencyServiceSigningPublicKey An Ed25519 public key used to verify the key transparency service's
 *                                               signature over the tree head.
 * @param keyTransparencyServiceVrfPublicKey     An Ed25519 public key used to verify the input-output pair of a
 *                                               <a href="https://www.rfc-editor.org/rfc/rfc9381.html">Verifiable Random
 *                                               Function</a>.
 * @param batchSize                              The maximum number of updates that the key transparency service should
 *                                               return in a single response.
 */
@ConfigurationProperties("auditor")
record AuditorConfiguration(
    @NotNull
    EdECPrivateKey privateKey,
    @NotNull
    EdECPublicKey publicKey,
    @NotNull
    EdECPublicKey keyTransparencyServiceSigningPublicKey,
    @NotNull
    EdECPublicKey keyTransparencyServiceVrfPublicKey,
    @Positive
    int batchSize) {
}
