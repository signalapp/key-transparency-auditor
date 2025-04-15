/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

/**
 * Returned for the very first update in the key transparency service. Can only be applied to a real update.
 */
public record NewTreeProof() implements AuditorProof {
  @Override
  public String toString() {
    return "NewTreeProof";
  }
}
