/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

/**
 * Provided by the key transparency service to represent its starting prefix tree state before applying the given
 * update. The auditor verifies this proof against its own stored prefix tree root hash before accepting the update.
 */
public interface AuditorProof {
}
