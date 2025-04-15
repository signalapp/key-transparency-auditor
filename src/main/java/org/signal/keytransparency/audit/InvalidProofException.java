/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

/**
 * Indicates that the key transparency service provided an invalid proof of its starting prefix tree.
 */
public class InvalidProofException extends Exception {

  InvalidProofException(final String message) {
    super(message);
  }
}
