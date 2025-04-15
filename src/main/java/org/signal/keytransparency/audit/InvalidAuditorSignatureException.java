/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

/**
 * Indicates that a calculated signature did not match the one presented
 *
 * @see java.security.Signature#verify(byte[])
 */
public class InvalidAuditorSignatureException extends Exception {

  public InvalidAuditorSignatureException(String message) {
    super(message);
  }
}
