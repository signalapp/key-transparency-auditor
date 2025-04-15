/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256MessageDigest {

  /**
   * Infallibly returns a new {@code MessageDigest} instance that uses the SHA-256 algorithm. While getting a new
   * {@code MessageDigest} can fail in general, every implementation of the Java platform is required to support
   * SHA-256.
   *
   * @return a new {@code MessageDigest} instance that uses the SHA-256 algorithm
   */
  public static MessageDigest getMessageDigest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError("Every implementation of the Java platform is required to support SHA-256", e);
    }
  }
}
