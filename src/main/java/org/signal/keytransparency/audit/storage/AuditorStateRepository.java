/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit.storage;

import java.io.IOException;
import java.util.Optional;


/**
 * Stores auditor state data and a signature over it. The auditor may use this data to resume from its most recent
 * position in the key transparency log if it is restarted.
 */
public interface AuditorStateRepository {

  /**
   * @return the most recently stored serialized auditor state and signature
   */
  Optional<byte[]> getAuditorStateAndSignature() throws IOException;

  /**
   * Store the serialized auditor state and a signature over it.
   *
   * @param serializedAuditorStateAndSignature the serialized auditor state and signature to persist
   */
  void storeAuditorStateAndSignature(byte[] serializedAuditorStateAndSignature) throws IOException;
}
