/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import jakarta.validation.constraints.Size;
import java.util.HexFormat;

/**
 * Provides the data necessary for the auditor to verify and accept the given update.
 *
 * @param isRealUpdate    whether the given update is real or fake.
 * @param commitmentIndex the <a href="https://www.rfc-editor.org/rfc/rfc9381.html">Verifiable Random Function</a>
 *                        output of the search key that was updated. This value is used to search the prefix tree and to
 *                        calculate the prefix tree leaf hash. This is a randomly generated value if the update is
 *                        fake.
 * @param standInHashSeed a pseudo-random value that is hashed with a prefix tree's level index to generate a stand-in
 *                        value for that level.
 * @param commitment      a cryptographic hash of the update used to calculate the log tree leaf hash. This is a
 *                        randomly generated value if the update is fake.
 * @param proof           additional information to help the auditor efficiently verify that the update uses the
 *                        auditor's current prefix tree root hash as a starting point.
 */
public record AuditorUpdate(boolean isRealUpdate,
                            @Size(min = 32, max = 32)
                            byte[] commitmentIndex,
                            @Size(min = 16, max = 16)
                            byte[] standInHashSeed,
                            @Size(min = 32, max = 32)
                            byte[] commitment,
                            AuditorProof proof) {

  @Override
  public String toString() {
    return "AuditorUpdate{" +
        "isRealUpdate=" + isRealUpdate +
        ", commitmentIndex=" + HexFormat.of().formatHex(commitmentIndex) +
        ", standInHashSeed=" + HexFormat.of().formatHex(standInHashSeed) +
        ", commitment=" + HexFormat.of().formatHex(commitment) +
        ", proof=" + proof +
        "}";
  }
}
