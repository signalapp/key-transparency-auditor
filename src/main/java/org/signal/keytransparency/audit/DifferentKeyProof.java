/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import java.util.HexFormat;
import java.util.List;

/**
 * Returned when there has been at least one real update so far, and the given update does not affect an existing leaf
 * in the prefix tree. This means that the search for AuditorUpdate.index in the prefix tree ended in a stand-in hash
 * value. Can be applied to real or fake updates.
 *
 * @param oldStandInHashSeed used to calculate the stand-in hash value where the search ended.
 * @param copath             the list of sibling hashes up to and including the sibling of the stand-in hash value. This
 *                           list is returned in top to bottom order.
 */
public record DifferentKeyProof(byte[] oldStandInHashSeed,
                                List<byte[]> copath) implements AuditorProof {
  @Override
  public String toString() {
    return "DifferentKeyProof{" +
        "oldStandInHashSeed=" + HexFormat.of().formatHex(oldStandInHashSeed) +
        ", copath=" + copath.stream().map(bytes -> HexFormat.of().formatHex(bytes)).toList() +
        "}";
  }
}
