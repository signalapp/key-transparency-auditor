/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import java.util.HexFormat;
import java.util.List;

/**
 * Returned if there has been at least one real update so far, and the given update affects an existing leaf in the
 * prefix tree. This means that to verify the previous prefix tree root hash, the auditor must start all the way from
 * the prefix tree leaf hash and hash its way up to the root hash. Can only be applied to real updates.
 *
 * @param counter              the number of times that the value associated with the search key has been updated.
 * @param firstLogTreePosition the position of the first instance of the search key in the log tree.
 * @param copath               the sibling hashes of nodes in the direct path to the given leaf. This list only contains
 *                             hashes that are in the direct path of another leaf (the "explored part" of the prefix
 *                             tree). Use {@link AuditorUpdate#standInHashSeed} to calculate stand-in hashes in the
 *                             "unexplored" part of the prefix tree.
 */
public record SameKeyProof(int counter,
                           long firstLogTreePosition,
                           List<byte[]> copath
) implements AuditorProof {
  @Override
  public String toString() {
    return "SameKeyProof{" +
        "counter=" + counter +
        ", firstLogTreePosition=" + firstLogTreePosition +
        ", copath=" + copath.stream().map(bytes -> HexFormat.of().formatHex(bytes)).toList() +
        "}";
  }
}

