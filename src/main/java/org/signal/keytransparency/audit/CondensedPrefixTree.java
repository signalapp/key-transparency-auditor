/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import com.google.common.annotations.VisibleForTesting;
import jakarta.inject.Singleton;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;
import org.signal.keytransparency.audit.util.Sha256MessageDigest;

/**
 * A prefix tree is a 256-level binary Merkle tree where the leaves store data used by the key transparency service for
 * efficient lookup of entries within the log tree. The prefix tree is traversed with a commitment index, a 256-bit
 * value deterministically computed from the original search key via a <a
 * href="https://datatracker.ietf.org/doc/html/rfc9381">Verifiable Random Function</a>. Unlike the condensed log tree,
 * prefix trees treat the root — not leaves — as level 0, and the leaves as level 256.
 * <p>
 * The only data the auditor stores concerning prefix trees is the most recent prefix tree root hash. For each update,
 * the auditor first verifies that the update uses the same prefix tree root hash as a starting point before calculating
 * the new prefix tree root hash.
 */
@Singleton
class CondensedPrefixTree {

  private Optional<byte[]> rootHash;
  private final static byte LEAF_NODE_DOMAIN_INDICATOR = 0x00;
  private final static byte INTERMEDIATE_NODE_DOMAIN_INDICATOR = 0x01;
  private final static byte STAND_IN_NODE_DOMAIN_INDICATOR = 0x02;
  private final static int ROOT_LEVEL = 0;
  private final static int LEAF_LEVEL = 256;

  CondensedPrefixTree() {
    this(null);
  }

  CondensedPrefixTree(@Nullable final byte[] rootHash) {
    this.rootHash = Optional.ofNullable(rootHash);
  }

  /**
   * Applies the given update to the condensed prefix tree by first verifying that the auditor has the same starting
   * prefix tree root hash as the key transparency service, then calculating the new prefix tree root hash and updating
   * the auditor's view of it.
   *
   * @param update        the update to apply to the condensed prefix tree
   * @param numLogEntries the total number of updates processed so far by the auditor
   * @throws InvalidProofException if the provided {@link AuditorUpdate#proof()} is inconsistent with the auditor's view
   *                               of the prefix tree
   */
  void applyUpdate(final AuditorUpdate update, final long numLogEntries) throws InvalidProofException {
    verifyStartingRootHash(update, numLogEntries);

    rootHash = update.isRealUpdate()
        ? Optional.of(calculateNewRootHashForRealUpdate(update, numLogEntries))
        : Optional.of(calculateNewRootHashForFakeUpdate(update));
  }

  /**
   * Verify the starting prefix tree root hash between the auditor and the key transparency service.
   *
   * @param update        the update for which to verify its starting prefix tree root hash
   * @param numLogEntries the total number of updates processed so far by the auditor
   * @throws InvalidProofException if the provided {@link AuditorUpdate#proof()} is inconsistent with the auditor's view
   *                               of the prefix tree
   */
  @VisibleForTesting
  void verifyStartingRootHash(final AuditorUpdate update, final long numLogEntries) throws InvalidProofException {
    if (update.proof() instanceof NewTreeProof) {
      if (numLogEntries != 0 || rootHash.isPresent()) {
        throw new InvalidProofException("Auditor must have zero log entries and no root hash for a new tree proof");
      }

      return;
    }

    if (rootHash.isEmpty()) {
      if (numLogEntries == 0) {
        throw new InvalidProofException("First proof type must be newTree");
      }
      // This should never happen, unless #applyUpdate doesn't save the rootHash for NewTreeProof
      throw new InvalidProofException("No root hash present for proof");
    }

    final byte[] rootHashFromProof = switch (update.proof()) {
      case DifferentKeyProof differentKey -> {
        // Use the old seed to calculate a stand-in hash at the end of the copath
        final byte[] startingHash = calculateStandInHash(differentKey.oldStandInHashSeed(),
            differentKey.copath().size());

        // And then hash our way up to the root starting from the level of the last copath value.
        // The old seed is *only* used to calculate the startingHash in this proof.
        yield calculateRootHash(startingHash, differentKey.oldStandInHashSeed(), update.commitmentIndex(),
            differentKey.copath(), differentKey.copath().size());
      }
      case SameKeyProof sameKey -> {
        final byte[] startingHash = calculateLeafHash(update.commitmentIndex(), sameKey.counter(),
            sameKey.firstLogTreePosition());
        yield calculateRootHash(startingHash, update.standInHashSeed(), update.commitmentIndex(), sameKey.copath(),
            LEAF_LEVEL);
      }
      default -> throw new AssertionError("Unexpected proof type");
    };

    if (!Arrays.equals(rootHash.get(), rootHashFromProof)) {
      final String expectedRootHash = HexFormat.of().formatHex(rootHash.get());
      final String actualRootHash = HexFormat.of().formatHex(rootHashFromProof);
      throw new InvalidProofException(
          String.format("The auditor's starting prefix tree root hash for update %d does not match the one provided by the key transparency service."
              + "Expected %s, got %s. \nAuditor update: %s", numLogEntries, expectedRootHash, actualRootHash, update));
    }

  }

  /**
   * Returns the new prefix tree root hash for the given real update. This involves calculating a new leaf hash and
   * combining that with the provided copath and/or stand-in hashes (calculated from the provided seed) to hash our way
   * back up to the root hash.
   *
   * @param update        the update for which to calculate the new prefix tree root hash
   * @param numLogEntries the total number of updates processed so far by the auditor
   * @return the new prefix tree root hash for the given real update
   */
  @VisibleForTesting
  byte[] calculateNewRootHashForRealUpdate(final AuditorUpdate update, final long numLogEntries) {
    final byte[] leafHash = switch (update.proof()) {
      case NewTreeProof ignored -> calculateLeafHash(update.commitmentIndex(), 0, numLogEntries);
      case DifferentKeyProof ignored -> calculateLeafHash(update.commitmentIndex(), 0, numLogEntries);
      case SameKeyProof sameKey ->
          calculateLeafHash(update.commitmentIndex(), sameKey.counter() + 1, sameKey.firstLogTreePosition());
      default -> throw new AssertionError("Unexpected proof type");
    };

    final List<byte[]> copath = switch (update.proof()) {
      case NewTreeProof ignored -> Collections.emptyList();
      case DifferentKeyProof differentKey -> differentKey.copath();
      case SameKeyProof sameKey -> sameKey.copath();
      default -> throw new AssertionError("Unexpected proof type");
    };

    return calculateRootHash(leafHash, update.standInHashSeed(), update.commitmentIndex(), copath, LEAF_LEVEL);
  }

  /**
   * Returns the new prefix tree root hash for the given fake update. This involves calculating a new stand-in hash and
   * combining that with the provided copath and/or stand-in hashes (calculated from the provided seed) to hash our way
   * back up to the root hash.
   *
   * @param update the update for which to calculate the new prefix tree root hash
   * @return the new prefix tree root hash for the given fake update
   */
  @VisibleForTesting
  byte[] calculateNewRootHashForFakeUpdate(final AuditorUpdate update) throws InvalidProofException {
    final byte[] standInHash;
    final List<byte[]> copath;

    switch (update.proof()) {
      case NewTreeProof ignored -> throw new InvalidProofException("NewTree proof cannot be given for a fake update");
      case DifferentKeyProof differentKeyProof -> {
        standInHash = calculateStandInHash(update.standInHashSeed(), differentKeyProof.copath().size());
        copath = differentKeyProof.copath();
      }
      case SameKeyProof ignored -> throw new InvalidProofException("sameKey proof cannot be given for a fake update");
      default -> throw new AssertionError("Unexpected proof type");
    }

    return calculateRootHash(standInHash, update.standInHashSeed(), update.commitmentIndex(), copath, copath.size());
  }

  Optional<byte[]> getRootHash() {
    return rootHash;
  }

  /**
   * Calculate the root hash of the prefix tree after the update represented by the starting hash. The "dense" part of
   * the prefix tree refers to intermediate nodes in the direct path of a populated leaf node. The hashes of those
   * intermediate nodes are provided by the key transparency service when they are in the copath of another node.
   *
   * @param startingHash    the hash to start with. Will be a leaf hash for a real update and a stand-in hash for a fake
   *                        update.
   * @param seed            a pseudo-random value that is combined with a prefix tree level to calculate stand-in
   *                        sibling hashes in the sparse part of the prefix tree
   * @param commitmentIndex a 256-bit value used to traverse the prefix tree
   * @param copath          the sibling hashes in the dense part of the prefix tree. Ordered from root to leaf.
   * @param startingLevel   the level to start from in traversing up to the root of the prefix tree
   * @return the root hash of the prefix tree after the update represented by the starting hash
   */
  @VisibleForTesting
  static byte[] calculateRootHash(final byte[] startingHash,
      final byte[] seed,
      final byte[] commitmentIndex,
      final List<byte[]> copath,
      final int startingLevel) {
    validateByteArrayLength(startingHash, 32, "Starting hash must be 32 bytes");
    validateByteArrayLength(seed, 16, "Seed must be 16 bytes");
    validateByteArrayLength(commitmentIndex, 32, "Commitment index must be 32 bytes");

    for (final byte[] hash : copath) {
      validateByteArrayLength(hash, 32, "Intermediate hash must be 32 bytes");
    }

    if (copath.size() > 256 || startingLevel <= ROOT_LEVEL || startingLevel > LEAF_LEVEL) {
      throw new IllegalArgumentException("Invalid copath size or starting level");
    }

    byte[] hash = startingHash;
    for (int level = startingLevel; level > ROOT_LEVEL; level--) {
      // if we are in the dense part of the prefix tree, use the corresponding copath value;
      // otherwise calculate a stand-in hash
      final byte[] siblingHash = level <= copath.size() ? copath.get(level - 1) : calculateStandInHash(seed, level);

      hash = isBitSet(commitmentIndex, level)
          ? calculateParentHash(siblingHash, hash)
          : calculateParentHash(hash, siblingHash);
    }
    return hash;
  }

  /**
   * Returns whether the bit corresponding to the given level in the commitment index is 1.
   *
   * @param commitmentIndex a big-endian representation of 256 bits used to traverse the prefix tree
   * @param level           the level of interest
   * @return whether the bit corresponding to {@param level} in {@param commitmentIndex} is 1
   */
  @VisibleForTesting
  static boolean isBitSet(final byte[] commitmentIndex, final int level) {
    // bitIndex is the index of the bit at the given level
    // e.g. at level 1, we want the bit at index 0
    final int bitIndex = level - 1;

    // get the byte that contains the bit of interest
    final byte nthByte = commitmentIndex[bitIndex / 8];

    // and how many times to right shift the bit
    final int rightShiftNumTimes = 7 - bitIndex % 8;

    return ((nthByte >> rightShiftNumTimes) & 1) == 1;
  }

  @VisibleForTesting
  static byte[] calculateLeafHash(final byte[] commitmentIndex, final int updateCount, final long logTreePosition) {
    validateByteArrayLength(commitmentIndex, 32, "Commitment index must be 32 bytes");

    if (updateCount < 0 || logTreePosition < 0) {
      throw new IllegalArgumentException("Update count and log tree position cannot be less than 0");
    }

    // big-endian is the default byte order for ByteBuffer, no matter the underlying platform's native byte order
    final ByteBuffer countAndPositionBuffer = ByteBuffer.allocate(12);
    countAndPositionBuffer.putInt(updateCount);
    countAndPositionBuffer.putLong(logTreePosition);
    countAndPositionBuffer.flip();

    final MessageDigest messageDigest = Sha256MessageDigest.getMessageDigest();
    messageDigest.update(LEAF_NODE_DOMAIN_INDICATOR);
    messageDigest.update(commitmentIndex);
    messageDigest.update(countAndPositionBuffer);
    return messageDigest.digest();
  }

  @VisibleForTesting
  static byte[] calculateParentHash(final byte[] left, final byte[] right) {
    validateByteArrayLength(left, 32, "Left hash must be 32 bytes");
    validateByteArrayLength(right, 32, "Right hash must be 32 bytes");

    final MessageDigest messageDigest = Sha256MessageDigest.getMessageDigest();
    messageDigest.update(INTERMEDIATE_NODE_DOMAIN_INDICATOR);
    messageDigest.update(left);
    messageDigest.update(right);
    return messageDigest.digest();
  }

  @VisibleForTesting
  static byte[] calculateStandInHash(final byte[] seed, final int level) {
    validateByteArrayLength(seed, 16, "Seed must be 16 bytes");

    if (level <= ROOT_LEVEL || level > LEAF_LEVEL) {
      throw new IllegalArgumentException("Level must be greater than 0 and less than or equal to 256");
    }

    final MessageDigest messageDigest = Sha256MessageDigest.getMessageDigest();
    messageDigest.update(STAND_IN_NODE_DOMAIN_INDICATOR);
    messageDigest.update(seed);

    // We subtract one from the level index because we need it to fit within a byte
    // and will never calculate a stand-in hash for level 0 (the root node).
    messageDigest.update((byte) (level - 1));
    return messageDigest.digest();
  }

  private static void validateByteArrayLength(final byte[] bytes, final int expectedLength, final String errorMessage) {
    if (bytes.length != expectedLength) {
      throw new IllegalArgumentException(errorMessage);
    }
  }
}
