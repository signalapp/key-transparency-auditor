/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.signal.keytransparency.audit.util.Util.generateRandomBytes;

public class CondensedPrefixTreeTest {

  private CondensedPrefixTree condensedPrefixTree;

  @BeforeEach
  void setUp() {
    condensedPrefixTree = new CondensedPrefixTree();
  }

  private record FakeProof() implements AuditorProof {
  }

  @Test
  void verifyStartingRootHashNotNewTreeInvalidProof() throws InvalidProofException {
    final NewTreeProof newTreeProof = new NewTreeProof();
    final AuditorUpdate firstUpdate = generateAuditorUpdateWithProof(newTreeProof);
    final AuditorUpdate secondUpdate = generateAuditorUpdateWithProof(newTreeProof);
    condensedPrefixTree.applyUpdate(firstUpdate, 0);
    assertThrows(InvalidProofException.class, () -> condensedPrefixTree.verifyStartingRootHash(secondUpdate, 1));
  }

  @Test
  void verifyStartingRootHashForNewTreeInvalidProof() {
    final DifferentKeyProof differentKeyProof = new DifferentKeyProof(generateRandomBytes(16),
        List.of(generateRandomBytes(32)));
    final AuditorUpdate firstUpdate = generateAuditorUpdateWithProof(differentKeyProof);
    assertThrows(InvalidProofException.class, () -> condensedPrefixTree.applyUpdate(firstUpdate, 0));
  }

  @Test
  void verifyStartingRootHashSameKeyInvalidProof() throws InvalidProofException {
    final NewTreeProof newTreeProof = new NewTreeProof();
    final DifferentKeyProof differentKeyProof = new DifferentKeyProof(generateRandomBytes(16),
        List.of(generateRandomBytes(32)));
    final AuditorUpdate firstUpdate = generateAuditorUpdateWithProof(newTreeProof);

    final AuditorUpdate secondUpdate = generateAuditorUpdateWithProof(differentKeyProof);
    condensedPrefixTree.applyUpdate(firstUpdate, 0);
    assertThrows(InvalidProofException.class, () -> condensedPrefixTree.verifyStartingRootHash(secondUpdate, 1));
  }

  @Test
  void verifyStartingRootHashUnexpectedProofType() throws InvalidProofException {
    final NewTreeProof newTreeProof = new NewTreeProof();
    final AuditorUpdate firstUpdate = generateAuditorUpdateWithProof(newTreeProof);
    condensedPrefixTree.applyUpdate(firstUpdate, 0);

    final FakeProof fakeProof = new FakeProof();
    final AuditorUpdate update = generateAuditorUpdateWithProof(fakeProof);

    assertThrows(AssertionError.class, () -> condensedPrefixTree.verifyStartingRootHash(update, 1));
  }

  @Test
  void verifyStartingRootHashEmptyRootHash() {
    final FakeProof fakeProof = new FakeProof();
    final AuditorUpdate update = generateAuditorUpdateWithProof(fakeProof);

    assertThrows(InvalidProofException.class, () -> condensedPrefixTree.verifyStartingRootHash(update, 1));
  }

  @Test
  void calculateNewRootHashForRealUpdateUnexpectedProofType() {
    assertThrows(AssertionError.class, () ->
        condensedPrefixTree.calculateNewRootHashForRealUpdate(generateAuditorUpdateWithProof(new FakeProof()), 0));
  }

  @Test
  void calculateNewRootHashForFakeUpdateUnexpectedProofType() {
    assertThrows(AssertionError.class, () ->
        condensedPrefixTree.calculateNewRootHashForFakeUpdate(generateAuditorUpdateWithProof(new FakeProof())));
  }

  @Test
  void calculateNewRootHashForFakeUpdateIllegalArgument() {
    assertThrows(InvalidProofException.class, () ->
        condensedPrefixTree.calculateNewRootHashForFakeUpdate(generateAuditorUpdateWithProof(new NewTreeProof())));
    assertThrows(InvalidProofException.class, () ->
        condensedPrefixTree.calculateNewRootHashForFakeUpdate(generateAuditorUpdateWithProof(new SameKeyProof(
            0,
            1,
            List.of(generateRandomBytes(32))
        ))));
  }

  private AuditorUpdate generateAuditorUpdateWithProof(final AuditorProof proof) {
    return new AuditorUpdate(
        true,
        generateRandomBytes(32),
        generateRandomBytes(16),
        generateRandomBytes(32),
        proof);
  }

  @ParameterizedTest
  @MethodSource
  void calculateRootHashInvalidInput(final byte[] startingHash,
      final byte[] seed,
      final byte[] commitmentIndex,
      final List<byte[]> copath,
      final int startingLevel) {
    assertThrows(IllegalArgumentException.class, () ->
        CondensedPrefixTree.calculateRootHash(startingHash, seed, commitmentIndex, copath, startingLevel));
  }

  private static Stream<Arguments> calculateRootHashInvalidInput() {
    final byte[] validStartingHash = generateRandomBytes(32);
    final byte[] validSeed = generateRandomBytes(16);
    final byte[] validCommitmentIndex = generateRandomBytes(32);
    final List<byte[]> validCopath = List.of(generateRandomBytes(32));
    final int validStartingLevel = 25;

    final List<byte[]> tooLongCopathList = new java.util.ArrayList<>(Collections.emptyList());
    IntStream.range(0, 257).forEach(unused -> tooLongCopathList.add(generateRandomBytes(32)));

    return Stream.of(
        // Invalid startingHash
        Arguments.of(generateRandomBytes(31), validSeed, validCommitmentIndex, validCopath, validStartingLevel),
        // Invalid seed
        Arguments.of(validStartingHash, generateRandomBytes(15), validCommitmentIndex, validCopath, validStartingLevel),
        // Invalid commitmentIndex
        Arguments.of(validStartingHash, validSeed, generateRandomBytes(31), validCopath, validStartingLevel),
        // Invalid copath hash size
        Arguments.of(validStartingHash, validSeed, validCommitmentIndex, List.of(generateRandomBytes(31)),
            validStartingLevel),
        // Invalid copath length
        Arguments.of(validStartingHash, validSeed, validCommitmentIndex, tooLongCopathList, validStartingLevel),
        // Starting level too small
        Arguments.of(validStartingHash, validSeed, validCommitmentIndex, List.of(generateRandomBytes(31)), 0),
        // Starting level too large
        Arguments.of(validStartingHash, validSeed, validCommitmentIndex, List.of(generateRandomBytes(31)), 257)
    );
  }

  @ParameterizedTest
  @MethodSource
  void calculateLeafHashInvalidInput(final byte[] commitmentIndex,
      final int updateCount,
      final long logTreePosition) {
    assertThrows(IllegalArgumentException.class, () ->
        CondensedPrefixTree.calculateLeafHash(commitmentIndex, updateCount, logTreePosition));
  }

  private static Stream<Arguments> calculateLeafHashInvalidInput() {
    final byte[] validCommitmentIndex = generateRandomBytes(32);
    return Stream.of(
        // Invalid commitment index
        Arguments.of(generateRandomBytes(31), 0, 0),
        // Invalid update count
        Arguments.of(validCommitmentIndex, -1, 0),
        // Invalid log tree position
        Arguments.of(validCommitmentIndex, 0, -1)
    );
  }

  @ParameterizedTest
  @MethodSource
  void calculateParentHashInvalidInput(final byte[] leftHash,
      final byte[] rightHash) {
    assertThrows(IllegalArgumentException.class, () ->
        CondensedPrefixTree.calculateParentHash(leftHash, rightHash));
  }

  private static Stream<Arguments> calculateParentHashInvalidInput() {
    final byte[] validHash = generateRandomBytes(32);
    return Stream.of(
        Arguments.of(generateRandomBytes(31), validHash),
        Arguments.of(validHash, generateRandomBytes(31))
    );
  }

  @ParameterizedTest
  @MethodSource
  void calculateStandInHashInvalidInput(final byte[] seed, final int level) {
    assertThrows(IllegalArgumentException.class, () ->
        CondensedPrefixTree.calculateStandInHash(seed, level));
  }

  private static Stream<Arguments> calculateStandInHashInvalidInput() {
    final byte[] validSeed = generateRandomBytes(16);
    return Stream.of(
        Arguments.of(validSeed, 0),
        Arguments.of(validSeed, 257),
        Arguments.of(generateRandomBytes(15), 1)
    );
  }

  @ParameterizedTest
  @MethodSource
  void isBitSet(final byte[] commitmentIndex, final int level, final boolean expected) {
    assertEquals(expected, CondensedPrefixTree.isBitSet(commitmentIndex, level));
  }

  private static Stream<Arguments> isBitSet() {
    return Stream.of(
        Arguments.of(new byte[]{1, 1, 1}, 3, false),
        Arguments.of(new byte[]{1, 1, 1}, 17, false),
        Arguments.of(new byte[]{1, 1, 1}, 8, true),
        Arguments.of(new byte[]{1, 1, 1}, 16, true)
    );
  }
}
