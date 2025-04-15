/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.signal.keytransparency.audit.util.Util;
import org.signal.keytransparency.audit.util.Sha256MessageDigest;

import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class CondensedLogTreeTest {

  private CondensedLogTree condensedLogTree;

  @BeforeEach
  void setUp() {
    condensedLogTree = new CondensedLogTree();
  }

  @Test
  void constructNewCondensedLogTree() {
    final List<org.signal.keytransparency.audit.LogTreeNode> nodes = new ArrayList<>(List.of(
        new org.signal.keytransparency.audit.LogTreeNode(9, new byte[32]),
        new org.signal.keytransparency.audit.LogTreeNode(12, new byte[32]),
        new org.signal.keytransparency.audit.LogTreeNode(3, new byte[32])
    ));
    final CondensedLogTree condensedLogTree1 = new CondensedLogTree(nodes, 7);
    nodes.sort(Comparator.comparingLong(org.signal.keytransparency.audit.LogTreeNode::id));

    assertEquals(nodes, condensedLogTree1.getNodes());
  }

  @Test
  void getRootHashEmptyLogTree() {
    assertThrows(IllegalArgumentException.class, () -> condensedLogTree.getRootHash());
  }

  @Test
  void addLeafNodeAndGetRootHash() {
    // add first log entry
    final byte[] firstCommitment = Util.generateRandomBytes(32);
    final byte[] firstPrefixTreeRootHash = Util.generateRandomBytes(32);
    condensedLogTree.addLeafNode(firstCommitment, firstPrefixTreeRootHash, 0);

    final MessageDigest messageDigest = Sha256MessageDigest.getMessageDigest();
    messageDigest.update(firstPrefixTreeRootHash);
    messageDigest.update(firstCommitment);
    final byte[] expectedFirstLeafHash = messageDigest.digest();

    // check stored node
    assertEquals(1, condensedLogTree.getNodes().size());
    assertEquals(0L, condensedLogTree.getNodes().getFirst().id());
    assertArrayEquals(expectedFirstLeafHash, condensedLogTree.getNodes().getFirst().hash());

    // check root hash
    assertArrayEquals(expectedFirstLeafHash, condensedLogTree.getRootHash());

    // add second log entry
    final byte[] secondCommitment = Util.generateRandomBytes(32);
    final byte[] secondPrefixTreeRootHash = Util.generateRandomBytes(32);
    condensedLogTree.addLeafNode(secondCommitment, secondPrefixTreeRootHash, 1);

    messageDigest.update(secondPrefixTreeRootHash);
    messageDigest.update(secondCommitment);
    final byte[] expectedSecondLeafHash = messageDigest.digest();

    messageDigest.update(CondensedLogTree.LEAF_NODE_DOMAIN_INDICATOR);
    messageDigest.update(expectedFirstLeafHash);
    messageDigest.update(CondensedLogTree.LEAF_NODE_DOMAIN_INDICATOR);
    messageDigest.update(expectedSecondLeafHash);
    final byte[] expectedSecondLogTreeRootHash = messageDigest.digest();

    // check stored node
    assertEquals(1, condensedLogTree.getNodes().size());
    assertEquals(1L, condensedLogTree.getNodes().getFirst().id());
    assertArrayEquals(expectedSecondLogTreeRootHash, condensedLogTree.getNodes().getFirst().hash());

    // check root hash
    assertArrayEquals(expectedSecondLogTreeRootHash, condensedLogTree.getRootHash());

    // add third log entry
    final byte[] thirdCommitment = Util.generateRandomBytes(32);
    final byte[] thirdPrefixTreeRootHash = Util.generateRandomBytes(32);
    condensedLogTree.addLeafNode(thirdCommitment, thirdPrefixTreeRootHash, 2);

    messageDigest.update(thirdPrefixTreeRootHash);
    messageDigest.update(thirdCommitment);
    final byte[] expectedThirdLeafHash = messageDigest.digest();

    messageDigest.update(CondensedLogTree.INTERMEDIATE_NODE_DOMAIN_INDICATOR);
    messageDigest.update(expectedSecondLogTreeRootHash);
    messageDigest.update(CondensedLogTree.LEAF_NODE_DOMAIN_INDICATOR);
    messageDigest.update(expectedThirdLeafHash);
    final byte[] expectedThirdLogTreeRootHash = messageDigest.digest();

    final List<org.signal.keytransparency.audit.LogTreeNode> listNodes = condensedLogTree.getNodes().stream().toList();

    // check stored nodes
    assertEquals(2, condensedLogTree.getNodes().size());
    assertEquals(List.of(1L, 4L),
        condensedLogTree.getNodes().stream().map(org.signal.keytransparency.audit.LogTreeNode::id).toList());
    assertArrayEquals(expectedSecondLogTreeRootHash, listNodes.get(0).hash());
    assertArrayEquals(expectedThirdLeafHash, listNodes.get(1).hash());

    // check root hash
    assertArrayEquals(expectedThirdLogTreeRootHash, condensedLogTree.getRootHash());
  }

  @ParameterizedTest
  @CsvSource({
      "0, 0, true",
      "3, 4, false",
      "3, 12, true",
      "9, 12, true"
  })
  void isFullSubtree(final long nodeId, final long maxLeafNodeId, final boolean expectedIsFullSubtree) {
    assertEquals(expectedIsFullSubtree, CondensedLogTree.isFullSubtree(nodeId, maxLeafNodeId));
  }

  @ParameterizedTest
  @CsvSource({
      "-1, 0", // nodeId is negative
      "0, -1", // maxLeafNodeId is negative
      "5, 4", // nodeId does not exist in tree
  })
  void isFullSubtreeIllegalNodeId(final long nodeId, final long maxLeafNodeId) {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.isFullSubtree(nodeId, maxLeafNodeId));
  }

  @ParameterizedTest
  @MethodSource
  void getFullSubtreeRootNodeIds(final long maxLeafNodeId, final List<Long> expectedRootNodeIds) {
    assertIterableEquals(expectedRootNodeIds, CondensedLogTree.getFullSubtreeRootNodeIds(maxLeafNodeId));
  }

  private static Stream<Arguments> getFullSubtreeRootNodeIds() {
    return Stream.of(
        Arguments.of(0, List.of(0L)),
        Arguments.of(2, List.of(1L)),
        Arguments.of(4, List.of(1L, 4L)),
        Arguments.of(6, List.of(3L)),
        Arguments.of(8, List.of(3L, 8L)),
        Arguments.of(12, List.of(3L, 9L, 12L))
    );
  }

  @Test
  void getFullSubtreeRootNodeIdsIllegalNodeId() {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.getFullSubtreeRootNodeIds(-1));
  }

  @ParameterizedTest
  @CsvSource({
      "1, 0",
      "2, 2",
      "3, 4",
      "6, 10"
  })
  void getMaxLeafNodeId(final long numLogEntries, final long expectedMaxLeafNodeId) {
    assertEquals(expectedMaxLeafNodeId, CondensedLogTree.getMaxLeafNodeId(numLogEntries));
  }

  @Test
  void getMaxLeafNodeIdIllegalNodeId() {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.getMaxLeafNodeId(0));
  }

  @ParameterizedTest
  @MethodSource
  void verifyConsistentState(final List<org.signal.keytransparency.audit.LogTreeNode> actualNodes,
      final long maxLeafNodeId,
      final boolean consistentState) {
    if (consistentState) {
      assertDoesNotThrow(() -> CondensedLogTree.verifyConsistentState(new ArrayDeque<>(actualNodes), maxLeafNodeId));
    } else {
      assertThrows(IllegalArgumentException.class,
          () -> CondensedLogTree.verifyConsistentState(new ArrayDeque<>(actualNodes), maxLeafNodeId));
    }
  }

  private static Stream<Arguments> verifyConsistentState() {
    return Stream.of(
        Arguments.of(List.of(new org.signal.keytransparency.audit.LogTreeNode(0, new byte[32])), 0, true),
        Arguments.of(List.of(new org.signal.keytransparency.audit.LogTreeNode(1, new byte[32])), 2, true),
        Arguments.of(List.of(
            new LogTreeNode(1, new byte[32]),
            new org.signal.keytransparency.audit.LogTreeNode(4, new byte[32])), 4, true),
        Arguments.of(List.of(
            new org.signal.keytransparency.audit.LogTreeNode(3, new byte[32]),
            new org.signal.keytransparency.audit.LogTreeNode(9, new byte[32]),
            new org.signal.keytransparency.audit.LogTreeNode(12, new byte[32])), 12, true),
        // wrong nodes
        Arguments.of(List.of(
            new org.signal.keytransparency.audit.LogTreeNode(3, new byte[32]),
            new org.signal.keytransparency.audit.LogTreeNode(9, new byte[32])), 12, false),
        // inconsistent ordering
        Arguments.of(List.of(
            new org.signal.keytransparency.audit.LogTreeNode(3, new byte[32]),
            new org.signal.keytransparency.audit.LogTreeNode(12, new byte[32]),
            new org.signal.keytransparency.audit.LogTreeNode(9, new byte[32])), 12, false)
    );
  }

  @ParameterizedTest
  @CsvSource({
      "1, 0",
      "3, 1",
      "7, 3",
      "9, 8"
  })
  void getLeftChild(final long nodeId, final long expectedLeftChildNodeId) {
    assertEquals(expectedLeftChildNodeId, CondensedLogTree.getLeftChild(nodeId));
  }

  @ParameterizedTest
  @CsvSource({
      "-1", // nodeId is negative
      "4", // nodeId is leaf node
  })
  void getLeftChildIllegalNodeId(final long nodeId) {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.getLeftChild(nodeId));
  }

  @ParameterizedTest
  @CsvSource({
      "1, 2, 2",
      "3, 4, 4",
      "3, 6, 5",
      "7, 8, 8",
      "7, 10, 9"
  })
  void getRightChild(final long nodeId, final long maxLeafNodeId, final long expectedRightChildNodeId) {
    assertEquals(expectedRightChildNodeId, CondensedLogTree.getRightChild(nodeId, maxLeafNodeId));
  }

  @ParameterizedTest
  @CsvSource({
      "-1, 2", // nodeId is negative
      "2, -1", // maxLeafNodeId is negative
      "4, 4", // nodeId is leaf node
      "5, 4", // nodeId does not exist in tree
  })
  void getRightChildIllegalNodeId(final long nodeId, final long maxLeafNodeId) {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.getRightChild(nodeId, maxLeafNodeId));
  }

  @ParameterizedTest
  @CsvSource({
      "0, 2, 1",
      "2, 4, 1",
      "3, 10, 7",
      "7, 16, 15"
  })
  void getParentNodeId(final long nodeId, final long maxLeafNodeId, final long expectedParentNodeId) {
    assertEquals(expectedParentNodeId, CondensedLogTree.getParent(nodeId, maxLeafNodeId));
  }

  @ParameterizedTest
  @CsvSource({
      "-1, 2", // nodeId is negative
      "2, -1", // maxLeafNodeId is negative
      "3, 4", // nodeId is root node
      "11, 10", // nodeId does not exist in tree
  })
  void getParentNodeIdIllegalNodeId(final long nodeId, final long maxLeafNodeId) {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.getParent(nodeId, maxLeafNodeId));
  }

  @ParameterizedTest
  @CsvSource({
      "0, 0",
      "2, 1",
      "4, 3",
      "6, 3",
      "10, 7"
  })
  void getRootNodeId(final long maxLeafNodeId, final long expectedRootNodeId) {
    assertEquals(expectedRootNodeId, CondensedLogTree.getRoot(maxLeafNodeId));
  }

  @Test
  void getRootNodeIdIllegalNodeId() {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.getRoot(-1));
  }

  @ParameterizedTest
  @CsvSource({
      "0, 0",
      "2, 0",
      "1, 1",
      "5, 1",
      "3, 2",
      "11, 2",
      "7, 3"
  })
  void getLevel(final long nodeId, final int expectedLevel) {
    assertEquals(expectedLevel, CondensedLogTree.getLevel(nodeId));
  }

  @Test
  void getLevelIllegalNodeId() {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.getLevel(-1));
  }

  @ParameterizedTest
  @CsvSource({
      "0, true",
      "16, true",
      "1, false",
      "15, false"
  })
  void isLeafNode(final long nodeId, final boolean expectLeafNode) {
    assertEquals(expectLeafNode, CondensedLogTree.isLeafNode(nodeId));
  }

  @Test
  void isLeafNodeIllegalNodeId() {
    assertThrows(IllegalArgumentException.class, () -> CondensedLogTree.isLeafNode(-1));
  }
}
