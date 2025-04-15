/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

import com.google.common.annotations.VisibleForTesting;
import org.signal.keytransparency.audit.util.Sha256MessageDigest;

import java.security.MessageDigest;
import java.util.*;

/**
 * A condensed form of the key transparency service's left balanced, binary Merkle log tree that only stores enough
 * nodes to reconstruct the root hash.
 * <p>
 * Nodes are stored in ascending order by node ID, where each node is either a leaf or the root of a full subtree.
 */
class CondensedLogTree {

  private final ArrayDeque<LogTreeNode> nodes;
  @VisibleForTesting
  static byte LEAF_NODE_DOMAIN_INDICATOR = 0x00;
  @VisibleForTesting
  static byte INTERMEDIATE_NODE_DOMAIN_INDICATOR = 0x01;

  CondensedLogTree() {
    this.nodes = new ArrayDeque<>();
  }

  CondensedLogTree(final Collection<LogTreeNode> logTreeNodes, final long numLogEntries) {
    this.nodes = new ArrayDeque<>();
    // make sure the nodes are in ascending order by node ID
    logTreeNodes.stream()
        .sorted(Comparator.comparingLong(LogTreeNode::id))
        .forEach(nodes::addLast);

    // verify that the given nodes are what we expect for a log tree of the given size
    verifyConsistentState(nodes, getMaxLeafNodeId(numLogEntries));
  }

  /**
   * @param numLogEntries the number of log entries in the tree
   * @return the maximum leaf node ID in the log tree given the number of log entries
   */
  @VisibleForTesting
  static long getMaxLeafNodeId(final long numLogEntries) {
    if (numLogEntries <= 0) {
      throw new IllegalArgumentException("Number of log entries must be greater than 0");
    }

    return (numLogEntries - 1) * 2;
  }

  /**
   * Verifies that the IDs and ordering of the given nodes are consistent with what is expected for a log tree of the
   * given size.
   *
   * @param actualNodes   the stored nodes in the log tree
   * @param maxLeafNodeId the maximum leaf node ID in the log tree
   * @throws IllegalArgumentException if the stored node IDs do not match the expected set of node IDs
   */
  @VisibleForTesting
  static void verifyConsistentState(final Collection<LogTreeNode> actualNodes, final long maxLeafNodeId) {
    final List<Long> expectedNodes = getFullSubtreeRootNodeIds(maxLeafNodeId);
    if (!expectedNodes.equals(actualNodes.stream().map(LogTreeNode::id).toList())) {
      throw new IllegalArgumentException(
          "Stored node IDs do not match the expected node IDs for a tree of the given size");
    }
  }

  /**
   * Given a node ID and the max leaf node ID, return whether the given node ID is the root of a full subtree in the log tree.
   * A subtree is considered full if the number of leaves it has is a power of two.
   *
   * @param nodeId        the node ID for which to determine if it serves as the root of a full subtree
   * @param maxLeafNodeId the maximum leaf node ID in the log tree
   * @return whether the given node is the root of a full subtree
   */
  @VisibleForTesting
  static boolean isFullSubtree(final long nodeId, final long maxLeafNodeId) {
    if (nodeId < 0 || maxLeafNodeId < 0) {
      throw new IllegalArgumentException("Node IDs must be non-negative");
    } else if (nodeId > maxLeafNodeId) {
      throw new IllegalArgumentException("The given node does not exist in the tree");
    }

    // calculate the expected max leaf node ID in a full subtree where nodeId is the root
    final long expectedMaxLeafNodeId = nodeId + (1L << getLevel(nodeId)) - 1;

    return expectedMaxLeafNodeId <= maxLeafNodeId;
  }

  /**
   * Returns the list of full subtree root node IDs starting from the root node of the log tree and traversing down
   * the right side. Because the log tree is left-balanced, if a right child node exists, the left subtree must be
   * full.
   *
   * @param maxLeafNodeId the maximum leaf node ID in the log tree
   * @return a list of node IDs that are the root nodes of full subtrees in the log tree
   */
  @VisibleForTesting
  static List<Long> getFullSubtreeRootNodeIds(final long maxLeafNodeId) {
    if (maxLeafNodeId < 0) {
      throw new IllegalArgumentException("Node IDs must be non-negative");
    }

    long rootNodeId = getRoot(maxLeafNodeId);
    final List<Long> subtreeRootNodeIds = new ArrayList<>();
    while (!isFullSubtree(rootNodeId, maxLeafNodeId)) {
      subtreeRootNodeIds.add(getLeftChild(rootNodeId));
      rootNodeId = getRightChild(rootNodeId, maxLeafNodeId);
    }
    subtreeRootNodeIds.add(rootNodeId);

    return subtreeRootNodeIds;
  }

  /**
   * Adds a leaf node to the condensed log tree.
   * As each leaf node is added, the condensed log tree calculates and stores the root node of the largest full subtree
   * created by the addition of the leaf node, discarding any intermediate nodes that were previously stored.
   *
   * @param commitment         a cryptographic hash of the update
   * @param prefixTreeRootHash the root hash of the prefix tree after the given update
   * @param numLogEntries      the total number of updates processed so far by the auditor
   */
  void addLeafNode(final byte[] commitment, final byte[] prefixTreeRootHash, final long numLogEntries) {
    final long maxLeafNodeId = numLogEntries * 2; // the maximum leaf node ID when including the current node
    byte[] currentHash = calculateLeafHash(prefixTreeRootHash, commitment);
    long currentNodeId = maxLeafNodeId;
    int currentLevel = 0;
    final MessageDigest messageDigest = Sha256MessageDigest.getMessageDigest();

    // If the current node has the same level as the most recently added node in the list,
    // the two are part of a full subtree and can therefore be discarded in favor of the parent node.
    while (!nodes.isEmpty() && getLevel(nodes.peekLast().id()) == currentLevel) {

      // Pop the node from the stack
      final LogTreeNode node = nodes.removeLast();

      // Get the hash of the parent node
      final byte domainIndicator = currentLevel == 0 ? LEAF_NODE_DOMAIN_INDICATOR : INTERMEDIATE_NODE_DOMAIN_INDICATOR;
      messageDigest.update(domainIndicator);
      messageDigest.update(node.hash());
      messageDigest.update(domainIndicator);
      messageDigest.update(currentHash);
      currentHash = messageDigest.digest();

      // Calculate the node ID and level of the parent node
      currentNodeId = getParent(node.id(), maxLeafNodeId);
      currentLevel += 1;
    }

    // Add the node to the stack
    nodes.addLast(new LogTreeNode(currentNodeId, currentHash));
  }

  /**
   * Given the commitment and prefix tree root hash associated with an update, calculates the leaf hash of the log
   * tree.
   *
   * @param commitment         a cryptographic hash of the update
   * @param prefixTreeRootHash the root hash of the prefix tree after the update represented by the commitment
   * @return the log tree leaf hash corresponding to the given update
   */
  private static byte[] calculateLeafHash(final byte[] prefixTreeRootHash, final byte[] commitment) {
    final MessageDigest messageDigest = Sha256MessageDigest.getMessageDigest();
    messageDigest.update(prefixTreeRootHash);
    messageDigest.update(commitment);
    return messageDigest.digest();
  }

  /**
   * Returns the node ID of the parent of the given node in a log tree of a given size.
   *
   * @param nodeId        the ID of the node for which to find a parent
   * @param maxLeafNodeId the ID of the right-most leaf node in the tree
   * @return the ID of the parent of the given node
   * @throws IllegalArgumentException if the given node is the root of the tree, is not present in a log tree with the
   *                                  given maximum leaf node ID, or is negative
   */
  @VisibleForTesting
  static long getParent(final long nodeId, final long maxLeafNodeId) {
    if (nodeId < 0 || maxLeafNodeId < 0) {
      throw new IllegalArgumentException("Node IDs must be non-negative");
    } else if (nodeId > maxLeafNodeId) {
      throw new IllegalArgumentException("The given node does not exist in the tree");
    }

    final long rootNodeId = getRoot(maxLeafNodeId);
    if (nodeId == rootNodeId) {
      throw new IllegalArgumentException("Root nodes do not have parent nodes");
    }

    long parentNodeId = rootNodeId;

    // Descend from the root until our next step is the target node
    while (true) {
      final long childNodeId =
          nodeId < parentNodeId ? getLeftChild(parentNodeId) : getRightChild(parentNodeId, maxLeafNodeId);

      if (childNodeId != nodeId) {
        parentNodeId = childNodeId;
      } else {
        break;
      }
    }

    return parentNodeId;
  }

  /**
   * Reconstructs the root hash of the log tree.
   * <p>
   * If only one node is stored, then it contains the root hash. Otherwise, hash together the last two nodes to produce
   * their parent hash. This intermediate parent hash is then hashed with the next node in the stack, and so on, until
   * the root of the log tree is reached.
   *
   * @return the root hash of the log tree
   * @throws IllegalArgumentException if there are no entries in the log tree
   */
  byte[] getRootHash() {
    if (nodes.isEmpty()) {
      throw new IllegalArgumentException("Cannot return root hash of an empty log tree");
    } else if (nodes.size() == 1) {
      return nodes.peek().hash();
    } else {
      final MessageDigest messageDigest = Sha256MessageDigest.getMessageDigest();

      // we stored the nodes in ascending order by node ID
      // but hash them together in reverse order to get the root hash of the log tree
      final LogTreeNode mostRecentlyAddedNode = nodes.getLast();
      byte[] rootHash = mostRecentlyAddedNode.hash();
      // only the most recently added node has the potential to be a leaf
      boolean isLeafNode = isLeafNode(mostRecentlyAddedNode.id());

      final Iterator<LogTreeNode> reverseIterator =  nodes.descendingIterator();
      // skip the most recent node
      reverseIterator.next();
      while (reverseIterator.hasNext()) {
        final LogTreeNode node = reverseIterator.next();
        messageDigest.update(INTERMEDIATE_NODE_DOMAIN_INDICATOR);
        messageDigest.update(node.hash());
        messageDigest.update(isLeafNode ? LEAF_NODE_DOMAIN_INDICATOR : INTERMEDIATE_NODE_DOMAIN_INDICATOR);
        messageDigest.update(rootHash);

        rootHash = messageDigest.digest();
        isLeafNode = false;
      }
      return rootHash;
    }
  }

  List<LogTreeNode> getNodes() {
    return nodes.stream().toList();
  }

  /**
   * Returns the node ID of the left child of an intermediate node within a log tree. Callers are responsible for
   * checking that the {@code nodeId} does not exceed the tree's maximum node ID.
   *
   * @param nodeId the node ID of the intermediate node for which to find the left child node
   * @return the node ID of the left child of the given intermediate node
   * @throws IllegalArgumentException if the given node ID belongs to a leaf node or is negative
   */
  @VisibleForTesting
  static long getLeftChild(final long nodeId) {
    if (nodeId < 0) {
      throw new IllegalArgumentException("Node ID must be non-negative");
    } else if (isLeafNode(nodeId)) {
      throw new IllegalArgumentException("Leaf nodes do not have children");
    }

    return nodeId - (1L << (getLevel(nodeId) - 1));
  }

  /**
   * Returns the node ID of the right child of an intermediate node within a log tree of a given size.
   *
   * @param nodeId the node ID of the intermediate node for which to find the right child node
   * @return the node ID of the right child of the given intermediate node
   * @throws IllegalArgumentException if the given node ID belongs to a leaf node or is not present in the log tree or
   *                                  is negative
   */
  @VisibleForTesting
  static long getRightChild(final long nodeId, final long maxLeafNodeId) {
    if (nodeId < 0 || maxLeafNodeId < 0) {
      throw new IllegalArgumentException("Node IDs must be non-negative");
    } else if (isLeafNode(nodeId)) {
      throw new IllegalArgumentException("Leaf nodes do not have children");
    } else if (nodeId > maxLeafNodeId) {
      throw new IllegalArgumentException("Tree does not contain given intermediate node");
    }

    // Start at where we think the right child WOULD be if this were a full subtree, then walk left until we find a
    // child node that ACTUALLY IS in a tree of the given size
    long rightNodeId = nodeId + (1L << (getLevel(nodeId) - 1));

    while (rightNodeId > maxLeafNodeId) {
      rightNodeId = getLeftChild(rightNodeId);
    }

    return rightNodeId;
  }

  /**
   * Returns the node ID of the root node in a log tree of a given size.
   *
   * @param maxLeafNodeId the ID of the right-most leaf node in the tree
   * @return the node ID of the root node in a log tree of a given size
   * @throws IllegalArgumentException if {@param maxLeafNodeId} is negative
   */
  @VisibleForTesting
  static long getRoot(final long maxLeafNodeId) {
    if (maxLeafNodeId < 0) {
      throw new IllegalArgumentException("Max leaf node ID must be non-negative");
    }

    return maxLeafNodeId == 0 ? 0 : Long.highestOneBit(maxLeafNodeId) - 1;
  }

  /**
   * Returns the level of a given node ID within a log tree. Leaf nodes are located at the bottom level (0), and the
   * level of a node's parent is equal to the level of the node plus 1.  Callers are responsible for checking
   * that the {@code nodeId} does not exceed the tree's maximum node ID.
   *
   * @param nodeId the ID of the node for which to find a level within the log tree
   * @return the node's level within the log tree
   * @throws IllegalArgumentException if {@param nodeId} is negative
   */
  @VisibleForTesting
  static int getLevel(final long nodeId) {
    if (nodeId < 0) {
      throw new IllegalArgumentException("Node IDs must be non-negative");
    }

    return isLeafNode(nodeId) ? 0 : Long.numberOfTrailingZeros(~nodeId);
  }

  /**
   * Indicates whether the given node ID maps to a leaf node in a log tree. Callers are responsible for checking
   * that the {@code nodeId} does not exceed the tree's maximum node ID.
   *
   * @param nodeId the ID of the node to inspect
   * @return {@code true} if the given node ID belongs to a leaf node or {@code false} if the given node ID belongs to
   * an intermediate node
   * @throws IllegalArgumentException if the given node ID is negative
   */
  @VisibleForTesting
  static boolean isLeafNode(final long nodeId) {
    if (nodeId < 0) {
      throw new IllegalArgumentException("Node IDs must be non-negative");
    }

    return nodeId % 2 == 0;
  }
}
