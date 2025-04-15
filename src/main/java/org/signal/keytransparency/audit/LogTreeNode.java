/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.keytransparency.audit;

/**
 * A leaf or intermediate node in the log tree.
 *
 * @param id   the node ID
 * @param hash the hash stored by the node. See {@link CondensedLogTree#calculateLeafHash} and
 *             {@link CondensedLogTree#addLeafNode} for leaf and intermediate hash calculations, respectively.
 */
public record LogTreeNode(long id, byte[] hash) {
}
