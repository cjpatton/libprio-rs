// SPDX-License-Identifier: MPL-2.0

//! Types for defining binary trees.

type SubTree<V> = Option<Box<Node<V>>>;

/// Represents a node of a binary tree.
pub struct Node<V> {
    /// XXX
    pub value: V,
    /// XXX
    pub left: SubTree<V>,
    /// XXX
    pub right: SubTree<V>,
}

impl<V> Node<V> {
    /// XXX
    pub fn new(value: V) -> Self {
        Self {
            value,
            left: None,
            right: None,
        }
    }
}

/// Represents an append-only binary tree.
pub struct BinaryTree<V> {
    /// XXX
    pub root: SubTree<V>,
}

impl<V> Default for BinaryTree<V> {
    fn default() -> Self {
        Self {
            root: Option::default(),
        }
    }
}
