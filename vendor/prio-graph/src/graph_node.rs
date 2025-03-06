use crate::TransactionId;

/// A single node in a priority graph that is associated with a `Transaction`.
/// When a node reaches the main queue, the top-level prioritization function can use a reference
/// to this node to calculate a modified priority for the node, which is only used for
/// prioritization for the main queue.
pub struct GraphNode<Id: TransactionId> {
    /// Whether this node is active, i.e. has not been removed from the main queue.
    pub(crate) active: bool,
    /// Number of edges into this node.
    pub(crate) blocked_by_count: usize,
    /// Unique edges from this node.
    /// The number of edges is the same as the number of forks.
    pub edges: Vec<Id>,
}

impl<Id: TransactionId> GraphNode<Id> {
    /// Returns true if the edge was added successfully.
    /// Edges are only added if the edge is unique.
    /// Because we always add edges as we insert, the edge is unique if the
    /// `id` does not match the last element in the `edges` vector.
    pub fn try_add_edge(&mut self, id: Id) -> bool {
        if self.edges.last() == Some(&id) {
            false
        } else {
            self.edges.push(id);
            true
        }
    }
}
