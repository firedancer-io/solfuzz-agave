use {
    crate::{
        lock::Lock, top_level_id::TopLevelId, AccessKind, GraphNode, ResourceKey, TransactionId,
    },
    ahash::AHashMap,
    std::collections::{hash_map::Entry, BinaryHeap},
};

/// A directed acyclic graph where edges are only present between nodes if
/// that node is the next-highest priority node for a particular resource.
/// Resources can be either read or write locked with write locks being
/// exclusive.
/// `Transaction`s are inserted into the graph and then popped in time-priority order.
/// Between conflicting transactions, the first to be inserted will always have higher priority.
pub struct PrioGraph<
    Id: TransactionId,
    Rk: ResourceKey,
    Tl: TopLevelId<Id>,
    Pfn: Fn(&Id, &GraphNode<Id>) -> Tl,
> {
    /// Locked resources and which transaction holds them.
    locks: AHashMap<Rk, Lock<Id>>,
    /// Graph edges and count of edges into each node. The count is used
    /// to detect joins.
    nodes: AHashMap<Id, GraphNode<Id>>,
    /// Main queue - currently unblocked transactions.
    main_queue: BinaryHeap<Tl>,
    /// Priority modification for top-level transactions.
    top_level_prioritization_fn: Pfn,
}

impl<
        Id: TransactionId,
        Rk: ResourceKey,
        Tl: TopLevelId<Id>,
        Pfn: Fn(&Id, &GraphNode<Id>) -> Tl,
    > PrioGraph<Id, Rk, Tl, Pfn>
{
    /// Drains all transactions from the primary queue into a batch.
    /// Then, for each transaction in the batch, unblock transactions it was blocking.
    /// If any of those transactions are now unblocked, add them to the main queue.
    /// Repeat until the main queue is empty.
    pub fn natural_batches(
        iter: impl IntoIterator<Item = (Id, impl IntoIterator<Item = (Rk, AccessKind)>)>,
        top_level_prioritization_fn: Pfn,
    ) -> Vec<Vec<Id>> {
        // Insert all transactions into the graph.
        let mut graph = PrioGraph::new(top_level_prioritization_fn);
        for (id, tx) in iter.into_iter() {
            graph.insert_transaction(id, tx);
        }

        graph.make_natural_batches()
    }

    /// Create a new priority graph.
    pub fn new(top_level_prioritization_fn: Pfn) -> Self {
        Self {
            locks: AHashMap::new(),
            nodes: AHashMap::new(),
            main_queue: BinaryHeap::new(),
            top_level_prioritization_fn,
        }
    }

    /// Clear the graph.
    pub fn clear(&mut self) {
        self.main_queue.clear();
        self.locks.clear();
        self.nodes.clear();
    }

    /// Make natural batches from the transactions already inserted into the graph.
    /// Drains all transactions from the primary queue into a batch.
    /// Then, for each transaction in the batch, unblock transactions it was blocking.
    /// If any of those transactions are now unblocked, add them to the main queue.
    /// Repeat until the main queue is empty.
    pub fn make_natural_batches(&mut self) -> Vec<Vec<Id>> {
        // Create natural batches by manually popping without unblocking at each level.
        let mut batches = vec![];

        while !self.main_queue.is_empty() {
            let mut batch = Vec::new();
            while let Some(id) = self.pop() {
                batch.push(id);
            }

            for id in &batch {
                self.unblock(id);
            }

            batches.push(batch);
        }

        batches
    }

    /// Insert a transaction into the graph with the given `Id`.
    /// `Transaction`s should be inserted in priority order.
    pub fn insert_transaction(&mut self, id: Id, tx: impl IntoIterator<Item = (Rk, AccessKind)>) {
        let mut node = GraphNode {
            active: true,
            edges: Vec::new(),
            blocked_by_count: 0,
        };

        let mut block_tx = |blocking_id: Id| {
            // If the blocking transaction is the same as the current transaction, do nothing.
            // This indicates the transaction has multiple accesses to the same resource.
            if blocking_id == id {
                return;
            }

            let Some(blocking_tx_node) = self.nodes.get_mut(&blocking_id) else {
                panic!("blocking node must exist");
            };

            // If the node isn't active then we only do chain tracking.
            if blocking_tx_node.active {
                // Add edges to the current node.
                // If it is a unique edge, increment the blocked_by_count for the current node.
                if blocking_tx_node.try_add_edge(id) {
                    node.blocked_by_count += 1;
                }
            }
        };

        for (resource_key, access_kind) in tx.into_iter() {
            match self.locks.entry(resource_key) {
                Entry::Vacant(entry) => {
                    entry.insert(match access_kind {
                        AccessKind::Read => Lock::Read(vec![id], None),
                        AccessKind::Write => Lock::Write(id),
                    });
                }
                Entry::Occupied(mut entry) => match access_kind {
                    AccessKind::Read => {
                        if let Some(blocking_tx) = entry.get_mut().add_read(id) {
                            block_tx(blocking_tx);
                        }
                    }
                    AccessKind::Write => {
                        if let Some(blocking_txs) = entry.get_mut().add_write(id) {
                            for blocking_tx in blocking_txs {
                                block_tx(blocking_tx);
                            }
                        }
                    }
                },
            }
        }

        self.nodes.insert(id, node);

        // If the node is not blocked, add it to the main queue.
        if self.nodes.get(&id).unwrap().blocked_by_count == 0 {
            self.main_queue.push(self.create_top_level_id(id));
        }
    }

    /// Returns true if the main queue is empty.
    pub fn is_empty(&self) -> bool {
        self.main_queue.is_empty()
    }

    /// Combination of `pop` and `unblock`.
    /// Returns None if the queue is empty.
    /// Returns the `Id` of the popped node, and the set of unblocked `Id`s.
    pub fn pop_and_unblock(&mut self) -> Option<(Id, Vec<Id>)> {
        let id = self.pop()?;
        Some((id, self.unblock(&id)))
    }

    /// Pop the highest priority node id from the main queue.
    /// Returns None if the queue is empty.
    pub fn pop(&mut self) -> Option<Id> {
        self.main_queue.pop().map(|top_level_id| top_level_id.id())
    }

    /// This will unblock transactions that were blocked by this transaction.
    /// Returns the set of `Id`s that were unblocked.
    ///
    /// Panics:
    ///     - Node does not exist.
    ///     - If the node.blocked_by_count != 0
    pub fn unblock(&mut self, id: &Id) -> Vec<Id> {
        // If the node is already removed, do nothing.
        let Some(node) = self.nodes.get_mut(id) else {
            panic!("node must exist");
        };
        assert_eq!(node.blocked_by_count, 0, "node must be unblocked");

        node.active = false;
        let edges = core::mem::take(&mut node.edges);

        // Unblock transactions that were blocked by this node.
        for blocked_tx in edges.iter() {
            let blocked_tx_node = self
                .nodes
                .get_mut(blocked_tx)
                .expect("blocked_tx must exist");
            blocked_tx_node.blocked_by_count -= 1;

            if blocked_tx_node.blocked_by_count == 0 {
                self.main_queue.push(self.create_top_level_id(*blocked_tx));
            }
        }

        edges
    }

    /// Returns whether the given `Id` is at the top level of the graph, i.e. not blocked.
    /// If the node does not exist, returns false.
    pub fn is_blocked(&self, id: Id) -> bool {
        self.nodes
            .get(&id)
            .map(|node| node.active && node.blocked_by_count != 0)
            .unwrap_or_default()
    }

    fn create_top_level_id(&self, id: Id) -> Tl {
        (self.top_level_prioritization_fn)(&id, self.nodes.get(&id).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub type TxId = u64;

    pub type Account = u64;

    pub struct Tx {
        read_locked_resources: Vec<Account>,
        write_locked_resources: Vec<Account>,
    }

    impl Tx {
        fn resources(&self) -> impl Iterator<Item = (Account, AccessKind)> + '_ {
            let write_locked_resources = self
                .write_locked_resources
                .iter()
                .cloned()
                .map(|rk| (rk, AccessKind::Write));
            let read_locked_resources = self
                .read_locked_resources
                .iter()
                .cloned()
                .map(|rk| (rk, AccessKind::Read));

            write_locked_resources.chain(read_locked_resources)
        }
    }

    // Take in groups of transactions, where each group is a set of transaction ids,
    // and the read and write locked resources for each transaction.
    fn setup_test(
        transaction_groups: impl IntoIterator<Item = (Vec<TxId>, Vec<Account>, Vec<Account>)>,
    ) -> (AHashMap<TxId, Tx>, Vec<TxId>) {
        let mut transaction_lookup_table = AHashMap::new();
        let mut priority_ordered_ids = vec![];
        for (ids, read_accounts, write_accounts) in transaction_groups {
            for id in &ids {
                priority_ordered_ids.push(*id);
                transaction_lookup_table.insert(
                    *id,
                    Tx {
                        read_locked_resources: read_accounts.clone(),
                        write_locked_resources: write_accounts.clone(),
                    },
                );
            }
        }

        // Sort in reverse priority order - highest priority first.
        priority_ordered_ids.sort_by(|a, b| b.cmp(a));

        (transaction_lookup_table, priority_ordered_ids)
    }

    fn create_lookup_iterator<'a>(
        transaction_lookup_table: &'a AHashMap<TxId, Tx>,
        reverse_priority_order_ids: &'a [TxId],
    ) -> impl Iterator<Item = (TxId, impl IntoIterator<Item = (Account, AccessKind)> + 'a)> + 'a
    {
        reverse_priority_order_ids.iter().map(|id| {
            (
                *id,
                transaction_lookup_table
                    .get(id)
                    .expect("id must exist")
                    .resources(),
            )
        })
    }

    impl TopLevelId<TxId> for TxId {
        fn id(&self) -> TxId {
            *self
        }
    }

    fn test_top_level_priority_fn(id: &TxId, _node: &GraphNode<TxId>) -> TxId {
        *id
    }

    #[test]
    fn test_simple_queue() {
        // Setup:
        // 3 -> 2 -> 1
        // batches: [3], [2], [1]
        let (transaction_lookup_table, transaction_queue) =
            setup_test([(vec![3, 2, 1], vec![], vec![0])]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [[3], [2], [1]]);
    }

    #[test]
    fn test_multiple_separate_queues() {
        // Setup:
        // 8 -> 4 -> 2 -> 1
        // 7 -> 5 -> 3
        // 6
        // batches: [8, 7, 6], [4, 5], [2, 3], [1]
        let (transaction_lookup_table, transaction_queue) = setup_test([
            (vec![8, 4, 2, 1], vec![], vec![0]),
            (vec![7, 5, 3], vec![], vec![1]),
            (vec![6], vec![], vec![2]),
        ]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [vec![8, 7, 6], vec![5, 4], vec![3, 2], vec![1]]);
    }

    #[test]
    fn test_joining_queues() {
        // Setup:
        // 6 -> 3
        //        \
        //          -> 2 -> 1
        //        /
        // 5 -> 4
        // batches: [6, 5], [3, 4], [2], [1]
        let (transaction_lookup_table, transaction_queue) = setup_test([
            (vec![6, 3], vec![], vec![0]),
            (vec![5, 4], vec![], vec![1]),
            (vec![2, 1], vec![], vec![0, 1]),
        ]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [vec![6, 5], vec![4, 3], vec![2], vec![1]]);
    }

    #[test]
    fn test_forking_queues() {
        // Setup:
        //         -> 2 -> 1
        //        /
        // 6 -> 5
        //        \
        //         -> 4 -> 3
        // batches: [6], [5], [4, 2], [3, 1]
        let (transaction_lookup_table, transaction_queue) = setup_test([
            (vec![6, 5], vec![], vec![0, 1]),
            (vec![2, 1], vec![], vec![0]),
            (vec![4, 3], vec![], vec![1]),
        ]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [vec![6], vec![5], vec![4, 2], vec![3, 1]]);
    }

    #[test]
    fn test_forking_and_joining() {
        // Setup:
        //         -> 5 ----          -> 2 -> 1
        //        /          \      /
        // 9 -> 8              -> 4
        //        \          /      \
        //         -> 7 -> 6          -> 3
        // batches: [9], [8], [7, 5], [6], [4], [3, 2], [1]
        let (transaction_lookup_table, transaction_queue) = setup_test([
            (vec![5, 2, 1], vec![], vec![0]),
            (vec![9, 8, 4], vec![], vec![0, 1]),
            (vec![7, 6, 3], vec![], vec![1]),
        ]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(
            batches,
            [
                vec![9],
                vec![8],
                vec![7, 5],
                vec![6],
                vec![4],
                vec![3, 2],
                vec![1]
            ]
        );
    }

    #[test]
    fn test_shared_read_account_no_conflicts() {
        // Setup:
        //   - all transactions read-lock account 0.
        // 8 -> 6 -> 4 -> 2
        // 7 -> 5 -> 3 -> 1
        // Batches: [8, 7], [6, 5], [4, 3], [2, 1]
        let (transaction_lookup_table, transaction_queue) = setup_test([
            (vec![8, 6, 4, 2], vec![0], vec![1]),
            (vec![7, 5, 3, 1], vec![0], vec![2]),
        ]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [vec![8, 7], vec![6, 5], vec![4, 3], vec![2, 1]]);
    }

    #[test]
    fn test_self_conflicting() {
        // Setup:
        //   - transaction read and write locks account 0.
        // 1
        // Batches: [1]
        let (transaction_lookup_table, transaction_queue) =
            setup_test([(vec![1], vec![0], vec![0])]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [vec![1]]);
    }

    #[test]
    fn test_self_conflicting_write_priority() {
        // Setup:
        //   - transaction 2 read and write locks account 0.
        // 2 --> 1
        // Batches: [2, 1]
        let (transaction_lookup_table, transaction_queue) =
            setup_test([(vec![2], vec![0], vec![0]), (vec![1], vec![0], vec![])]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [vec![2], vec![1]]);
    }

    #[test]
    fn test_write_read_read_conflict() {
        // Setup:
        //  - W --> R
        //      \
        //       -> R
        // - all transactions using same account 0.
        // Batches: [3], [2, 1]
        let (transaction_lookup_table, transaction_queue) =
            setup_test([(vec![3], vec![], vec![0]), (vec![2, 1], vec![0], vec![])]);
        let batches = PrioGraph::natural_batches(
            create_lookup_iterator(&transaction_lookup_table, &transaction_queue),
            test_top_level_priority_fn,
        );
        assert_eq!(batches, [vec![3], vec![2, 1]]);
    }
}
