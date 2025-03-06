/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! The defintions of the ListIter type
use std::iter::{DoubleEndedIterator, FusedIterator};
use crate::{listindex::ListIndex, IndexList};

/// A double-ended iterator over all the elements in the list. It is fused and
/// can be reversed.
pub struct ListIter<'a, T> {
    pub(crate) list: &'a IndexList<T>,
    pub(crate) next: ListIndex,
    pub(crate) prev: ListIndex,
}

impl<'a, T> Iterator for ListIter<'a, T> {
    type Item = &'a T;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.list.get(self.next);
        self.next = self.list.next_index(self.next);
        item
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let my_len = self.list.len();
        (my_len, Some(my_len))
    }
}
impl<T> FusedIterator for ListIter<'_, T> {}

impl<T> DoubleEndedIterator for ListIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let item = self.list.get(self.prev);
        self.prev = self.list.prev_index(self.prev);
        item
    }
}
