/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! The definition of the ListDrainIter type
use std::iter::{DoubleEndedIterator, FusedIterator};
use crate::{listiter::ListIter, IndexList};

/// A consuming interator that will remove elements from the list as it is
/// iterating over them. The iterator is fused and can also be reversed.
pub struct ListDrainIter<'a, T>(&'a mut IndexList<T>);

impl<'a, T> ListDrainIter<'a, T> {
    pub fn new(list: &'a mut IndexList<T>) -> Self {
        ListDrainIter::<'a, T>(list)
    }
}

impl<T> Iterator for ListDrainIter<'_, T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.remove_first()
    }
}

impl<T> DoubleEndedIterator for ListDrainIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.remove_last()
    }
}

impl<T> FusedIterator for ListDrainIter<'_, T> {}

impl<'a, T> IntoIterator for &'a IndexList<T> {
    type Item = &'a T;
    type IntoIter = ListIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
