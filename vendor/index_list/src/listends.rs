/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! The defenition of the ListEnds type
//!
use std::{default::Default, fmt, mem};
use crate::listindex::ListIndex;

#[derive(Clone, Debug, Default)]
pub struct ListEnds {
    pub(crate) head: ListIndex,
    pub(crate) tail: ListIndex,
}

impl ListEnds {
    #[allow(dead_code)]
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }
    #[inline]
    pub fn clear(&mut self) {
        self.new_both(ListIndex::new());
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }
    #[inline]
    pub fn new_head(&mut self, head: ListIndex) -> ListIndex {
        mem::replace(&mut self.head, head)
    }
    #[inline]
    pub fn new_tail(&mut self, tail: ListIndex) -> ListIndex {
        mem::replace(&mut self.tail, tail)
    }
    #[inline]
    pub fn new_both(&mut self, both: ListIndex) {
        self.head = both;
        self.tail = both;
    }
}

impl fmt::Display for ListEnds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}>=<{}", self.head, self.tail)
    }
}
