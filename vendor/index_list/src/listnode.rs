/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! The difinition of the ListNode type
//!
use std::{default::Default, fmt, mem};
use crate::listindex::ListIndex;

#[derive(Clone, Debug, Default)]
pub struct ListNode {
    pub(crate) next: ListIndex,
    pub(crate) prev: ListIndex,
}

impl ListNode {
    #[inline]
    pub fn new() -> ListNode {
        Default::default()
    }
    #[inline]
    pub fn new_next(&mut self, next: ListIndex) -> ListIndex {
        mem::replace(&mut self.next, next)
    }
    #[inline]
    pub fn new_prev(&mut self, prev: ListIndex) -> ListIndex {
        mem::replace(&mut self.prev, prev)
    }
}

impl fmt::Display for ListNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}<>{}", self.next, self.prev)
    }
}
