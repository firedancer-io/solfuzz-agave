//! Definition of the ListIndex type
//! 
use std::{convert::TryFrom, default::Default, fmt, num::NonZeroU32};

/// Vector index for the elements in the list. They are typically not
/// squential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct ListIndex {
    ndx: Option<NonZeroU32>
}

impl ListIndex {
    #[inline]
    pub fn new() -> ListIndex {
        Default::default()
    }
    #[inline]
    /// Returns `true` for a valid index.
    ///
    /// A valid index can be used in IndexList method calls.
    pub fn is_some(&self) -> bool {
        self.ndx.is_some()
    }
    #[inline]
    /// Returns `true` for an invalid index.
    ///
    /// An invalid index will always be ignored and have `None` returned from
    /// any IndexList method call that returns something.
    pub fn is_none(&self) -> bool {
        self.ndx.is_none()
    }
    #[inline]
    pub(crate) fn get(&self) -> Option<usize> {
        Some(self.ndx?.get() as usize - 1)
    }
    #[inline]
    pub(crate) fn set(mut self, index: Option<usize>) -> Self {
        if let Some(n) = index {
            self.ndx = NonZeroU32::try_from(n as u32 + 1).ok()
        }
        self
    }
}

impl From<u32> for ListIndex {
    fn from(index: u32) -> ListIndex {
        ListIndex::new().set(Some(index as usize))
    }
}

impl From<u64> for ListIndex {
    fn from(index: u64) -> ListIndex {
        ListIndex::new().set(Some(index as usize))
    }
}

impl From<usize> for ListIndex {
    fn from(index: usize) -> ListIndex {
        ListIndex::new().set(Some(index))
    }
}

impl From<Option<usize>> for ListIndex {
    fn from(index: Option<usize>) -> ListIndex {
        ListIndex::new().set(index)
    }
}

impl fmt::Display for ListIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ndx) = self.ndx {
            write!(f, "{}", ndx)
        } else {
            write!(f, "|")
        }
    }
}
