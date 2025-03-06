use crate::TransactionId;

/// A read-lock can be held by multiple transactions, and
/// subsequent write-locks should be blocked by all of them.
/// Write-locks are exclusive.
pub(crate) enum Lock<Id: TransactionId> {
    Read(Vec<Id>, Option<Id>), // (Current Reads, Most Recent Write)
    Write(Id),
}

impl<Id: TransactionId> Lock<Id> {
    /// Take read-lock on a resource.
    /// Returns the id of the write transaction that is blocking the added read.
    pub fn add_read(&mut self, id: Id) -> Option<Id> {
        match self {
            Lock::Read(ids, maybe_write) => {
                ids.push(id);
                *maybe_write
            }
            Lock::Write(current_write_id) => {
                // If the current write is the same as the one we're adding,
                // do not overwrite the write-lock.
                let current_write_id = *current_write_id;
                if current_write_id == id {
                    return None;
                }
                let Lock::Write(id) =
                    core::mem::replace(self, Lock::Read(vec![id], Some(current_write_id)))
                else {
                    unreachable!("LockKind::Write is guaranteed by match");
                };
                Some(id)
            }
        }
    }

    /// Take write-lock on a resource.
    /// Returns the ids of transactions blocking the added write.
    pub fn add_write(&mut self, id: Id) -> Option<Vec<Id>> {
        match core::mem::replace(self, Lock::Write(id)) {
            Lock::Read(ids, _) => Some(ids),
            Lock::Write(current_write_id) => {
                if current_write_id == id {
                    None
                } else {
                    Some(vec![current_write_id])
                }
            }
        }
    }
}
