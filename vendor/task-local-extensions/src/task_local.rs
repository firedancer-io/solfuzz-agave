// clippy bug wrongly flags the task_local macro as being bad.
// a fix is already merged but hasn't made it upstream yet
#![allow(clippy::declare_interior_mutable_const)]

use crate::Extensions;
use std::cell::RefCell;
use std::future::Future;

thread_local! {
    static EXTENSIONS: RefCell<Extensions> = RefCell::new(Extensions::new());
}

/// Sets a task local to `Extensions` before `fut` is run,
/// and fetches the contents of the task local Extensions after completion
/// and returns it.
pub async fn with_extensions<T>(
    mut extensions: Extensions,
    fut: impl Future<Output = T>,
) -> (Extensions, T) {
    pin_utils::pin_mut!(fut);
    let res = std::future::poll_fn(|cx| {
        EXTENSIONS.with(|ext| {
            // swap in the extensions
            std::mem::swap(&mut extensions, &mut *ext.borrow_mut());

            let res = fut.as_mut().poll(cx);

            // swap back
            std::mem::swap(&mut extensions, &mut *ext.borrow_mut());

            res
        })
    })
    .await;

    (extensions, res)
}

/// Retrieve any item from task-local storage.
// TODO: doesn't need to be async?
pub async fn get_local_item<T: Send + Sync + Clone + 'static>() -> Option<T> {
    EXTENSIONS
        .try_with(|e| e.borrow().get::<T>().cloned())
        .ok()
        .flatten()
}

/// Set an item in task-local storage.
// TODO: doesn't need to be async?
pub async fn set_local_item<T: Send + Sync + 'static>(item: T) {
    EXTENSIONS
        .try_with(|e| e.borrow_mut().insert(item))
        .expect("Failed to set local item.");
}

#[cfg(test)]
mod tests {
    use crate::{get_local_item, set_local_item, with_extensions, Extensions};

    #[derive(Clone)]
    struct A;
    #[derive(Clone)]
    struct B;

    #[derive(Clone)]
    struct C;

    #[tokio::test]
    async fn works() {
        let mut a = Extensions::new();
        a.insert(A);

        let (a, _) = with_extensions(a, async {
            let mut b = Extensions::new();
            b.insert(B);

            let (b, _) = with_extensions(b, async {
                assert!(get_local_item::<A>().await.is_none());
                assert!(get_local_item::<B>().await.is_some());
                set_local_item(C).await;
            })
            .await;

            // returned extension is correct
            assert!(b.get::<B>().is_some());
            assert!(b.get::<C>().is_some());

            assert!(get_local_item::<A>().await.is_some());
            assert!(get_local_item::<B>().await.is_none());
            assert!(get_local_item::<C>().await.is_none());
        })
        .await;

        // returned extension is correct
        assert!(a.get::<A>().is_some());
    }
}
