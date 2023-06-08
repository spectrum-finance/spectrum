use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::oneshot;
use futures::channel::oneshot::{Receiver, Sender};
use pin_project::pin_project;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Cancelled;

/// Converts a future to a future which can be cancelled.
pub fn cancellable<F, T>(future: F) -> (impl Future<Output = Result<T, Cancelled>>, CancelToken)
where
    F: Future<Output = T>,
{
    let (snd, recv) = oneshot::channel();
    (CancellableFuture { future, signal: recv }, CancelToken(snd))
}

pub struct CancelToken(Sender<()>);

impl CancelToken {
    /// Cancel the future.
    pub fn cancel(self) -> bool {
        self.0.send(()).is_ok()
    }
}

#[pin_project]
pub struct CancellableFuture<F> {
    #[pin]
    future: F,
    #[pin]
    signal: Receiver<()>,
}

impl<F: Future> Future for CancellableFuture<F> {
    type Output = Result<F::Output, Cancelled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            Poll::Ready(v) => Poll::Ready(Ok(v)),
            Poll::Pending => match this.signal.poll(cx) {
                Poll::Ready(_) => Poll::Ready(Err(Cancelled {})),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use async_std::future::pending;
    use async_std::task;

    use crate::cancellable::{cancellable, Cancelled};

    #[async_std::test]
    async fn can_be_cancelled() {
        let (cancellable_fut, token) = cancellable(pending::<()>());
        let handle = task::spawn(cancellable_fut);
        assert!(token.cancel());
        assert_eq!(handle.await, Err(Cancelled))
    }
}
