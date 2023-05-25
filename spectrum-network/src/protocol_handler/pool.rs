use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_std::channel::Sender;
use async_std::future::{timeout, TimeoutError};
use futures::stream::FuturesOrdered;
use futures::{FutureExt, Stream};
use log::warn;

/// Tasks talk to protocol behaviour.
pub enum FromTask<TIn, TOut> {
    /// Inject the input into protocol behaviour.
    ToBehaviour(TIn),
    /// Instructs protocol behaviour to emit the event.
    ToHandler(TOut),
}

pub struct TaskPool<TIn, TOut, TErr> {
    /// Name of the pool.
    name: String,
    /// Timeout for each task.
    timeout: Duration,
    /// Communication channel with parental behaviour.
    channel: Sender<FromTask<TIn, TOut>>,
    tasks: FuturesOrdered<
        Pin<Box<dyn Future<Output = Result<Result<(), TErr>, TimeoutError>> + Send + 'static>>,
    >,
}

impl<TIn, TOut, TErr> TaskPool<TIn, TOut, TErr> {
    pub fn spawn<F, R>(&mut self, task: F)
    where
        F: FnOnce(Sender<FromTask<TIn, TOut>>) -> R,
        R: Future<Output = Result<(), TErr>> + Send + 'static,
        TErr: 'static,
    {
        self.tasks
            .push_back(timeout(self.timeout, task(self.channel.clone())).boxed())
    }
}

impl<TIn, TOut, TErr> Stream for TaskPool<TIn, TOut, TErr> {
    type Item = Result<(), TErr>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<(), TErr>>> {
        loop {
            match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
                Poll::Ready(Some(Ok(res))) => {
                    return Poll::Ready(Some(res));
                }
                Poll::Ready(Some(Err(_timeout))) => {
                    warn!("[{}] Operation timeout", self.name);
                    continue;
                }
                Poll::Pending => {}
                Poll::Ready(None) => return Poll::Ready(None),
            }
            return Poll::Pending;
        }
    }
}
