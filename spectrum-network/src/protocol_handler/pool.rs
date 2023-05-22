use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::FuturesOrdered;
use futures::{FutureExt, Stream};

pub struct TaskPool<TOut, TErr> {
    tasks: FuturesOrdered<Pin<Box<dyn Future<Output = Result<TOut, TErr>> + Send + 'static>>>,
}

impl<TOut, TErr> TaskPool<TOut, TErr> {
    pub fn spawn(&mut self, task: impl Future<Output = Result<TOut, TErr>> + Send + 'static) {
        self.tasks.push_back(task.boxed())
    }
}

impl<TOut, TErr> Stream for TaskPool<TOut, TErr> {
    type Item = Result<TOut, TErr>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<TOut, TErr>>> {
        loop {
            match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
                Poll::Ready(Some(res)) => {
                    return Poll::Ready(Some(res));
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }
        Poll::Pending
    }
}
