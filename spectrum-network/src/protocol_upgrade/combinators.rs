use futures::prelude::*;
use libp2p::core::upgrade::{InboundUpgrade, ProtocolName, UpgradeInfo};
use std::{
    iter::FromIterator,
    pin::Pin,
    task::{Context, Poll},
    vec,
};

/// Upgrade that combines multiple upgrades of the same type into one. Supports all the protocols
/// supported by either sub-upgrade.
#[derive(Debug, Clone)]
pub struct AnyUpgradeOf<T>(pub Vec<T>);

impl<T> From<Vec<T>> for AnyUpgradeOf<T> {
    fn from(list: Vec<T>) -> Self {
        Self(list)
    }
}

impl<T> FromIterator<T> for AnyUpgradeOf<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T: UpgradeInfo> UpgradeInfo for AnyUpgradeOf<T> {
    type Info = ProtoNameWithUsize<T::Info>;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.0
            .iter()
            .enumerate()
            .flat_map(|(n, p)| {
                p.protocol_info()
                    .into_iter()
                    .map(move |i| ProtoNameWithUsize(i, n))
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl<T, C> InboundUpgrade<C> for AnyUpgradeOf<T>
where
    T: InboundUpgrade<C>,
{
    type Output = (T::Output, usize);
    type Error = (T::Error, usize);
    type Future = FutWithUsize<T::Future>;

    fn upgrade_inbound(mut self, sock: C, info: Self::Info) -> Self::Future {
        let fut = self.0.remove(info.1).upgrade_inbound(sock, info.0);
        FutWithUsize(fut, info.1)
    }
}

/// Groups a `ProtocolName` with a `usize`.
#[derive(Debug, Clone)]
pub struct ProtoNameWithUsize<T>(T, usize);

impl<T: ProtocolName> ProtocolName for ProtoNameWithUsize<T> {
    fn protocol_name(&self) -> &[u8] {
        self.0.protocol_name()
    }
}

/// Equivalent to `fut.map_ok(|v| (v, num)).map_err(|e| (e, num))`, where `fut` and `num` are
/// the two fields of this struct.
#[pin_project::pin_project]
pub struct FutWithUsize<T>(#[pin] T, usize);

impl<T: Future<Output = Result<O, E>>, O, E> Future for FutWithUsize<T> {
    type Output = Result<(O, usize), (E, usize)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.project();
        match Future::poll(this.0, cx) {
            Poll::Ready(Ok(v)) => Poll::Ready(Ok((v, *this.1))),
            Poll::Ready(Err(e)) => Poll::Ready(Err((e, *this.1))),
            Poll::Pending => Poll::Pending,
        }
    }
}
