//! Keep queued local clients reachable when a restored reactor misses readiness.
use std::future::Future;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener as DirectListener;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::time::{Instant, Interval, MissedTickBehavior};

const FALLBACK_INTERVAL: Duration = Duration::from_secs(1);

pub(super) struct Listener {
    asynchronous: Arc<UnixListener>,
    direct: DirectListener,
    retry: Interval,
}

impl Listener {
    pub(super) fn new(asynchronous: impl Into<Arc<UnixListener>>) -> io::Result<Self> {
        let asynchronous = asynchronous.into();
        // Both descriptors address the same accept queue. The duplicate is used
        // only for a direct nonblocking syscall, without reactor readiness state.
        let direct = DirectListener::from(asynchronous.as_ref().as_fd().try_clone_to_owned()?);
        direct.set_nonblocking(true)?;
        let mut retry =
            tokio::time::interval_at(Instant::now() + FALLBACK_INTERVAL, FALLBACK_INTERVAL);
        retry.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Ok(Self {
            asynchronous,
            direct,
            retry,
        })
    }

    pub(super) async fn accept(&mut self) -> io::Result<UnixStream> {
        let primary = async { self.asynchronous.accept().await.map(|(stream, _)| stream) };
        accept_with_fallback(primary, &self.direct, &mut self.retry).await
    }
}

async fn accept_with_fallback(
    primary: impl Future<Output = io::Result<UnixStream>>,
    direct: &DirectListener,
    retry: &mut Interval,
) -> io::Result<UnixStream> {
    tokio::pin!(primary);
    loop {
        tokio::select! {
            biased;
            result = &mut primary => return result,
            _ = retry.tick() => {
                match direct.accept() {
                    Ok((stream, _)) => {
                        // Drain a queued burst without imposing one second per
                        // client. An empty check returns to the ordinary cadence.
                        retry.reset_immediately();
                        stream.set_nonblocking(true)?;
                        return UnixStream::from_std(stream);
                    }
                    Err(error) if matches!(error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream as DirectStream;
    use tokio::io::AsyncReadExt;
    use tokio::time::timeout;

    #[tokio::test]
    async fn shared_listener_preserves_payload_and_peer_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.sock");
        let shared = Arc::new(UnixListener::bind(&path).unwrap());
        let mut listener = Listener::new(shared.clone()).unwrap();
        let mut client = DirectStream::connect(&path).unwrap();
        client.write_all(b"shared").unwrap();
        let mut accepted = timeout(Duration::from_millis(500), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = [0; 6];
        accepted.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"shared");
        assert_eq!(
            accepted.peer_cred().unwrap().uid(),
            super::super::owner_uid()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn queued_clients_survive_missing_readiness_and_cancelled_accept() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.sock");
        let direct = DirectListener::bind(&path).unwrap();
        direct.set_nonblocking(true).unwrap();
        let mut retry =
            tokio::time::interval_at(Instant::now() + FALLBACK_INTERVAL, FALLBACK_INTERVAL);
        retry.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Model a reactor whose accept notification never arrives. Empty polls
        // must remain pending, and cancelling that wait must not lose a client.
        assert!(timeout(
            Duration::from_millis(500),
            accept_with_fallback(std::future::pending(), &direct, &mut retry,)
        )
        .await
        .is_err());
        let mut client = DirectStream::connect(&path).unwrap();
        client.write_all(b"queued request").unwrap();
        let mut second_client = DirectStream::connect(&path).unwrap();
        second_client.write_all(b"second").unwrap();
        let mut accepted = timeout(
            FALLBACK_INTERVAL,
            accept_with_fallback(std::future::pending(), &direct, &mut retry),
        )
        .await
        .unwrap()
        .unwrap();
        let mut bytes = [0; 14];
        accepted.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"queued request");
        assert_eq!(
            accepted.peer_cred().unwrap().uid(),
            super::super::owner_uid()
        );
        let drained_at = Instant::now();
        let mut second = timeout(
            Duration::from_millis(1),
            accept_with_fallback(std::future::pending(), &direct, &mut retry),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(Instant::now(), drained_at);
        let mut bytes = [0; 6];
        second.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"second");
        assert_eq!(
            direct.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
