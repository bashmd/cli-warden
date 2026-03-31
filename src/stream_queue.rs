use std::sync::Arc;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};

pub const DEFAULT_CHUNK_BYTES: usize = 8 * 1024;
pub const DEFAULT_PACKET_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_MAX_UNCONFIRMED_BYTES: usize = 128 * 1024;

pub struct QueuedItem<T> {
    pub item: T,
    _permit: Option<OwnedSemaphorePermit>,
}

impl<T> QueuedItem<T> {
    pub fn unbounded(item: T) -> Self {
        Self {
            item,
            _permit: None,
        }
    }

    pub fn with_permit(item: T, permit: OwnedSemaphorePermit) -> Self {
        Self {
            item,
            _permit: Some(permit),
        }
    }
}

pub fn into_stream<T>(rx: mpsc::Receiver<QueuedItem<T>>) -> impl Stream<Item = T> {
    ReceiverStream::new(rx).map(|queued| queued.item)
}

pub async fn send_unbounded<T>(tx: &mpsc::Sender<QueuedItem<T>>, item: T) -> Result<(), String> {
    tx.send(QueuedItem::unbounded(item))
        .await
        .map_err(|_| "stream receiver closed".to_string())
}

pub async fn send_metered<T>(
    tx: &mpsc::Sender<QueuedItem<T>>,
    byte_budget: &Arc<Semaphore>,
    item: T,
    bytes: usize,
) -> Result<(), String> {
    let permit = byte_budget
        .clone()
        .acquire_many_owned(bytes as u32)
        .await
        .map_err(|_| "byte budget closed".to_string())?;

    tx.send(QueuedItem::with_permit(item, permit))
        .await
        .map_err(|_| "stream receiver closed".to_string())
}
