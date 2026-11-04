use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const MAGIC: u32 = u32::MAX;
pub(crate) const CELL_BYTES: usize = 4096;
const HEADER_BYTES: usize = 17;
const DATA_BYTES: usize = CELL_BYTES - HEADER_BYTES;
pub(crate) const PERIOD: Duration = Duration::from_secs(1);
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const MAX_PEERS: usize = 4;

pub(crate) struct Job {
    pub payload: Vec<u8>,
    pub deadline: Instant,
    pub reply: std::sync::mpsc::SyncSender<()>,
}

pub(crate) struct Connection {
    pub queue: tokio::sync::mpsc::Sender<Job>,
    pub task: tokio::task::JoinHandle<()>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid shaped stream record")
}

fn data_cell(sequence: u64, payload: &[u8], offset: usize) -> ([u8; CELL_BYTES], usize) {
    let mut cell = [0u8; CELL_BYTES];
    cell[0] = 1;
    cell[1..9].copy_from_slice(&sequence.to_le_bytes());
    cell[9..13].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    cell[13..17].copy_from_slice(&(offset as u32).to_le_bytes());
    let count = DATA_BYTES.min(payload.len() - offset);
    cell[HEADER_BYTES..HEADER_BYTES + count].copy_from_slice(&payload[offset..offset + count]);
    (cell, offset + count)
}

#[derive(Default)]
struct Assembler {
    payload: Vec<u8>,
    total: usize,
    last_sequence: u64,
}

impl Assembler {
    fn push(&mut self, cell: &[u8; CELL_BYTES]) -> io::Result<Option<(u64, Vec<u8>)>> {
        if cell[0] == 0 {
            return Ok(None);
        }
        if cell[0] != 1 {
            return Err(invalid());
        }
        let sequence = u64::from_le_bytes(cell[1..9].try_into().unwrap());
        let total = u32::from_le_bytes(cell[9..13].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(cell[13..17].try_into().unwrap()) as usize;
        if total == 0
            || total > crate::arti::MAX_INBOUND_PAYLOAD_BYTES
            || sequence != self.last_sequence.checked_add(1).ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        if offset != self.payload.len() || (offset != 0 && total != self.total) || offset >= total {
            return Err(invalid());
        }
        self.total = total;
        let count = DATA_BYTES.min(total - offset);
        self.payload
            .extend_from_slice(&cell[HEADER_BYTES..HEADER_BYTES + count]);
        if self.payload.len() == total {
            self.last_sequence = sequence;
            Ok(Some((sequence, std::mem::take(&mut self.payload))))
        } else {
            Ok(None)
        }
    }
}

async fn read_cell<Reader: AsyncRead + Unpin>(reader: &mut Reader) -> io::Result<[u8; CELL_BYTES]> {
    let mut cell = [0u8; CELL_BYTES];
    tokio::time::timeout(Duration::from_secs(30), reader.read_exact(&mut cell)).await??;
    Ok(cell)
}

async fn write_cell<Writer: AsyncWrite + Unpin>(
    writer: &mut Writer,
    cell: &[u8; CELL_BYTES],
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        writer.write_all(cell).await?;
        writer.flush().await
    })
    .await?
}

pub(crate) async fn receive<Stream>(
    stream: Stream,
    enabled: Arc<AtomicBool>,
    handler: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    period: Duration,
) -> io::Result<()>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let acknowledgement = AtomicU64::new(0);
    let read = async {
        let mut assembler = Assembler::default();
        loop {
            let cell = read_cell(&mut reader).await?;
            if let Some((sequence, payload)) = assembler.push(&cell)? {
                acknowledgement.store(sequence, Ordering::SeqCst);
                let handler = handler.clone();
                tokio::task::spawn_blocking(move || handler(payload))
                    .await
                    .map_err(io::Error::other)?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let write = async {
        let mut timer = tokio::time::interval(period);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            if !enabled.load(Ordering::SeqCst) {
                return Err(io::Error::other("traffic shaping disabled"));
            }
            let mut cell = [0u8; CELL_BYTES];
            let sequence = acknowledgement.swap(0, Ordering::SeqCst);
            if sequence != 0 {
                cell[0] = 2;
                cell[1..9].copy_from_slice(&sequence.to_le_bytes());
            }
            write_cell(&mut writer, &cell).await?;
        }
    };
    futures::try_join!(read, write).map(|_: ((), ())| ())
}

pub(crate) async fn send<Stream>(
    stream: Stream,
    jobs: &mut tokio::sync::mpsc::Receiver<Job>,
    period: Duration,
) -> io::Result<()>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (receipts, mut receipt_rx) = tokio::sync::mpsc::channel(1);
    let read = async {
        loop {
            let cell = read_cell(&mut reader).await?;
            match cell[0] {
                0 => {}
                2 => receipts
                    .try_send(u64::from_le_bytes(cell[1..9].try_into().unwrap()))
                    .map_err(|_| invalid())?,
                _ => return Err(invalid()),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let write = async {
        writer.write_all(&MAGIC.to_le_bytes()).await?;
        writer.flush().await?;
        let mut timer = tokio::time::interval(period);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut pending: Option<Job> = None;
        let mut offset = 0;
        let mut sequence = 0u64;
        loop {
            tokio::select! {
                _ = timer.tick() => {
                    let cell = if let Some(job) = &pending {
                        if Instant::now() >= job.deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, "shaped send expired")); }
                        if offset < job.payload.len() {
                            let (cell, next) = data_cell(sequence, &job.payload, offset);
                            offset = next;
                            cell
                        } else { [0u8; CELL_BYTES] }
                    } else { [0u8; CELL_BYTES] };
                    write_cell(&mut writer, &cell).await?;
                }
                receipt = receipt_rx.recv() => {
                    let receipt = receipt.ok_or_else(invalid)?;
                    let job = pending.take().ok_or_else(invalid)?;
                    if receipt != sequence || offset != job.payload.len() { return Err(invalid()); }
                    let _ = job.reply.send(());
                }
                job = jobs.recv(), if pending.is_none() => {
                    let job = job.ok_or_else(|| io::Error::other("shaped stream closed"))?;
                    if Instant::now() >= job.deadline { continue; }
                    sequence = sequence.checked_add(1).ok_or_else(invalid)?;
                    offset = 0;
                    pending = Some(job);
                }
            }
        }
    };
    futures::try_join!(read, write).map(|_: ((), ())| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shaped_records_reassemble_and_reject_invalid_sequences_and_lengths() {
        let payload = vec![42; crate::arti::MAX_INBOUND_PAYLOAD_BYTES];
        let mut assembler = Assembler::default();
        let mut offset = 0;
        while offset < payload.len() {
            assert!(assembler.push(&[0; CELL_BYTES]).unwrap().is_none());
            let (cell, next) = data_cell(1, &payload, offset);
            let result = assembler.push(&cell).unwrap();
            if next == payload.len() {
                assert_eq!(result.unwrap().1, payload);
            }
            offset = next;
        }
        assert!(assembler.push(&data_cell(1, b"replay", 0).0).is_err());
        let mut cell = data_cell(2, b"test", 0).0;
        cell[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(assembler.push(&cell).is_err());
    }

    #[test]
    fn shaped_stream_transfers_payload_and_emits_idle_cover() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (client, mut server) = tokio::io::duplex(CELL_BYTES * 4);
            let (queue, mut jobs) = tokio::sync::mpsc::channel(1);
            let (reply, receipt) = std::sync::mpsc::sync_channel(1);
            let client_task =
                tokio::spawn(
                    async move { send(client, &mut jobs, Duration::from_millis(5)).await },
                );
            assert_eq!(server.read_u32_le().await.unwrap(), MAGIC);
            assert_eq!(read_cell(&mut server).await.unwrap(), [0; CELL_BYTES]);
            assert_eq!(read_cell(&mut server).await.unwrap(), [0; CELL_BYTES]);
            queue
                .send(Job {
                    payload: b"message".to_vec(),
                    deadline: Instant::now() + Duration::from_secs(5),
                    reply,
                })
                .await
                .unwrap();
            let (captured, received) = std::sync::mpsc::sync_channel(1);
            let server_task = tokio::spawn(receive(
                server,
                Arc::new(AtomicBool::new(true)),
                Arc::new(move |payload| {
                    captured.send(payload).unwrap();
                }),
                Duration::from_millis(5),
            ));
            tokio::task::spawn_blocking(move || {
                receipt.recv_timeout(Duration::from_secs(5)).unwrap()
            })
            .await
            .unwrap();
            let payload = tokio::task::spawn_blocking(move || {
                received.recv_timeout(Duration::from_secs(5)).unwrap()
            })
            .await
            .unwrap();
            assert_eq!(payload, b"message");
            server_task.abort();
            client_task.abort();
        });
    }
}
