use std::fmt;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size (1 KB) to prevent memory exhaustion attacks.
///
/// Real MinerMessage payloads are only a few hundred bytes (Ready, NewJob, JobResult).
/// 1 KB provides sufficient headroom while minimizing the amplification attack surface.
pub const MAX_MESSAGE_SIZE: u32 = 1024;

/// Conservative max auth token length so a `Ready { token }` JSON frame still fits
/// under [`MAX_MESSAGE_SIZE`]. Larger operator-supplied tokens would make every
/// miner fail with an opaque framing/deserialize error.
pub const MAX_AUTH_TOKEN_LEN: usize = 512;

/// Status codes returned in API responses.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiResponseStatus {
	Accepted,
	Running,
	Completed,
	Failed,
	Cancelled,
	NotFound,
	Error,
}

/// QUIC protocol messages exchanged between node and miner.
///
/// The protocol is:
/// - Miner sends `Ready { token }` immediately after connecting to establish the stream and
///   authenticate (token must match the node's miner auth token)
/// - Node sends `NewJob` to submit a mining job (implicitly cancels any previous job)
/// - Miner sends `JobResult` when mining completes
#[derive(Serialize, Deserialize, Clone)]
pub enum MinerMessage {
	/// Miner → Node: Sent immediately after connecting to establish the stream
	/// and authenticate. This is required because QUIC streams are lazily initialized.
	Ready {
		/// Shared secret that must match the node's miner auth token.
		token: String,
	},

	/// Node → Miner: Submit a new mining job.
	/// If a job is already running, it will be cancelled and replaced.
	NewJob(MiningRequest),

	/// Miner → Node: Mining result (completed, failed, or cancelled).
	JobResult(MiningResult),
}

impl fmt::Debug for MinerMessage {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Ready { .. } => f.write_str("Ready { token: \"[REDACTED]\" }"),
			Self::NewJob(req) => f.debug_tuple("NewJob").field(req).finish(),
			Self::JobResult(res) => f.debug_tuple("JobResult").field(res).finish(),
		}
	}
}

/// Write a length-prefixed JSON message to an async writer.
///
/// Wire format: 4-byte big-endian length prefix followed by JSON payload.
pub async fn write_message<W: AsyncWrite + Unpin>(
	writer: &mut W,
	msg: &MinerMessage,
) -> std::io::Result<()> {
	let json = serde_json::to_vec(msg)
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
	let len = json.len() as u32;
	writer.write_all(&len.to_be_bytes()).await?;
	writer.write_all(&json).await?;
	Ok(())
}

/// Read a length-prefixed JSON message from an async reader.
///
/// Wire format: 4-byte big-endian length prefix followed by JSON payload.
/// Returns an error if the message exceeds MAX_MESSAGE_SIZE.
///
/// This function is not cancellation safe: dropping its future may discard bytes
/// already consumed from the reader. In a `select!` loop, retain a
/// [`MinerMessageReader`] and call its `read_message` method instead.
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<MinerMessage> {
	MinerMessageReader::new(reader).read_message().await
}

/// A cancellation-safe reader for length-prefixed JSON miner messages.
///
/// Keep this value outside a `select!` loop. Partial length prefixes and payloads
/// belong to the reader, so dropping a pending [`Self::read_message`] future does
/// not discard bytes. Dropping the reader itself still discards that state.
pub struct MinerMessageReader<R> {
	reader: R,
	length: [u8; 4],
	length_read: usize,
	payload: Vec<u8>,
	payload_read: usize,
}

impl<R: AsyncRead + Unpin> MinerMessageReader<R> {
	/// Wrap an async byte stream, beginning at a message boundary.
	pub fn new(reader: R) -> Self {
		Self { reader, length: [0; 4], length_read: 0, payload: Vec::new(), payload_read: 0 }
	}

	/// Read the next message, resuming any interrupted prefix or payload.
	///
	/// Cancellation is safe while this reader is retained. Oversized messages are
	/// rejected before allocating or reading their payload; a truncated stream
	/// returns [`std::io::ErrorKind::UnexpectedEof`].
	pub async fn read_message(&mut self) -> std::io::Result<MinerMessage> {
		while self.length_read < self.length.len() {
			let count = self.reader.read(&mut self.length[self.length_read..]).await?;
			if count == 0 {
				return Err(std::io::ErrorKind::UnexpectedEof.into());
			}
			self.length_read += count;
		}
		let length = u32::from_be_bytes(self.length);
		if length > MAX_MESSAGE_SIZE {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("Message size {} exceeds maximum {}", length, MAX_MESSAGE_SIZE),
			));
		}

		self.payload.resize(length as usize, 0);
		while self.payload_read < self.payload.len() {
			let count = self.reader.read(&mut self.payload[self.payload_read..]).await?;
			if count == 0 {
				return Err(std::io::ErrorKind::UnexpectedEof.into());
			}
			self.payload_read += count;
		}

		let message = serde_json::from_slice(&self.payload)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
		self.length_read = 0;
		self.payload_read = 0;
		self.payload.clear();
		message
	}
}

/// Request payload sent from Node to Miner.
///
/// The miner will choose its own random starting nonce, enabling multiple
/// miners to work on the same job without coordination.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MiningRequest {
	pub job_id: String,
	/// Hex encoded header hash (32 bytes -> 64 chars, no 0x prefix)
	pub mining_hash: String,
	/// Difficulty (U512 as decimal string). Must be non-zero.
	pub difficulty: String,
}

/// Response payload for job submission (`/mine`) and cancellation (`/cancel`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MiningResponse {
	pub status: ApiResponseStatus,
	pub job_id: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub message: Option<String>,
}

/// Response payload for checking job results (`/result/{job_id}`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MiningResult {
	pub status: ApiResponseStatus,
	pub job_id: String,
	/// Hex encoded U512 representation of the final/winning nonce (no 0x prefix).
	pub nonce: Option<String>,
	/// Hex encoded [u8; 64] representation of the winning nonce (128 chars, no 0x prefix).
	/// This is the primary field the Node uses for verification.
	pub work: Option<String>,
	pub hash_count: u64,
	pub elapsed_time: f64,
	/// Miner ID assigned by the node (set server-side, not by the miner).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub miner_id: Option<u64>,
}
