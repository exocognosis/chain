use quantus_miner_api::{
	read_message, write_message, ApiResponseStatus, MinerMessage, MinerMessageReader,
	MiningRequest, MiningResult, MAX_MESSAGE_SIZE,
};
use tokio::io::{AsyncWriteExt, DuplexStream};

fn result(job_id: &str) -> MinerMessage {
	MinerMessage::JobResult(MiningResult {
		status: ApiResponseStatus::Completed,
		job_id: job_id.to_owned(),
		nonce: None,
		work: Some("ab".repeat(64)),
		hash_count: 42,
		elapsed_time: 0.25,
		miner_id: None,
	})
}

fn frame(message: &MinerMessage) -> Vec<u8> {
	let payload = serde_json::to_vec(message).unwrap();
	let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
	frame.extend(payload);
	frame
}

async fn interrupt_receive(reader: &mut MinerMessageReader<DuplexStream>) {
	tokio::select! {
		biased;
		message = reader.read_message() => panic!("partial frame unexpectedly completed: {message:?}"),
		// Like a ready job-broadcast branch, this wins after the read has consumed
		// the available bytes and returned Pending, dropping the receive future.
		_ = std::future::ready(()) => {}
	}
}

fn assert_message(actual: MinerMessage, expected: &MinerMessage) {
	assert_eq!(serde_json::to_value(actual).unwrap(), serde_json::to_value(expected).unwrap());
}

#[tokio::test]
async fn interrupted_prefix_and_payload_preserve_this_and_the_next_frame() {
	let first = result("first");
	let second = result("second");
	let bytes = frame(&first);
	for split in 1..bytes.len() {
		let (mut writer, receiver) = tokio::io::duplex(4096);
		let mut reader = MinerMessageReader::new(receiver);
		writer.write_all(&bytes[..split]).await.unwrap();
		interrupt_receive(&mut reader).await;
		writer.write_all(&bytes[split..]).await.unwrap();
		write_message(&mut writer, &second).await.unwrap();
		writer.shutdown().await.unwrap();
		let actual = reader.read_message().await.unwrap_or_else(|error| {
			panic!("frame must survive interruption after {split} bytes: {error}")
		});
		assert_message(actual, &first);
		assert_message(reader.read_message().await.unwrap(), &second);
	}
}

#[tokio::test]
async fn repeated_interruptions_preserve_each_byte_of_a_frame() {
	let expected = result("fragmented");
	let bytes = frame(&expected);
	let (mut writer, receiver) = tokio::io::duplex(4096);
	let mut reader = MinerMessageReader::new(receiver);
	for byte in &bytes[..bytes.len() - 1] {
		writer.write_all(&[*byte]).await.unwrap();
		interrupt_receive(&mut reader).await;
	}
	writer.write_all(&bytes[bytes.len() - 1..]).await.unwrap();
	writer.shutdown().await.unwrap();
	assert_message(reader.read_message().await.unwrap(), &expected);
}

#[tokio::test]
async fn oversized_frames_are_rejected_before_reading_a_payload() {
	let (mut writer, receiver) = tokio::io::duplex(4);
	let mut reader = MinerMessageReader::new(receiver);
	writer.write_all(&(MAX_MESSAGE_SIZE + 1).to_be_bytes()).await.unwrap();
	let error = reader.read_message().await.unwrap_err();
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn truncated_prefix_and_payload_report_eof() {
	let bytes = frame(&result("truncated"));
	for length in [0, 2, 4, bytes.len() - 1] {
		let (mut writer, receiver) = tokio::io::duplex(4096);
		let mut reader = MinerMessageReader::new(receiver);
		writer.write_all(&bytes[..length]).await.unwrap();
		writer.shutdown().await.unwrap();
		let error = reader.read_message().await.unwrap_err();
		assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
	}
}

#[tokio::test]
async fn existing_read_helper_preserves_all_message_variants() {
	let messages = [
		MinerMessage::Ready { token: "test-token".to_owned() },
		MinerMessage::NewJob(MiningRequest {
			job_id: "new-job".to_owned(),
			mining_hash: "00".repeat(32),
			difficulty: "1".to_owned(),
		}),
		result("completed-job"),
	];
	let (mut writer, mut receiver) = tokio::io::duplex(4096);
	for message in &messages {
		write_message(&mut writer, message).await.unwrap();
	}
	writer.shutdown().await.unwrap();
	for expected in &messages {
		assert_message(read_message(&mut receiver).await.unwrap(), expected);
	}
}

#[tokio::test]
async fn maximum_size_message_is_accepted() {
	let expected = result("maximum");
	let mut payload = serde_json::to_vec(&expected).unwrap();
	payload.resize(MAX_MESSAGE_SIZE as usize, b' ');
	let (mut writer, receiver) = tokio::io::duplex(4096);
	let mut reader = MinerMessageReader::new(receiver);
	writer.write_all(&MAX_MESSAGE_SIZE.to_be_bytes()).await.unwrap();
	writer.write_all(&payload).await.unwrap();
	writer.shutdown().await.unwrap();
	assert_message(reader.read_message().await.unwrap(), &expected);
}

#[tokio::test]
async fn invalid_json_consumes_only_its_own_frame() {
	for payload in [b"".as_slice(), b"not-json".as_slice()] {
		let (mut writer, receiver) = tokio::io::duplex(4096);
		let mut reader = MinerMessageReader::new(receiver);
		writer.write_all(&(payload.len() as u32).to_be_bytes()).await.unwrap();
		writer.write_all(payload).await.unwrap();
		let next = result("following-invalid-json");
		write_message(&mut writer, &next).await.unwrap();
		writer.shutdown().await.unwrap();
		assert_eq!(
			reader.read_message().await.unwrap_err().kind(),
			std::io::ErrorKind::InvalidData
		);
		assert_message(reader.read_message().await.unwrap(), &next);
	}
}
