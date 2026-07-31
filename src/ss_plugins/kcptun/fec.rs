//! Wire-compatible forward error correction for `kcp-go`.
//!
//! Kcptun protects the complete FEC packet with its packet crypt.  The FEC
//! layer therefore deals only with plaintext packets and deliberately keeps
//! a very small number of incomplete shard sets to bound unauthenticated UDP
//! memory use.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;

use reed_solomon_erasure::galois_8::ReedSolomon;

pub const FEC_HEADER_SIZE: usize = 6;
pub const FEC_DATA_HEADER_SIZE: usize = 8;
pub const FEC_TYPE_DATA: u16 = 0xf1;
pub const FEC_TYPE_PARITY: u16 = 0xf2;
pub const FEC_TYPE_OOB: u16 = 0xf3;
pub const DEFAULT_MAX_SHARD_SETS: usize = 3;

#[derive(Debug)]
pub struct FecEncodeResult {
    /// The original data packet followed by parity packets when a shard set
    /// has just completed.
    pub packets: Vec<Vec<u8>>,
}

pub struct FecEncoder {
    codec: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
    total_shards: usize,
    max_kcp_packet: usize,
    next_sequence: u32,
    sequence_limit: u32,
    pending: Vec<Vec<u8>>,
}

impl FecEncoder {
    pub fn new(
        data_shards: usize,
        parity_shards: usize,
        max_kcp_packet: usize,
    ) -> io::Result<Self> {
        validate_parameters(data_shards, parity_shards, max_kcp_packet)?;
        let total_shards = data_shards + parity_shards;
        let codec = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|error| invalid(format!("invalid Kcptun FEC settings: {error}")))?;
        Ok(Self {
            codec,
            data_shards,
            parity_shards,
            total_shards,
            max_kcp_packet,
            next_sequence: 0,
            sequence_limit: u32::MAX / total_shards as u32 * total_shards as u32,
            pending: Vec::with_capacity(data_shards),
        })
    }

    pub fn encode(&mut self, kcp_packet: &[u8]) -> io::Result<FecEncodeResult> {
        if kcp_packet.is_empty() || kcp_packet.len() > self.max_kcp_packet {
            return Err(invalid_data(format!(
                "Kcptun KCP packet length {} is outside 1..={}",
                kcp_packet.len(),
                self.max_kcp_packet
            )));
        }
        let encoded_size = kcp_packet
            .len()
            .checked_add(2)
            .filter(|size| *size <= u16::MAX as usize)
            .ok_or_else(|| invalid_data("Kcptun FEC data shard is too large"))?;

        let sequence = self.take_sequence();
        let mut data_packet = Vec::with_capacity(FEC_DATA_HEADER_SIZE + kcp_packet.len());
        data_packet.extend_from_slice(&sequence.to_le_bytes());
        data_packet.extend_from_slice(&FEC_TYPE_DATA.to_le_bytes());
        data_packet.extend_from_slice(&(encoded_size as u16).to_le_bytes());
        data_packet.extend_from_slice(kcp_packet);

        self.pending.push(data_packet[FEC_HEADER_SIZE..].to_vec());
        let mut packets = vec![data_packet];
        if self.pending.len() != self.data_shards {
            return Ok(FecEncodeResult { packets });
        }

        let shard_len = self
            .pending
            .iter()
            .map(Vec::len)
            .max()
            .ok_or_else(|| invalid_data("Kcptun FEC shard set is unexpectedly empty"))?;
        let mut shards = Vec::with_capacity(self.total_shards);
        for mut shard in self.pending.drain(..) {
            shard.resize(shard_len, 0);
            shards.push(shard);
        }
        shards.extend((0..self.parity_shards).map(|_| vec![0_u8; shard_len]));
        self.codec
            .encode(&mut shards)
            .map_err(|error| invalid_data(format!("Kcptun FEC encoding failed: {error}")))?;

        for parity in shards.drain(self.data_shards..) {
            let sequence = self.take_sequence();
            let mut parity_packet = Vec::with_capacity(FEC_HEADER_SIZE + parity.len());
            parity_packet.extend_from_slice(&sequence.to_le_bytes());
            parity_packet.extend_from_slice(&FEC_TYPE_PARITY.to_le_bytes());
            parity_packet.extend_from_slice(&parity);
            packets.push(parity_packet);
        }
        Ok(FecEncodeResult { packets })
    }

    fn take_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if self.next_sequence >= self.sequence_limit {
            self.next_sequence = 0;
        }
        sequence
    }
}

#[derive(Debug, Default)]
pub struct FecDecodeResult {
    /// KCP packets ready to pass to the KCP state machine.  A received data
    /// packet is returned immediately; reconstructed data packets follow it.
    pub kcp_packets: Vec<Vec<u8>>,
}

struct ShardSet {
    shards: Vec<Option<Vec<u8>>>,
    present: usize,
    max_len: usize,
    arrival: u64,
}

pub struct FecDecoder {
    codec: ReedSolomon,
    data_shards: usize,
    total_shards: usize,
    sequence_limit: u32,
    max_packet_size: usize,
    max_shard_sets: usize,
    arrival: u64,
    sets: HashMap<u32, ShardSet>,
    completed: HashSet<u32>,
    completed_order: VecDeque<u32>,
}

impl FecDecoder {
    pub fn new(
        data_shards: usize,
        parity_shards: usize,
        max_packet_size: usize,
    ) -> io::Result<Self> {
        Self::with_max_shard_sets(
            data_shards,
            parity_shards,
            max_packet_size,
            DEFAULT_MAX_SHARD_SETS,
        )
    }

    pub fn with_max_shard_sets(
        data_shards: usize,
        parity_shards: usize,
        max_packet_size: usize,
        max_shard_sets: usize,
    ) -> io::Result<Self> {
        validate_parameters(
            data_shards,
            parity_shards,
            max_packet_size.saturating_sub(FEC_DATA_HEADER_SIZE),
        )?;
        if max_shard_sets == 0 || max_shard_sets > 64 {
            return Err(invalid("Kcptun FEC shard-set limit must be in 1..=64"));
        }
        let codec = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|error| invalid(format!("invalid Kcptun FEC settings: {error}")))?;
        Ok(Self {
            codec,
            data_shards,
            total_shards: data_shards + parity_shards,
            sequence_limit: u32::MAX / (data_shards + parity_shards) as u32
                * (data_shards + parity_shards) as u32,
            max_packet_size,
            max_shard_sets,
            arrival: 0,
            sets: HashMap::with_capacity(max_shard_sets),
            completed: HashSet::with_capacity(max_shard_sets * 2),
            completed_order: VecDeque::with_capacity(max_shard_sets * 2),
        })
    }

    pub fn decode(&mut self, packet: &[u8]) -> io::Result<FecDecodeResult> {
        if packet.len() < FEC_HEADER_SIZE || packet.len() > self.max_packet_size {
            return Err(invalid_data(format!(
                "Kcptun FEC packet length {} is outside {}..={}",
                packet.len(),
                FEC_HEADER_SIZE,
                self.max_packet_size
            )));
        }
        let sequence = u32::from_le_bytes(packet[..4].try_into().expect("fixed sequence slice"));
        if sequence >= self.sequence_limit {
            return Err(invalid_data(
                "Kcptun FEC sequence exceeds the wrap-protection boundary",
            ));
        }
        let packet_type = u16::from_le_bytes(packet[4..6].try_into().expect("fixed type slice"));
        let shard_index = sequence as usize % self.total_shards;
        match packet_type {
            FEC_TYPE_DATA if shard_index < self.data_shards => {}
            FEC_TYPE_PARITY if shard_index >= self.data_shards => {}
            FEC_TYPE_OOB => {
                return Err(invalid_data(
                    "Kcptun out-of-band FEC packets are not valid session traffic",
                ));
            }
            FEC_TYPE_DATA | FEC_TYPE_PARITY => {
                return Err(invalid_data(
                    "Kcptun FEC packet type does not match its shard position",
                ));
            }
            _ => return Err(invalid_data("unknown Kcptun FEC packet type")),
        }

        let mut result = FecDecodeResult::default();
        if packet_type == FEC_TYPE_DATA {
            if packet.len() < FEC_DATA_HEADER_SIZE {
                return Err(invalid_data("truncated Kcptun FEC data packet"));
            }
            let declared =
                u16::from_le_bytes(packet[6..8].try_into().expect("fixed size slice")) as usize;
            if declared < 2 || declared != packet.len() - FEC_HEADER_SIZE {
                return Err(invalid_data("invalid Kcptun FEC data length"));
            }
            result
                .kcp_packets
                .push(packet[FEC_DATA_HEADER_SIZE..].to_vec());
        }

        let set_id = sequence / self.total_shards as u32;
        if self.completed.contains(&set_id) {
            return Ok(result);
        }
        if !self.sets.contains_key(&set_id) {
            self.evict_oldest_if_full();
            self.arrival = self.arrival.wrapping_add(1);
            self.sets.insert(
                set_id,
                ShardSet {
                    shards: vec![None; self.total_shards],
                    present: 0,
                    max_len: 0,
                    arrival: self.arrival,
                },
            );
        }

        let set = self.sets.get_mut(&set_id).expect("inserted shard set");
        if set.shards[shard_index].is_some() {
            return Ok(FecDecodeResult::default());
        }
        let shard = packet[FEC_HEADER_SIZE..].to_vec();
        if shard.is_empty() {
            return Err(invalid_data("empty Kcptun FEC shard"));
        }
        set.max_len = set.max_len.max(shard.len());
        set.shards[shard_index] = Some(shard);
        set.present += 1;

        if set.present < self.data_shards {
            return Ok(result);
        }

        let mut set = self.sets.remove(&set_id).expect("existing shard set");
        let missing_data: Vec<usize> = (0..self.data_shards)
            .filter(|index| set.shards[*index].is_none())
            .collect();
        if missing_data.is_empty() {
            self.mark_completed(set_id);
            return Ok(result);
        }
        for shard in set.shards.iter_mut().flatten() {
            shard.resize(set.max_len, 0);
        }
        self.codec
            .reconstruct_data(&mut set.shards)
            .map_err(|error| invalid_data(format!("Kcptun FEC recovery failed: {error}")))?;

        for index in missing_data {
            let recovered = set.shards[index]
                .take()
                .ok_or_else(|| invalid_data("Kcptun FEC did not recover a data shard"))?;
            if recovered.len() < 2 {
                return Err(invalid_data("recovered Kcptun FEC shard is truncated"));
            }
            let declared =
                u16::from_le_bytes(recovered[..2].try_into().expect("fixed size slice")) as usize;
            if declared < 2 || declared > recovered.len() {
                return Err(invalid_data(
                    "recovered Kcptun FEC shard has an invalid length",
                ));
            }
            result.kcp_packets.push(recovered[2..declared].to_vec());
        }
        self.mark_completed(set_id);
        Ok(result)
    }

    pub fn pending_shard_sets(&self) -> usize {
        self.sets.len()
    }

    fn evict_oldest_if_full(&mut self) {
        if self.sets.len() < self.max_shard_sets {
            return;
        }
        if let Some(oldest) = self
            .sets
            .iter()
            .min_by_key(|(_, set)| set.arrival)
            .map(|(id, _)| *id)
        {
            self.sets.remove(&oldest);
        }
    }

    fn mark_completed(&mut self, set_id: u32) {
        if self.completed.insert(set_id) {
            self.completed_order.push_back(set_id);
        }
        while self.completed_order.len() > self.max_shard_sets * 2 {
            if let Some(oldest) = self.completed_order.pop_front() {
                self.completed.remove(&oldest);
            }
        }
    }
}

pub fn packet_type(packet: &[u8]) -> io::Result<u16> {
    if packet.len() < FEC_HEADER_SIZE {
        return Err(invalid_data("truncated Kcptun FEC packet"));
    }
    Ok(u16::from_le_bytes(
        packet[4..6].try_into().expect("fixed type slice"),
    ))
}

fn validate_parameters(
    data_shards: usize,
    parity_shards: usize,
    max_payload: usize,
) -> io::Result<()> {
    if data_shards == 0
        || parity_shards == 0
        || data_shards
            .checked_add(parity_shards)
            .is_none_or(|total| total > 256)
    {
        return Err(invalid(
            "Kcptun FEC needs positive shard counts and at most 256 total shards",
        ));
    }
    if max_payload == 0 || max_payload > u16::MAX as usize - 2 {
        return Err(invalid("Kcptun FEC packet limit is invalid"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_two_lost_data_shards() {
        let originals = [
            b"first packet".as_slice(),
            b"second packet is longer".as_slice(),
            b"third packet".as_slice(),
            b"fourth".as_slice(),
        ];
        let mut encoder = FecEncoder::new(4, 2, 256).unwrap();
        let mut wire = Vec::new();
        for original in originals {
            wire.extend(encoder.encode(original).unwrap().packets);
        }
        assert_eq!(wire.len(), 6);

        // Lose data shards 1 and 3. Both parity shards are sufficient to
        // reconstruct them.
        let mut decoder = FecDecoder::new(4, 2, 512).unwrap();
        let mut recovered = Vec::new();
        for index in [0, 2, 4, 5] {
            recovered.extend(decoder.decode(&wire[index]).unwrap().kcp_packets);
        }
        assert!(recovered.iter().any(|packet| packet == originals[0]));
        assert!(recovered.iter().any(|packet| packet == originals[1]));
        assert!(recovered.iter().any(|packet| packet == originals[2]));
        assert!(recovered.iter().any(|packet| packet == originals[3]));
        assert_eq!(decoder.pending_shard_sets(), 0);
    }

    #[test]
    fn rejects_malformed_and_inconsistent_packets() {
        let mut decoder = FecDecoder::new(2, 1, 64).unwrap();
        assert!(decoder.decode(&[0; 5]).is_err());

        let mut wrong_position = vec![0_u8; 8];
        wrong_position[..4].copy_from_slice(&2_u32.to_le_bytes());
        wrong_position[4..6].copy_from_slice(&FEC_TYPE_DATA.to_le_bytes());
        wrong_position[6..8].copy_from_slice(&2_u16.to_le_bytes());
        assert!(decoder.decode(&wrong_position).is_err());

        let mut wrong_size = vec![0_u8; 9];
        wrong_size[4..6].copy_from_slice(&FEC_TYPE_DATA.to_le_bytes());
        wrong_size[6..8].copy_from_slice(&2_u16.to_le_bytes());
        assert!(decoder.decode(&wrong_size).is_err());

        let oversized = vec![0_u8; 65];
        assert!(decoder.decode(&oversized).is_err());
    }

    #[test]
    fn bounds_incomplete_shard_sets_and_ignores_duplicates() {
        let mut decoder = FecDecoder::with_max_shard_sets(2, 1, 64, 2).unwrap();
        for set in 0..8_u32 {
            let sequence = set * 3;
            let mut packet = Vec::new();
            packet.extend_from_slice(&sequence.to_le_bytes());
            packet.extend_from_slice(&FEC_TYPE_DATA.to_le_bytes());
            packet.extend_from_slice(&3_u16.to_le_bytes());
            packet.push(set as u8);
            assert_eq!(decoder.decode(&packet).unwrap().kcp_packets.len(), 1);
            assert!(decoder.pending_shard_sets() <= 2);

            // A duplicate must not grow state or be delivered twice.
            assert!(decoder.decode(&packet).unwrap().kcp_packets.is_empty());
            assert!(decoder.pending_shard_sets() <= 2);
        }
    }
}
