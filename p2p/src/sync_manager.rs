use core::{fmt::Display, hash::Hash, ops::Range, time::Duration};
use std::{collections::HashMap, sync::Arc, time::Instant};

use anyhow::Result;
use arithmetic::NonZeroExt as _;
use cached::{Cached as _, TimedSizedCache};
use eth2_libp2p::{rpc::StatusMessage, NetworkGlobals, PeerId};
use helper_functions::misc;
use itertools::Itertools as _;
use log::{log, Level};
use prometheus_metrics::Metrics;
use rand::{prelude::SliceRandom, seq::IteratorRandom as _, thread_rng};
use thiserror::Error;
use typenum::Unsigned as _;
use types::{
    config::Config,
    deneb::containers::BlobIdentifier,
    fulu::{containers::DataColumnIdentifier, primitives::ColumnIndex},
    nonstandard::Phase,
    phase0::primitives::{Epoch, Slot, H256},
    preset::Preset,
};

use crate::{
    block_sync_service::SyncDirection, misc::RequestId,
    range_and_root_requests::RangeAndRootRequests,
};

#[derive(PartialEq, Eq, Hash, Debug)]
struct ChainId {
    finalized_root: H256,
    finalized_epoch: Epoch,
}

impl From<&StatusMessage> for ChainId {
    fn from(status: &StatusMessage) -> Self {
        Self {
            finalized_root: status.finalized_root,
            finalized_epoch: status.finalized_epoch,
        }
    }
}

const BATCHES_PER_PEER: usize = 1;
const EPOCHS_PER_REQUEST: u64 = 2; // max 32
const GREEDY_MODE_BATCH_MULTIPLIER: usize = 3;
const GREEDY_MODE_PEER_LIMIT: usize = 2;
const MAX_SYNC_DISTANCE_IN_SLOTS: u64 = 10000;
const NOT_ENOUGH_PEERS_MESSAGE_COOLDOWN: Duration = Duration::from_secs(10);
const PEER_UPDATE_COOLDOWN_IN_SECONDS: u64 = 12;
const SEQUENTIAL_REDOWNLOADS_TILL_RESET: usize = 5;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SyncTarget {
    BlobSidecar,
    Block,
    DataColumnSidecar(Vec<ColumnIndex>),
}

#[derive(Debug, Clone)]
pub struct SyncBatch {
    pub target: SyncTarget,
    pub direction: SyncDirection,
    pub peer_id: PeerId,
    pub start_slot: Slot,
    pub count: u64,
}

pub struct SyncManager {
    peers: HashMap<PeerId, StatusMessage>,
    blob_requests: RangeAndRootRequests<BlobIdentifier>,
    block_requests: RangeAndRootRequests<H256>,
    data_column_requests: RangeAndRootRequests<DataColumnIdentifier>,
    last_sync_head: Slot,
    last_sync_range: Range<Slot>,
    sequential_redownloads: usize,
    status_updates_cache: TimedSizedCache<Epoch, ()>,
    not_enough_peers_message_shown_at: Option<Instant>,
    sync_from_finalized: bool,
    network_globals: Arc<NetworkGlobals>,
}

impl SyncManager {
    pub fn new(network_globals: Arc<NetworkGlobals>) -> Self {
        Self {
            peers: HashMap::new(),
            blob_requests: RangeAndRootRequests::<BlobIdentifier>::default(),
            block_requests: RangeAndRootRequests::<H256>::default(),
            data_column_requests: RangeAndRootRequests::<DataColumnIdentifier>::default(),
            last_sync_range: 0..0,
            last_sync_head: 0,
            sequential_redownloads: 0,
            status_updates_cache: TimedSizedCache::with_size_and_lifespan(
                5,
                PEER_UPDATE_COOLDOWN_IN_SECONDS,
            ),
            not_enough_peers_message_shown_at: None,
            sync_from_finalized: false,
            network_globals,
        }
    }

    #[must_use]
    pub const fn network_globals(&self) -> &Arc<NetworkGlobals> {
        &self.network_globals
    }

    pub fn request_direction(&mut self, request_id: RequestId) -> Option<SyncDirection> {
        self.block_requests.request_direction(request_id)
    }

    pub fn add_peer(&mut self, peer_id: PeerId, status: StatusMessage) {
        self.log(
            Level::Debug,
            format_args!("add peer (peer_id: {peer_id}, status: {status:?})"),
        );

        self.peers.insert(peer_id, status);
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Vec<SyncBatch> {
        self.log(
            Level::Debug,
            format_args!("remove peer (peer_id: {peer_id})"),
        );

        self.peers.remove(peer_id);

        self.block_requests
            .remove_peer(peer_id)
            .chain(self.blob_requests.remove_peer(peer_id))
            .chain(self.data_column_requests.remove_peer(peer_id))
            .collect_vec()
    }

    pub fn retry_batch(&mut self, request_id: RequestId, batch: SyncBatch) {
        self.log(
            Level::Debug,
            format_args!("retrying (request_id: {request_id}, batch {batch:?})"),
        );

        let target = batch.target.clone();
        match target {
            SyncTarget::DataColumnSidecar(columns) => {
                self.add_data_columns_request_by_range(request_id, batch, &columns);
            }
            SyncTarget::BlobSidecar => {
                self.add_blob_request_by_range(request_id, batch);
            }
            SyncTarget::Block => {
                self.add_block_request_by_range(request_id, batch);
            }
        }

        // if self
        //     .not_enough_peers_message_shown_at
        //     .map(|instant| instant.elapsed() > NOT_ENOUGH_PEERS_MESSAGE_COOLDOWN)
        //     .unwrap_or(true)
        // {
        //     self.log(
        //         Level::Warn,
        //         format_args!("not enough peers to request"),
        //     );
        //     self.not_enough_peers_message_shown_at = Some(Instant::now());
        // }
    }

    pub fn build_back_sync_batches<P: Preset>(
        &mut self,
        state_slot: Slot,
        low_slot: Slot,
    ) -> Vec<SyncBatch> {
        let Some(peers_to_sync) = self.find_peers_to_sync() else {
            return vec![];
        };

        let slots_per_request = P::SlotsPerEpoch::non_zero().get() * EPOCHS_PER_REQUEST;

        let mut sync_batches = vec![];

        for (peer_id, index) in Self::peer_sync_batch_assignments(&peers_to_sync).zip(0..) {
            let start_slot = state_slot
                .saturating_sub(slots_per_request * (index + 1))
                .max(low_slot);

            let end_slot = state_slot.saturating_sub(slots_per_request * index);

            let count = if start_slot == low_slot {
                end_slot - low_slot
            } else {
                slots_per_request
            };

            let batch = SyncBatch {
                target: SyncTarget::Block,
                direction: SyncDirection::Back,
                peer_id,
                start_slot,
                count,
            };

            self.log(
                Level::Debug,
                format_args!("back sync batch built: {batch:?})"),
            );

            sync_batches.push(batch);

            if start_slot == low_slot {
                break;
            }
        }

        self.log(
            Level::Debug,
            format_args!("new back sync batches count: {}", sync_batches.len(),),
        );

        sync_batches
    }

    #[expect(clippy::too_many_lines)]
    pub fn build_forward_sync_batches<P: Preset>(
        &mut self,
        config: &Config,
        current_slot: Slot,
        local_head_slot: Slot,
        local_finalized_slot: Slot,
    ) -> Result<Vec<SyncBatch>> {
        let Some(peers_to_sync) = self.find_peers_to_sync() else {
            return Ok(vec![]);
        };

        let Some(remote_head_slot) = self.max_remote_head_slot(&peers_to_sync) else {
            return Ok(vec![]);
        };

        if remote_head_slot <= local_head_slot {
            self.log(
                Level::Debug,
                format_args!(
                    "remote peers have no new slots (local_head_slot: {local_head_slot}, \
                    remote_head_slot: {remote_head_slot})",
                ),
            );

            return Ok(vec![]);
        }

        // TODO(feature/fulu): calculate based on type of requests (block, blob, or data column) by
        // based on the rate limiter constraints, below are the number of slots per requests:
        // 1, blocks: *64 ~ 128 (quota)
        // 2, blobs: 32 (16 avg per slot) ~ *64 (8 avg per slot) = 512 (quota)
        // 3, data columns: 5120 (quota)
        //      - superfullnode (all 128 cols) = *32 ~ 40 (cap)
        //      - fullnode (require 8 samples) = *320 (10 epochs) | 480 (15 epochs) ~ 640 (20 epochs)
        // NOTE: option with "*" is consider to be used
        let slots_per_request = P::SlotsPerEpoch::non_zero().get() * EPOCHS_PER_REQUEST;

        let mut redownloads_increased = false;

        if self.sync_from_finalized && self.last_sync_range.end >= local_head_slot {
            self.sync_from_finalized = false;
        }

        let sync_start_slot = {
            if self.sync_from_finalized {
                self.last_sync_range.end + 1
            } else if local_head_slot <= self.last_sync_head {
                self.log(Level::Debug, "local head not progressing");
                self.sequential_redownloads += 1;
                redownloads_increased = true;

                if self.sequential_redownloads >= SEQUENTIAL_REDOWNLOADS_TILL_RESET {
                    // Redownload failed 5 times, time to redownload blocks from last finalized slot
                    self.sequential_redownloads = 0;
                    self.sync_from_finalized = true;
                    local_finalized_slot + 1
                } else {
                    // If head slot has not changed since last sync,
                    // re-download everything from local head slot minus backtrack distance
                    local_head_slot.saturating_sub(P::SlotsPerEpoch::U64) + 1
                }
            } else {
                // Resume download from last sync batch end slot
                self.sequential_redownloads = 0;
                core::cmp::max(self.last_sync_range.end, local_head_slot) + 1
            }
        };

        self.log(
            Level::Debug,
            format_args!(
                "sequential redownloads: {}, \
                local finalized slot: {local_finalized_slot}, \
                local head slot: {local_head_slot}, \
                last sync head: {}, \
                remote head slot: {remote_head_slot}, \
                last sync range: {:?}, \
                sync start slot: {sync_start_slot},",
                self.sequential_redownloads, self.last_sync_head, self.last_sync_range,
            ),
        );

        self.last_sync_head = local_head_slot;

        if sync_start_slot >= local_head_slot + MAX_SYNC_DISTANCE_IN_SLOTS {
            return Ok(vec![]);
        }

        if remote_head_slot <= sync_start_slot {
            if redownloads_increased {
                self.sequential_redownloads = self.sequential_redownloads.saturating_sub(1);
            }

            self.log(
                Level::Debug,
                format_args!(
                    "remote peers have no new slots (sync_start_slot: {sync_start_slot}, \
                    remote_head_slot: {remote_head_slot})",
                ),
            );

            return Ok(vec![]);
        }

        let slot_distance = remote_head_slot.saturating_sub(sync_start_slot);
        let batches_in_front = usize::try_from(slot_distance / slots_per_request + 1)?;

        let mut max_slot = local_head_slot;
        let mut sync_batches = vec![];

        for (peer_id, index) in Self::peer_sync_batch_assignments(&peers_to_sync)
            .zip(0..)
            .take(batches_in_front)
        {
            let start_slot = sync_start_slot + slots_per_request * index;
            let count = remote_head_slot.saturating_sub(start_slot) + 1;
            let count = count.min(slots_per_request);

            max_slot = start_slot + count - 1;

            if config.phase_at_slot::<P>(start_slot) >= Phase::Fulu {
                let data_column_serve_range_slot =
                    misc::data_column_serve_range_slot::<P>(config, current_slot);
                if data_column_serve_range_slot < max_slot {
                    let columns = self
                        .network_globals()
                        .sampling_columns
                        .iter()
                        .copied()
                        .collect::<Vec<_>>();

                    match self.map_peer_custody_columns(&columns, None) {
                        Ok(peer_custody_columns_mapping) => {
                            for (peer_id, columns) in peer_custody_columns_mapping {
                                sync_batches.push(SyncBatch {
                                    target: SyncTarget::DataColumnSidecar(columns),
                                    direction: SyncDirection::Forward,
                                    peer_id,
                                    start_slot,
                                    count,
                                });
                            }
                        }
                        Err(error) => {
                            self.log(
                                Level::Debug,
                                format_args!(
                                    "could not find reliable peers to request column sidecars: {}, error: {}",
                                    self.network_globals.sampling_columns.iter().join(", "),
                                    error,
                                ),
                            );

                            sync_batches.push(SyncBatch {
                                target: SyncTarget::DataColumnSidecar(columns),
                                direction: SyncDirection::Forward,
                                peer_id,
                                start_slot,
                                count,
                            });
                        }
                    }
                }
            } else {
                let blob_serve_range_slot = misc::blob_serve_range_slot::<P>(config, current_slot);
                if blob_serve_range_slot < max_slot {
                    sync_batches.push(SyncBatch {
                        target: SyncTarget::BlobSidecar,
                        direction: SyncDirection::Forward,
                        peer_id,
                        start_slot,
                        count,
                    });
                }
            }

            sync_batches.push(SyncBatch {
                target: SyncTarget::Block,
                direction: SyncDirection::Forward,
                peer_id,
                start_slot,
                count,
            });
        }

        self.log(
            Level::Debug,
            format_args!("new sync batches count: {}", sync_batches.len()),
        );

        self.last_sync_range = sync_start_slot..max_slot;

        Ok(sync_batches)
    }

    pub fn ready_to_request_by_range(&mut self) -> bool {
        self.block_requests.ready_to_request_by_range()
            && self.blob_requests.ready_to_request_by_range()
    }

    pub fn ready_to_request_block_by_root(
        &mut self,
        block_root: H256,
        peer_id: Option<PeerId>,
    ) -> bool {
        self.block_requests
            .ready_to_request_by_root(&block_root, peer_id)
    }

    pub fn add_blob_request_by_range(&mut self, request_id: RequestId, batch: SyncBatch) {
        self.log(
            Level::Debug,
            format_args!(
                "add blob request by range (request_id: {}, peer_id: {}, range: {:?})",
                request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
            ),
        );

        self.blob_requests.add_request_by_range(request_id, batch)
    }

    pub fn add_blobs_request_by_root(
        &mut self,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: PeerId,
    ) -> Vec<BlobIdentifier> {
        self.log(Level::Debug, format_args!(
            "add blobs request by root (blob_identifiers: {blob_identifiers:?}, peer_id: {peer_id})",
        ));

        blob_identifiers
            .into_iter()
            .filter(|blob_id| self.blob_requests.add_request_by_root(*blob_id, peer_id))
            .collect_vec()
    }

    pub fn add_block_request_by_range(&mut self, request_id: RequestId, batch: SyncBatch) {
        self.log(
            Level::Debug,
            format_args!(
                "add block request by range (request_id: {}, peer_id: {}, range: {:?})",
                request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
            ),
        );

        self.block_requests.add_request_by_range(request_id, batch)
    }

    pub fn add_block_request_by_root(&mut self, block_root: H256, peer_id: PeerId) -> bool {
        self.log(
            Level::Debug,
            format_args!(
                "add block request by root (block_root: {block_root:?}, peer_id: {peer_id})",
            ),
        );

        self.block_requests.add_request_by_root(block_root, peer_id)
    }

    pub fn add_data_columns_request_by_range(
        &mut self,
        request_id: RequestId,
        batch: SyncBatch,
        columns: &[ColumnIndex],
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "add data column request by range (request_id: {}, peer_id: {}, range: {:?}, columns: [{}])",
                request_id,
                batch.peer_id,
                (batch.start_slot..(batch.start_slot + batch.count)),
                columns.iter().join(", "),
            ),
        );

        self.data_column_requests
            .add_request_by_range(request_id, batch)
    }

    pub fn add_data_columns_request_by_root(
        &mut self,
        data_column_identifiers: Vec<DataColumnIdentifier>,
        peer_id: PeerId,
    ) -> Vec<DataColumnIdentifier> {
        self.log(
            Level::Debug,
            format_args!(
                "add data column request by root (identifiers: {data_column_identifiers:?}, peer_id: {peer_id})",
            ),
        );

        data_column_identifiers
            .into_iter()
            .filter(|identifier| {
                self.data_column_requests
                    .add_request_by_root(*identifier, peer_id)
            })
            .collect_vec()
    }

    pub fn random_peer(&self) -> Option<PeerId> {
        let chain_id = self.chain_with_max_peer_count()?;

        self.peers
            .iter()
            .filter(|(_, status)| ChainId::from(*status) == chain_id)
            .map(|(&peer_id, _)| peer_id)
            .choose(&mut thread_rng())
    }

    pub fn blobs_by_range_request_finished(&mut self, request_id: RequestId) {
        self.log(
            Level::Debug,
            format_args!("request blob sidecars by range finished (request_id: {request_id})",),
        );

        self.blob_requests.request_by_range_finished(request_id)
    }

    pub fn received_blob_sidecar_chunk(
        &mut self,
        blob_identifier: BlobIdentifier,
        peer_id: PeerId,
        request_id: RequestId,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "received blob sidecar by root (blob_identifier: {blob_identifier:?}, \
            request_id: {request_id}, peer_id: {peer_id})",
            ),
        );

        self.blob_requests
            .chunk_by_root_received(&blob_identifier, &peer_id)
    }

    pub fn blocks_by_range_request_finished(&mut self, request_id: RequestId) {
        self.log(
            Level::Debug,
            format_args!("request blocks by range finished (request_id: {request_id})"),
        );

        self.block_requests.request_by_range_finished(request_id)
    }

    pub fn block_by_root_request_finished(&self, block_root: H256) {
        self.log(
            Level::Debug,
            format_args!("request block by root finished (block_root: {block_root:?})"),
        );
    }

    pub fn data_columns_by_range_request_finished(&mut self, request_id: RequestId) {
        self.log(
            Level::Debug,
            format_args!("request data columns by range finished (request_id: {request_id:?})",),
        );

        self.data_column_requests
            .request_by_range_finished(request_id)
    }

    pub fn received_data_column_sidecar_chunk(
        &mut self,
        data_column_identifier: DataColumnIdentifier,
        peer_id: PeerId,
        request_id: RequestId,
    ) {
        self.log(
            Level::Debug,
            format_args!(
                "received data column sidecar by root (data_column_identifier: {data_column_identifier:?}, \
            request_id: {request_id}, peer_id: {peer_id})",
            ),
        );

        self.data_column_requests
            .chunk_by_root_received(&data_column_identifier, &peer_id)
    }

    /// Log a message with peer count information.
    fn log(&self, level: Level, message: impl Display) {
        log!(
            level,
            "[Sync Peers: {}/{}] {}",
            self.most_peers(),
            self.total_peers(),
            message
        );
    }

    fn find_peers_to_sync(&mut self) -> Option<Vec<PeerId>> {
        self.find_chain_to_sync().map(|chain_id| {
            let peers_to_sync = self.chain_peers_shuffled(&chain_id);

            self.log(
                Level::Debug,
                format_args!("peers to sync count: {}", peers_to_sync.len()),
            );

            peers_to_sync
        })
    }

    fn find_chain_to_sync(&mut self) -> Option<ChainId> {
        match self.chain_with_max_peer_count() {
            Some(chain_id) => {
                self.log(
                    Level::Debug,
                    format_args!(
                        "selected chain to sync (finalized root {:?}, finalized epoch {})",
                        chain_id.finalized_root, chain_id.finalized_epoch,
                    ),
                );

                Some(chain_id)
            }
            None => {
                if self
                    .not_enough_peers_message_shown_at
                    .map(|instant| instant.elapsed() > NOT_ENOUGH_PEERS_MESSAGE_COOLDOWN)
                    .unwrap_or(true)
                {
                    self.log(Level::Debug, "waiting for more peers to join to start sync");
                    self.not_enough_peers_message_shown_at = Some(Instant::now());
                }

                None
            }
        }
    }

    fn chain_peers(&self, chain_id: &ChainId) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, status)| &ChainId::from(*status) == chain_id)
            .map(|(&peer_id, _)| peer_id)
            .collect()
    }

    fn chain_peers_shuffled(&self, chain_id: &ChainId) -> Vec<PeerId> {
        let mut peers = self.chain_peers(chain_id);
        peers.shuffle(&mut thread_rng());
        peers
    }

    fn chain_with_max_peer_count(&self) -> Option<ChainId> {
        self.chains_with_peer_counts()
            .into_iter()
            .max_by_key(|(_, peer_count)| *peer_count)
            .map(|(chain_id, _)| chain_id)
    }

    fn chains_with_peer_counts(&self) -> HashMap<ChainId, usize> {
        self.peers.iter().counts_by(|(_, status)| status.into())
    }

    fn most_peers(&self) -> usize {
        self.chains_with_peer_counts()
            .values()
            .max()
            .copied()
            .unwrap_or_default()
    }

    fn total_peers(&self) -> usize {
        self.peers.len()
    }

    fn max_remote_head_slot(&self, peers: &[PeerId]) -> Option<Slot> {
        peers
            .iter()
            .filter_map(|peer_id| self.peers.get(peer_id))
            .map(|status| status.head_slot)
            .max()
    }

    fn peer_sync_batch_assignments(peers: &[PeerId]) -> impl Iterator<Item = PeerId> + '_ {
        let batches_per_peer = if peers.len() <= GREEDY_MODE_PEER_LIMIT {
            BATCHES_PER_PEER * GREEDY_MODE_BATCH_MULTIPLIER
        } else {
            BATCHES_PER_PEER
        };

        core::iter::repeat(peers)
            .take(batches_per_peer)
            .flatten()
            .copied()
    }

    fn get_custodial_peers(&self, column_index: ColumnIndex) -> Vec<PeerId> {
        self.network_globals()
            .custody_peers_for_column(column_index)
    }

    fn get_random_custodial_peer(
        &self,
        column_index: ColumnIndex,
        ignore_peer: Option<PeerId>,
    ) -> Option<PeerId> {
        let mut custodial_peers = self.get_custodial_peers(column_index);

        // `ingore_peer` is often the previous requested peer that failed to response the request, or response
        // with an RPC error, which might not able to response to the request again, the peer
        // will be ignored from this request
        if let Some(peer) = ignore_peer {
            custodial_peers.retain(|&p| p != peer);
        }

        custodial_peers.choose(&mut thread_rng()).copied()
    }

    pub fn map_peer_custody_columns(
        &self,
        column_indices: &[ColumnIndex],
        ignore_peer: Option<PeerId>,
    ) -> Result<HashMap<PeerId, Vec<ColumnIndex>>> {
        let mut peer_columns_mapping = HashMap::new();

        for column_index in column_indices {
            let Some(custodial_peer) = self.get_random_custodial_peer(*column_index, ignore_peer)
            else {
                return Err(MapPeerCustodyError::NoCustodyPeers {
                    column_index: *column_index,
                }
                .into());
            };

            let peer_custody_columns = peer_columns_mapping
                .entry(custodial_peer)
                .or_insert_with(Vec::new);

            peer_custody_columns.push(*column_index);
        }

        Ok(peer_columns_mapping)
    }

    pub fn expired_blob_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch, Instant)> + '_ {
        self.blob_requests.expired_range_batches()
    }

    pub fn expired_block_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch, Instant)> + '_ {
        self.block_requests.expired_range_batches()
    }

    pub fn expired_data_column_range_batches(
        &mut self,
    ) -> impl Iterator<Item = (SyncBatch, Instant)> + '_ {
        self.data_column_requests.expired_range_batches()
    }

    pub fn cache_clear(&mut self) {
        self.blob_requests.cache_clear();
        self.block_requests.cache_clear();
        self.data_column_requests.cache_clear();
    }

    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(module_path!(), &type_name, "peers", self.peers.len());
        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "status_updates_cache",
            self.status_updates_cache.cache_size(),
        );

        // TODO: Differentiate
        self.blob_requests.track_collection_metrics(metrics);
        self.block_requests.track_collection_metrics(metrics);
        self.data_column_requests.track_collection_metrics(metrics);
    }
}

#[derive(Debug, Error)]
enum MapPeerCustodyError {
    #[error("No custodial peer for column_index: {column_index}")]
    NoCustodyPeers { column_index: ColumnIndex },
}

#[cfg(test)]
mod tests {
    use eth2_libp2p::NetworkConfig;
    use slog::{o, Drain};
    use std::sync::Arc;
    use test_case::test_case;
    use types::{
        config::Config as ChainConfig,
        phase0::primitives::H32,
        preset::{Mainnet, Minimal},
    };

    use super::*;

    pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        if enabled {
            slog::Logger::root(drain.filter_level(level).fuse(), o!())
        } else {
            slog::Logger::root(drain.filter(|_| false).fuse(), o!())
        }
    }

    fn build_sync_manager() -> SyncManager {
        let log = build_log(slog::Level::Debug, false);
        let chain_config = Arc::new(ChainConfig::default());
        let network_config = Arc::new(NetworkConfig::default());
        let network_globals =
            NetworkGlobals::new_test_globals(chain_config, vec![], &log, network_config);
        SyncManager::new(network_globals.into())
    }

    // `SyncBatch.count` is 16 because the test cases use `Minimal`.
    // `Minimal::SlotsPerEpoch::U64` × `EPOCHS_PER_REQUEST` = 8 × 2 = 16.
    #[test_case(
        0,
        128,
        [
            (112, 16),
            (96, 16),
            (80, 16),
            (64, 16),
            (48, 16),
            (32, 16),
        ]
    )]
    #[test_case(
        0,
        64,
        [
            (48, 16),
            (32, 16),
            (16, 16),
            (0, 16),
        ]
    )]
    #[test_case(
        2,
        30,
        [
            (14, 16),
            (2, 12),
        ]
    )]
    fn build_back_sync_batches(
        low_slot: Slot,
        state_slot: Slot,
        resulting_batches: impl IntoIterator<Item = (Slot, u64)>,
    ) {
        let peer_status = StatusMessage {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 6,
            head_root: H256::default(),
            head_slot: 8 * 32,
        };

        let mut sync_manager = build_sync_manager();

        sync_manager.add_peer(PeerId::random(), peer_status);
        sync_manager.add_peer(PeerId::random(), peer_status);

        let batches = sync_manager.build_back_sync_batches::<Minimal>(state_slot, low_slot);

        itertools::assert_equal(
            batches
                .into_iter()
                .map(|batch| (batch.start_slot, batch.count)),
            resulting_batches,
        );
    }

    #[test]
    fn test_build_forward_sync_batches_when_head_progresses() -> Result<()> {
        let config = Config::mainnet();
        let current_slot = 20_001;
        let local_head_slot = 3000;
        let local_finalized_slot = 1000;

        let peer_status = StatusMessage {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 248,
            head_root: H256::default(),
            head_slot: 20_000,
        };

        let mut sync_manager = build_sync_manager();

        sync_manager.add_peer(PeerId::random(), peer_status);

        for i in 0..50 {
            let batches = sync_manager.build_forward_sync_batches::<Mainnet>(
                &config,
                current_slot,
                local_head_slot + i,
                local_finalized_slot,
            )?;

            let sync_range_from = local_head_slot + 64 * 3 * i + 1;
            let sync_range_to = sync_range_from + 64 * 3 - 1;

            assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

            let first_batch = batches.first().expect("sync batches should be present");

            assert_eq!(first_batch.direction, SyncDirection::Forward);
            assert_eq!(first_batch.target, SyncTarget::Block);

            itertools::assert_equal(
                batches
                    .into_iter()
                    .map(|batch| (batch.start_slot, batch.count)),
                [
                    (sync_range_from, 64),
                    (sync_range_from + 64, 64),
                    (sync_range_from + 64 * 2, 64),
                ],
            );
        }

        Ok(())
    }

    #[test]
    fn test_build_forward_sync_batches_when_head_does_not_progress() -> Result<()> {
        let config = Config::mainnet();
        let current_slot = 20_001;
        let local_head_slot = 3000;
        let local_finalized_slot = 1000;

        let peer_status = StatusMessage {
            fork_digest: H32::default(),
            finalized_root: H256::default(),
            finalized_epoch: 248,
            head_root: H256::default(),
            head_slot: 20_000,
        };

        let mut sync_manager = build_sync_manager();

        sync_manager.add_peer(PeerId::random(), peer_status);

        sync_manager.build_forward_sync_batches::<Mainnet>(
            &config,
            current_slot,
            local_head_slot,
            local_finalized_slot,
        )?;

        let sync_range_from = local_head_slot + 1;
        let sync_range_to = sync_range_from + 64 * 3 - 1;

        assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

        // From second to fifth retries try to download blocks from local head slot minus one epoch

        for _ in 0..4 {
            sync_manager.build_forward_sync_batches::<Mainnet>(
                &config,
                current_slot,
                local_head_slot,
                local_finalized_slot,
            )?;

            let sync_range_from = local_head_slot - 32 + 1;
            let sync_range_to = sync_range_from + 64 * 3 - 1;

            assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);
        }

        // It local head still fails to progress, re-download blocks from last finalized slot up to local head slot

        let mut i = 0;
        let mut sync_range_to = 0;

        while sync_range_to < local_head_slot {
            sync_manager.build_forward_sync_batches::<Mainnet>(
                &config,
                current_slot,
                local_head_slot,
                local_finalized_slot,
            )?;

            let sync_range_from = local_finalized_slot + 64 * 3 * i + 1;
            sync_range_to = sync_range_from + 64 * 3 - 1;

            assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

            i += 1;
        }

        // Resume normal syncing behaviour

        sync_manager.build_forward_sync_batches::<Mainnet>(
            &config,
            current_slot,
            local_head_slot,
            local_finalized_slot,
        )?;

        let sync_range_from = local_head_slot - 32 + 1;
        let sync_range_to = sync_range_from + 64 * 3 - 1;

        assert_eq!(sync_manager.last_sync_range, sync_range_from..sync_range_to);

        Ok(())
    }
}
