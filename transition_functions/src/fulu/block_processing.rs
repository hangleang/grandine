use anyhow::{ensure, Result};
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use helper_functions::{
    accessors::{self, get_current_epoch, get_randao_mix},
    error::SignatureKind,
    misc::{compute_timestamp_at_slot, kzg_commitment_to_versioned_hash},
    signing::SignForSingleFork as _,
    slot_report::SlotReport,
    verifier::{SingleVerifier, Verifier},
};
use ssz::SszHash as _;
use typenum::Unsigned as _;
use types::{
    combined::ExecutionPayloadParams,
    config::Config,
    deneb::containers::ExecutionPayloadHeader,
    fulu::{
        beacon_state::BeaconState as FuluBeaconState,
        containers::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock},
    },
    phase0::primitives::H256,
    preset::Preset,
};

use crate::{
    altair, electra,
    unphased::{self, Error},
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

/// [`process_block`](TODO(feature/electra))
///
/// This also serves as a substitute for [`compute_new_state_root`]. `compute_new_state_root` as
/// defined in `consensus-specs` uses `state_transition`, but in practice `state` will already be
/// processed up to `block.slot`, which would make `process_slots` fail due to the restriction added
/// in [version 0.11.3]. `consensus-specs` [originally used `process_block`] but it was [lost].
///
/// [`compute_new_state_root`]:        https://github.com/ethereum/consensus-specs/blob/2ef55744df782eb153fc0a3b1c7875b8c2e11730/specs/phase0/validator.md#state-root
/// [version 0.11.3]:                  https://github.com/ethereum/consensus-specs/releases/tag/v0.11.3
/// [originally used `process_block`]: https://github.com/ethereum/consensus-specs/commit/103a66b2af9d9ec1fd1c70adc8e9029af5775c1c#diff-abbdef70b08ada829d740f06c004c154R298-R301
/// [lost]:                            https://github.com/ethereum/consensus-specs/commit/2dbc33327084d2814958f92eb0a838b9bc161903#diff-e96c612010477fc9536e3ff1ef1a1d5dR343-R346
pub fn process_block<P: Preset>(
    config: &Config,
    state: &mut FuluBeaconState<P>,
    block: &BeaconBlock<P>,
    mut verifier: impl Verifier,
    slot_report: impl SlotReport,
) -> Result<()> {
    #[cfg(feature = "metrics")]
    let _timer = METRICS
        .get()
        .map(|metrics| metrics.block_transition_times.start_timer());

    verifier.reserve(count_required_signatures(block));

    custom_process_block(
        config,
        state,
        block,
        NullExecutionEngine,
        &mut verifier,
        slot_report,
    )?;

    verifier.finish()
}

pub fn process_block_for_gossip<P: Preset>(
    config: &Config,
    state: &FuluBeaconState<P>,
    block: &SignedBeaconBlock<P>,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.message.slot);

    unphased::process_block_header_for_gossip(state, &block.message)?;

    process_execution_payload_for_gossip(config, state, &block.message.body)?;

    SingleVerifier.verify_singular(
        block.message.signing_root(config, state),
        block.signature,
        accessors::public_key(state, block.message.proposer_index)?,
        SignatureKind::Block,
    )?;

    Ok(())
}

// TODO(feature/electra): Reuse function from `transition_functions::capella::block_processing`.
pub fn count_required_signatures<P: Preset>(block: &BeaconBlock<P>) -> usize {
    altair::count_required_signatures(block) + block.body.bls_to_execution_changes.len()
}

pub fn custom_process_block<P: Preset>(
    config: &Config,
    state: &mut FuluBeaconState<P>,
    block: &BeaconBlock<P>,
    execution_engine: impl ExecutionEngine<P>,
    mut verifier: impl Verifier,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    debug_assert_eq!(state.slot, block.slot);

    unphased::process_block_header(state, block)?;

    // > [Modified in Electra:EIP7251]
    electra::process_withdrawals(state, &block.body.execution_payload)?;

    // > [Modified in Electra:EIP6110]
    process_execution_payload(
        config,
        state,
        // TODO(Grandine Team): Try caching `block.hash_tree_root()`.
        //                      Also consider removing the parameter entirely.
        //                      It's only used for error reporting.
        //                      Perhaps it would be better to send the whole block?
        block.hash_tree_root(),
        &block.body,
        execution_engine,
    )?;

    unphased::process_randao(config, state, &block.body, &mut verifier)?;
    unphased::process_eth1_data(state, &block.body)?;

    // > [Modified in Electra:EIP6110:EIP7002:EIP7549:EIP7251]
    electra::process_operations(config, state, &block.body, &mut verifier, &mut slot_report)?;

    // > [New in Electra:EIP6110]
    for deposit_request in &block.body.execution_requests.deposits {
        electra::process_deposit_request(state, *deposit_request)?;
    }

    // > [New in Electra:EIP7002:EIP7251]
    for withdrawal_request in &block.body.execution_requests.withdrawals {
        electra::process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    // > [New in Electra:EIP7251]
    for consolidation_request in &block.body.execution_requests.consolidations {
        electra::process_consolidation_request(config, state, *consolidation_request)?;
    }

    altair::process_sync_aggregate(
        config,
        state,
        block.body.sync_aggregate,
        verifier,
        slot_report,
    )
}

fn process_execution_payload_for_gossip<P: Preset>(
    config: &Config,
    state: &FuluBeaconState<P>,
    body: &BeaconBlockBody<P>,
) -> Result<()> {
    let payload = &body.execution_payload;

    // > Verify timestamp
    let computed = compute_timestamp_at_slot(config, state, state.slot);
    let in_block = payload.timestamp;

    ensure!(
        computed == in_block,
        Error::<P>::ExecutionPayloadTimestampMismatch { computed, in_block },
    );

    // > [Modified in Fulu:EIP7594] Verify commitments are under limit
    let maximum = P::MaxBlobsPerBlockFulu::USIZE;
    let in_block = body.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block, maximum },
    );

    Ok(())
}

fn process_execution_payload<P: Preset>(
    config: &Config,
    state: &mut FuluBeaconState<P>,
    block_root: H256,
    body: &BeaconBlockBody<P>,
    execution_engine: impl ExecutionEngine<P>,
) -> Result<()> {
    let payload = &body.execution_payload;
    let execution_requests = &body.execution_requests;

    // > Verify consistency of the parent hash with respect to the previous execution payload header
    let in_state = state.latest_execution_payload_header.block_hash;
    let in_block = payload.parent_hash;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadParentHashMismatch { in_state, in_block },
    );

    // > Verify prev_randao
    let in_state = get_randao_mix(state, get_current_epoch(state));
    let in_block = payload.prev_randao;

    ensure!(
        in_state == in_block,
        Error::<P>::ExecutionPayloadPrevRandaoMismatch { in_state, in_block },
    );

    process_execution_payload_for_gossip(config, state, body)?;

    // TODO(feature/electra): Verify `is_valid_block_hash`.
    // TODO(feature/electra): Verify `versioned_hashes`.
    // > Verify the execution payload is valid
    let versioned_hashes = body
        .blob_kzg_commitments
        .iter()
        .copied()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    execution_engine.notify_new_payload(
        block_root,
        payload.clone().into(),
        Some(ExecutionPayloadParams::Electra {
            versioned_hashes,
            parent_beacon_block_root: state.latest_block_header.parent_root,
            execution_requests: execution_requests.clone(),
        }),
        None,
    )?;

    // > Cache execution payload header
    state.latest_execution_payload_header = ExecutionPayloadHeader::from(payload);

    Ok(())
}
