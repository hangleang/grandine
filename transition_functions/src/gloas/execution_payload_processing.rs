use anyhow::{ensure, Result};
use execution_engine::ExecutionEngine;
use helper_functions::{
    accessors::{get_current_epoch, get_randao_mix},
    error::SignatureKind,
    gloas::compute_exit_epoch_and_update_churn,
    misc::{self, compute_timestamp_at_slot, kzg_commitment_to_versioned_hash},
    signing::SignForSingleFork as _,
    verifier::Verifier,
};
use pubkey_cache::PubkeyCache;
use ssz::{SszHash as _, H256};
use typenum::Unsigned as _;
use types::{
    combined::ExecutionPayloadParams,
    config::Config,
    electra::containers::ExecutionRequests,
    gloas::containers::{
        BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadEnvelope,
        SignedExecutionPayloadEnvelope,
    },
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::PostGloasBeaconState,
};

use crate::unphased::Error;

pub fn verify_execution_payload_envelope_signature<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
    mut verifier: impl Verifier,
) -> Result<()> {
    let builder = state
        .validators()
        .get(signed_envelope.message.builder_index)?;

    verifier.verify_singular(
        signed_envelope.message.signing_root(config, state),
        signed_envelope.signature,
        pubkey_cache.get_or_insert(builder.pubkey)?,
        SignatureKind::ExecutionPayloadEnvelope,
    )?;

    Ok(())
}

pub fn validate_execution_payload_for_gossip<P: Preset>(
    config: &Config,
    state: &impl PostGloasBeaconState<P>,
    envelope: &ExecutionPayloadEnvelope<P>,
) -> Result<()> {
    let payload = &envelope.payload;

    // > Verify timestamp
    let computed = compute_timestamp_at_slot(config, state, state.slot());
    let in_block = payload.timestamp;

    ensure!(
        computed == in_block,
        Error::<P>::ExecutionPayloadTimestampMismatch { computed, in_block },
    );

    // > [Modified in Fulu:EIP7594] Verify commitments are under limit
    // > [Modified in Fulu:EIP7892] BPO blob schedule
    let maximum = config
        .get_blob_schedule_entry(get_current_epoch(state))
        .max_blobs_per_block;
    let in_block = envelope.blob_kzg_commitments.len();

    ensure!(
        in_block <= maximum,
        Error::<P>::TooManyBlockKzgCommitments { in_block, maximum },
    );

    Ok(())
}

pub fn validate_execution_payload<P: Preset>(
    config: &Config,
    state: &impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
) -> Result<()> {
    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;

    validate_execution_payload_for_gossip(config, state, envelope)?;

    // > Verify consistency with the beacon block
    let in_envelope = envelope.beacon_block_root;
    let in_state = state.latest_block_header().hash_tree_root();
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeBlockRootMismatch {
            in_envelope,
            in_state,
        }
    );

    let in_envelope = envelope.slot;
    let in_state = state.slot();
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeSlotMismatch {
            in_envelope,
            in_state,
        }
    );

    // > Verify consistency with the committed bid
    let committed_bid = state.latest_execution_payload_bid();
    let in_envelope = envelope.builder_index;
    let in_state = committed_bid.builder_index;
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeBuilderMismatch {
            in_envelope,
            in_state,
        }
    );

    let in_envelope = envelope.blob_kzg_commitments.hash_tree_root();
    let in_state = committed_bid.blob_kzg_commitments_root;
    ensure!(
        in_envelope == in_state,
        Error::<P>::EnvelopeBlobCommitmentsMismatch {
            in_envelope,
            in_state,
        }
    );

    // > Verify the withdrawals root
    let in_payload = payload.withdrawals.hash_tree_root();
    let in_state = state.latest_withdrawals_root();
    ensure!(
        in_payload == in_state,
        Error::<P>::PayloadWithdrawalsMismatch {
            in_payload,
            in_state,
        }
    );

    // > Verify the gas_limit
    let in_payload = payload.gas_limit;
    let in_state = committed_bid.gas_limit;
    ensure!(
        in_payload == in_state,
        Error::<P>::PayloadGasLimitMismatch {
            in_payload,
            in_state,
        }
    );

    // > Verify the block hash
    let in_payload = payload.block_hash;
    let in_state = committed_bid.block_hash;
    ensure!(
        in_payload == in_state,
        Error::<P>::PayloadBlockHashMismatch {
            in_payload,
            in_state,
        }
    );

    // > Verify consistency of the parent hash with respect to the previous execution payload header
    let in_state = state.latest_block_hash();
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

    Ok(())
}

pub fn process_execution_payload<P: Preset, V: Verifier>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    signed_envelope: &SignedExecutionPayloadEnvelope<P>,
    execution_engine: impl ExecutionEngine<P>,
    verifier: V,
) -> Result<()> {
    if !V::IS_NULL {
        verify_execution_payload_envelope_signature(
            config,
            pubkey_cache,
            state,
            signed_envelope,
            verifier,
        )?;
    }

    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;

    // > Cache latest block header state root
    let previous_state_root = state.hash_tree_root();
    if state.latest_block_header().state_root == H256::zero() {
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    validate_execution_payload(config, state, signed_envelope)?;

    // > Verify the execution payload is valid
    let versioned_hashes = envelope
        .blob_kzg_commitments
        .iter()
        .copied()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    execution_engine.notify_new_payload(
        envelope.beacon_block_root,
        payload.clone().into(),
        Some(ExecutionPayloadParams::Electra {
            versioned_hashes,
            parent_beacon_block_root: state.latest_block_header().parent_root,
            execution_requests: envelope.execution_requests.clone(),
        }),
        None,
    )?;

    process_execution_requests(config, state, &envelope.execution_requests)?;

    // > Queue the builder payment
    let payment_slot = misc::builder_payment_index_for_current_epoch::<P>(state.slot());
    let payment = *state.builder_pending_payments().get(payment_slot)?;
    let amount = payment.withdrawal.amount;
    if amount > 0 {
        let exit_queue_epoch = compute_exit_epoch_and_update_churn(config, state, amount);
        let withdrawable_epoch =
            exit_queue_epoch.saturating_add(config.min_validator_withdrawability_delay);
        state
            .builder_pending_withdrawals_mut()
            .push(BuilderPendingWithdrawal {
                withdrawable_epoch,
                ..payment.withdrawal
            })?;
    }
    *state
        .builder_pending_payments_mut()
        .mod_index_mut(payment_slot) = BuilderPendingPayment::default();

    // > Cache execution payload header
    let slot: usize = state.slot().try_into()?;
    state
        .execution_payload_availability_mut()
        .set(slot % SlotsPerHistoricalRoot::<P>::USIZE, true);
    *state.latest_block_hash_mut() = payload.block_hash;

    if !V::IS_NULL {
        let computed = state.hash_tree_root();
        let in_envelope = envelope.state_root;
        ensure!(
            in_envelope == computed,
            Error::<P>::StateRootMismatch {
                computed,
                in_block: in_envelope
            }
        );
    }

    Ok(())
}

fn process_execution_requests<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    for deposit_request in &execution_requests.deposits {
        // TODO(glaos): use `electra::process_deposit_request` once compatible
        process_deposit_request(state, *deposit_request)?;
    }

    for withdrawal_request in &execution_requests.withdrawals {
        // TODO(gloas): use `electra::process_withdrawal_request` once compatible
        process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    for consolidation_request in &execution_requests.consolidations {
        // TODO(gloas): use `electra::process_consolidation_request` once compatible
        process_consolidation_request(config, state, *consolidation_request)?;
    }

    Ok(())
}

// TODO(gloas): remove
use types::electra::consts::UNSET_DEPOSIT_REQUESTS_START_INDEX;
use types::electra::containers::DepositRequest;
use types::electra::containers::PendingDeposit;
fn process_deposit_request<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    deposit_request: DepositRequest,
) -> Result<()> {
    let DepositRequest {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        index,
    } = deposit_request;

    let slot = state.slot();

    // > Set deposit request start index
    if state.deposit_requests_start_index() == UNSET_DEPOSIT_REQUESTS_START_INDEX {
        *state.deposit_requests_start_index_mut() = index;
    }

    state.pending_deposits_mut().push(PendingDeposit {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        slot,
    })?;

    Ok(())
}

// TODO(gloas): remove
use core::ops::Index as _;
use helper_functions::gloas::initiate_validator_exit;
use helper_functions::mutators::balance;
use tap::Pipe as _;
use types::electra::consts::FULL_EXIT_REQUEST_AMOUNT;
use types::electra::containers::PendingPartialWithdrawal;
use types::electra::containers::WithdrawalRequest;
fn process_withdrawal_request<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    withdrawal_request: WithdrawalRequest,
) -> Result<()> {
    let amount = withdrawal_request.amount;
    let is_full_exit_request = amount == FULL_EXIT_REQUEST_AMOUNT;

    // > If partial withdrawal queue is full, only full exits are processed
    if state.pending_partial_withdrawals().len_usize() == P::PendingPartialWithdrawalsLimit::USIZE
        && !is_full_exit_request
    {
        return Ok(());
    }

    // > Verify pubkey exists
    let request_pubkey = withdrawal_request.validator_pubkey;
    let Some(validator_index) = index_of_public_key(state, &request_pubkey) else {
        return Ok(());
    };
    let validator_balance = *balance(state, validator_index)?;
    let validator = state.validators().get(validator_index)?;

    // > Verify withdrawal credentials
    let has_correct_credential = has_execution_withdrawal_credential(validator);
    let source_address = validator
        .withdrawal_credentials
        .as_bytes()
        .index(H256::len_bytes() - ExecutionAddress::len_bytes()..)
        .pipe(ExecutionAddress::from_slice);

    let is_correct_source_address = source_address == withdrawal_request.source_address;

    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }

    // > Verify the validator is active
    if !is_active_validator(validator, get_current_epoch(state)) {
        return Ok(());
    }

    // > Verify exit has not been initiated
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    // > Verify the validator has been active long enough
    if get_current_epoch(state) < validator.activation_epoch + config.shard_committee_period {
        return Ok(());
    }

    let pending_balance_to_withdraw =
        get_pending_balance_to_withdraw_post_gloas(state, validator_index);

    if is_full_exit_request {
        // > Only exit validator if it has no pending withdrawals in the queue
        if pending_balance_to_withdraw == 0 {
            initiate_validator_exit(config, state, validator_index)?;
        }

        return Ok(());
    }

    let has_sufficient_effective_balance = validator.effective_balance >= P::MIN_ACTIVATION_BALANCE;
    let has_excess_balance =
        validator_balance > P::MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw;

    // > Only allow partial withdrawals with compounding withdrawal credentials
    if has_compounding_withdrawal_credential(validator)
        && has_sufficient_effective_balance
        && has_excess_balance
    {
        let to_withdraw =
            amount.min(validator_balance - P::MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw);
        let exit_queue_epoch = compute_exit_epoch_and_update_churn(config, state, to_withdraw);
        let withdrawable_epoch = exit_queue_epoch + config.min_validator_withdrawability_delay;

        state
            .pending_partial_withdrawals_mut()
            .push(PendingPartialWithdrawal {
                validator_index,
                amount: to_withdraw,
                withdrawable_epoch,
            })?;
    }

    Ok(())
}

// TODO(gloas): remove
use helper_functions::accessors::get_consolidation_churn_limit;
use helper_functions::accessors::get_pending_balance_to_withdraw_post_gloas;
use helper_functions::accessors::index_of_public_key;
use helper_functions::predicates::has_compounding_withdrawal_credential;
use helper_functions::predicates::has_execution_withdrawal_credential;
use helper_functions::predicates::is_active_validator;
use types::electra::containers::ConsolidationRequest;
use types::electra::containers::PendingConsolidation;
use types::phase0::consts::FAR_FUTURE_EPOCH;
fn process_consolidation_request<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    consolidation_request: ConsolidationRequest,
) -> Result<()> {
    let ConsolidationRequest {
        source_address,
        source_pubkey,
        target_pubkey,
    } = consolidation_request;

    if is_valid_switch_to_compounding_request(state, consolidation_request)? {
        let Some(source_index) = index_of_public_key(state, &source_pubkey) else {
            return Ok(());
        };

        return switch_to_compounding_validator(state, source_index);
    }

    // > Verify that source != target, so a consolidation cannot be used as an exit.
    if source_pubkey == target_pubkey {
        return Ok(());
    }

    // > If the pending consolidations queue is full, consolidation requests are ignored
    if state.pending_consolidations().len_usize() == P::PendingConsolidationsLimit::USIZE {
        return Ok(());
    }

    // > If there is too little available consolidation churn limit, consolidation requests are ignored
    if get_consolidation_churn_limit(config, state) <= P::MIN_ACTIVATION_BALANCE {
        return Ok(());
    }

    // > Verify pubkeys exists
    let Some(source_index) = index_of_public_key(state, &source_pubkey) else {
        return Ok(());
    };
    let Some(target_index) = index_of_public_key(state, &target_pubkey) else {
        return Ok(());
    };

    let source_validator = state.validators().get(source_index)?;
    let target_validator = state.validators().get(target_index)?;

    // > Verify source withdrawal credentials
    let has_correct_credential = has_execution_withdrawal_credential(source_validator);
    let computed_source_address = compute_source_address(source_validator);

    if !(has_correct_credential && computed_source_address == source_address) {
        return Ok(());
    }

    // > Verify that target has compounding withdrawal credentials
    if !has_compounding_withdrawal_credential(target_validator) {
        return Ok(());
    }

    // > Verify the source and the target are active
    let current_epoch = get_current_epoch(state);
    if !is_active_validator(source_validator, current_epoch) {
        return Ok(());
    }
    if !is_active_validator(target_validator, current_epoch) {
        return Ok(());
    }

    // > Verify exits for source and target have not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    if target_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    let source_validator = state.validators().get(source_index)?;

    // > Verify the source has been active long enough
    if current_epoch < source_validator.activation_epoch + config.shard_committee_period {
        return Ok(());
    }

    // > Verify the source has no pending withdrawals in the queue
    if get_pending_balance_to_withdraw_post_gloas(state, source_index) > 0 {
        return Ok(());
    }

    // > Initiate source validator exit and append pending consolidation
    let exit_epoch = compute_consolidation_epoch_and_update_churn(
        config,
        state,
        source_validator.effective_balance,
    );

    let source_validator = state.validators_mut().get_mut(source_index)?;

    source_validator.exit_epoch = exit_epoch;
    source_validator.withdrawable_epoch =
        source_validator.exit_epoch + config.min_validator_withdrawability_delay;

    state
        .pending_consolidations_mut()
        .push(PendingConsolidation {
            source_index,
            target_index,
        })?;

    Ok(())
}

// TODO(gloas): remove
use helper_functions::predicates::has_eth1_withdrawal_credential;
fn is_valid_switch_to_compounding_request<P: Preset>(
    state: &impl PostGloasBeaconState<P>,
    consolidation_request: ConsolidationRequest,
) -> Result<bool> {
    let ConsolidationRequest {
        source_address,
        source_pubkey,
        target_pubkey,
    } = consolidation_request;

    // > Switch to compounding requires source and target be equal
    if source_pubkey != target_pubkey {
        return Ok(false);
    }

    // > Verify pubkey exists
    let Some(source_index) = index_of_public_key(state, &source_pubkey) else {
        return Ok(false);
    };

    let source_validator = state.validators().get(source_index)?;

    // > Verify request has been authorized
    if compute_source_address(source_validator) != source_address {
        return Ok(false);
    }

    // > Verify source withdrawal credentials
    if !has_eth1_withdrawal_credential(source_validator) {
        return Ok(false);
    }

    // > Verify the source is active
    let current_epoch = get_current_epoch(state);

    if !is_active_validator(source_validator, current_epoch) {
        return Ok(false);
    }

    // > Verify exit for source has not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(false);
    }

    Ok(true)
}

// TODO(gloas): remove
use types::phase0::containers::Validator;
use types::phase0::primitives::ExecutionAddress;
fn compute_source_address(validator: &Validator) -> ExecutionAddress {
    let prefix_len = H256::len_bytes() - ExecutionAddress::len_bytes();
    ExecutionAddress::from_slice(&validator.withdrawal_credentials[prefix_len..])
}

// TODO(gloas): remove
use helper_functions::misc::compute_activation_exit_epoch;
use types::phase0::primitives::Epoch;
use types::phase0::primitives::Gwei;
fn compute_consolidation_epoch_and_update_churn<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    consolidation_balance: Gwei,
) -> Epoch {
    let mut earliest_consolidation_epoch = core::cmp::max(
        state.earliest_consolidation_epoch(),
        compute_activation_exit_epoch::<P>(get_current_epoch(state)),
    );

    let per_epoch_consolidation_churn = get_consolidation_churn_limit(config, state);

    // > New epoch for consolidations.

    let mut consolidation_balance_to_consume =
        if state.earliest_consolidation_epoch() < earliest_consolidation_epoch {
            per_epoch_consolidation_churn
        } else {
            state.consolidation_balance_to_consume()
        };

    // > Consolidation doesn't fit in the current earliest epoch.

    if consolidation_balance > consolidation_balance_to_consume {
        let balance_to_process = consolidation_balance - consolidation_balance_to_consume;
        let additional_epochs = (balance_to_process - 1) / per_epoch_consolidation_churn + 1;
        earliest_consolidation_epoch += additional_epochs;
        consolidation_balance_to_consume += additional_epochs * per_epoch_consolidation_churn;
    }

    // > Consume the balance and update state variables.

    *state.consolidation_balance_to_consume_mut() =
        consolidation_balance_to_consume - consolidation_balance;
    *state.earliest_consolidation_epoch_mut() = earliest_consolidation_epoch;

    state.earliest_consolidation_epoch()
}

// TODO(gloas): remove
use types::electra::consts::COMPOUNDING_WITHDRAWAL_PREFIX;
use types::phase0::primitives::ValidatorIndex;
fn switch_to_compounding_validator<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    index: ValidatorIndex,
) -> Result<()> {
    let validator = state.validators_mut().get_mut(index)?;

    validator.withdrawal_credentials[..COMPOUNDING_WITHDRAWAL_PREFIX.len()]
        .copy_from_slice(COMPOUNDING_WITHDRAWAL_PREFIX);

    queue_excess_active_balance(state, index)?;

    Ok(())
}

// TODO(gloas): remove
use bls::{traits::SignatureBytes as _, SignatureBytes};
use types::phase0::consts::GENESIS_SLOT;
fn queue_excess_active_balance<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    index: ValidatorIndex,
) -> Result<()> {
    let balance = *state.balances().get(index)?;

    if balance > P::MIN_ACTIVATION_BALANCE {
        let excess_balance = balance - P::MIN_ACTIVATION_BALANCE;

        *state.balances_mut().get_mut(index)? = P::MIN_ACTIVATION_BALANCE;

        let validator = state.validators().get(index)?;

        let pubkey = validator.pubkey;
        let withdrawal_credentials = validator.withdrawal_credentials;

        state.pending_deposits_mut().push(PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount: excess_balance,
            signature: SignatureBytes::empty(),
            slot: GENESIS_SLOT,
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod spec_tests {
    use execution_engine::MockExecutionEngine;
    use helper_functions::verifier::SingleVerifier;
    use serde::Deserialize;
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        gloas::beacon_state::BeaconState,
        preset::{Mainnet, Minimal},
    };

    use super::*;

    #[derive(Deserialize)]
    struct Execution {
        execution_valid: bool,
    }

    macro_rules! processing_tests {
        (
            $module_name: ident,
            $processing_function: expr,
            $operation_name: literal,
            $mainnet_glob: literal,
            $minimal_glob: literal,
        ) => {
            mod $module_name {
                use super::*;

                #[test_resources($mainnet_glob)]
                fn mainnet(case: Case) {
                    run_processing_case_specialized::<Mainnet>(case);
                }

                #[test_resources($minimal_glob)]
                fn minimal(case: Case) {
                    run_processing_case_specialized::<Minimal>(case);
                }

                fn run_processing_case_specialized<P: Preset>(case: Case) {
                    run_processing_case::<P, _>(case, $operation_name, $processing_function);
                }
            }
        };
    }

    // TODO(gloas): use `electra::process_deposit_request`
    processing_tests! {
        process_deposit_request,
        |_, _, state, deposit_request, _| process_deposit_request(state, deposit_request),
        "deposit_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/deposit_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/deposit_request/*/*",
    }

    // TODO(gloas): use `electra::process_withdrawal_request`
    processing_tests! {
        process_withdrawal_request,
        |config, _, state, withdrawal_request, _| process_withdrawal_request(config, state, withdrawal_request),
        "withdrawal_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/withdrawal_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/withdrawal_request/*/*",
    }

    // TODO(gloas): use `electra::process_consolidation_request`
    processing_tests! {
        process_consolidation_request,
        |config, _, state, consolidation_request, _| process_consolidation_request(config, state, consolidation_request),
        "consolidation_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/consolidation_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/consolidation_request/*/*",
    }

    #[test_resources("consensus-spec-tests/tests/mainnet/gloas/operations/execution_payload/*/*")]
    fn mainnet_execution_payload(case: Case) {
        run_execution_payload_case::<Mainnet>(case);
    }

    #[test_resources("consensus-spec-tests/tests/minimal/gloas/operations/execution_payload/*/*")]
    fn minimal_execution_payload(case: Case) {
        run_execution_payload_case::<Minimal>(case);
    }

    fn run_processing_case<P: Preset, O: SszReadDefault>(
        case: Case,
        operation_name: &str,
        processing_function: impl FnOnce(
            &Config,
            &PubkeyCache,
            &mut BeaconState<P>,
            O,
            BlsSetting,
        ) -> Result<()>,
    ) {
        let pubkey_cache = PubkeyCache::default();
        let mut state = case.ssz_default("pre");
        let operation = case.ssz_default(operation_name);
        let post_option = case.try_ssz_default("post");
        let bls_setting = case.meta().bls_setting;

        let result = processing_function(
            &P::default_config(),
            &pubkey_cache,
            &mut state,
            operation,
            bls_setting,
        )
        .map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("operation processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("operation processing should fail");
        }
    }

    fn run_execution_payload_case<P: Preset>(case: Case) {
        let mut state = case.ssz_default::<BeaconState<P>>("pre");
        let signed_envelope_option = case.try_ssz_default("signed_envelope");
        let post_option = case.try_ssz_default("post");
        let Execution { execution_valid } = case.yaml("execution");
        let execution_engine = MockExecutionEngine::new(execution_valid, false, None);
        let pubkey_cache = PubkeyCache::default();

        // TODO(gloas): check for invalid case
        let Some(signed_envelope) = signed_envelope_option else {
            return;
        };

        let result = process_execution_payload(
            &P::default_config(),
            &pubkey_cache,
            &mut state,
            &signed_envelope,
            &execution_engine,
            SingleVerifier,
        )
        .map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("execution payload processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("execution payload processing should fail");
        }
    }
}
