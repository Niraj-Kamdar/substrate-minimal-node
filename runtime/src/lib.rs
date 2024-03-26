// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use frame::{
	deps::frame_support::{
		genesis_builder_helper::{build_config, create_default_config},
		weights::{FixedFee, NoFee},
	},
	prelude::*,
	runtime::{
		apis::{
			self, impl_runtime_apis, ApplyExtrinsicResult, CheckInherentsResult,
			ExtrinsicInclusionMode, OpaqueMetadata,
		},
		prelude::*,
	},
};

use sp_core::{
	crypto::{ByteArray, KeyTypeId},
	H160, H256, U256,
};
use sp_runtime::{
	traits::{
		IdentifyAccount,
		Verify
	},
	Perbill
};
use frame_support::{
	weights::{
		constants::WEIGHT_REF_TIME_PER_MILLIS,
	}
};

use fp_account::EthereumSignature;
use fp_evm::weight_per_gas;
use pallet_evm::{
	Account as EVMAccount, EnsureAccountId20, FeeCalculator, IdentityAddressMapping, Runner,
};

mod precompiles;
use precompiles::FrontierPrecompiles;

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// We allow for 2000ms of compute with a 6 second average block time.
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
pub const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
	WEIGHT_MILLISECS_PER_BLOCK * WEIGHT_REF_TIME_PER_MILLIS,
	u64::MAX,
);
pub const MAXIMUM_BLOCK_LENGTH: u32 = 5 * 1024 * 1024;


const BLOCK_GAS_LIMIT: u64 = 75_000_000;
const MAX_POV_SIZE: u64 = 5 * 1024 * 1024;

#[runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("minimal-template-runtime"),
	impl_name: create_runtime_str!("minimal-template-runtime"),
	authoring_version: 1,
	spec_version: 0,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	state_version: 1,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = EthereumSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

construct_runtime!(
	pub enum Runtime {
		System: frame_system,
		Timestamp: pallet_timestamp,

		Balances: pallet_balances,
		Sudo: pallet_sudo,
		TransactionPayment: pallet_transaction_payment,

		// EVM
		EVM: pallet_evm,
		Ethereum: pallet_ethereum,

		// our local pallet
		Template: pallet_minimal_template,
	}
);

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
	type Block = Block;
	type Version = Version;
	type BlockHashCount = ConstU32<1024>;
	type AccountData = pallet_balances::AccountData<<Runtime as pallet_balances::Config>::Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Runtime {
	type AccountStore = System;
}

#[derive_impl(pallet_sudo::config_preludes::TestDefaultConfig)]
impl pallet_sudo::Config for Runtime {}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Runtime {}

#[derive_impl(pallet_transaction_payment::config_preludes::TestDefaultConfig)]
impl pallet_transaction_payment::Config for Runtime {
	type OnChargeTransaction = pallet_transaction_payment::CurrencyAdapter<Balances, ()>;
	type WeightToFee = NoFee<<Self as pallet_balances::Config>::Balance>;
	type LengthToFee = FixedFee<1, <Self as pallet_balances::Config>::Balance>;
}

impl pallet_minimal_template::Config for Runtime {}

type Block = frame::runtime::types_common::BlockOf<Runtime, SignedExtra>;
type Header = HeaderFor<Runtime>;

type RuntimeExecutive =
	Executive<Runtime, Block, frame_system::ChainContext<Runtime>, Runtime, AllPalletsWithSystem>;

use pallet_transaction_payment::{FeeDetails, RuntimeDispatchInfo};

parameter_types! {
	pub BlockGasLimit: U256 = U256::from(BLOCK_GAS_LIMIT);
	pub const GasLimitPovSizeRatio: u64 = BLOCK_GAS_LIMIT.saturating_div(MAX_POV_SIZE);
	pub PrecompilesValue: FrontierPrecompiles<Runtime> = FrontierPrecompiles::<_>::new();
	pub WeightPerGas: Weight = Weight::from_parts(weight_per_gas(BLOCK_GAS_LIMIT, NORMAL_DISPATCH_RATIO, WEIGHT_MILLISECS_PER_BLOCK), 0);
	pub SuicideQuickClearLimit: u32 = 0;
}

// EVM Support
impl pallet_evm::Config for Runtime {
		/// Calculator for current gas price.
		type FeeCalculator = ();

		/// Maps Ethereum gas to Substrate weight.
		type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;

		/// Weight corresponding to a gas unit.
		type WeightPerGas = WeightPerGas;

		/// Block number to block hash.
		type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;

		/// Allow the origin to call on behalf of given address.
		type CallOrigin = EnsureAccountId20;
		/// Allow the origin to withdraw on behalf of given address.
		type WithdrawOrigin = EnsureAccountId20;

		/// Mapping from address to account id.
		type AddressMapping = IdentityAddressMapping;
		/// Currency type for withdraw and balance storage.
		type Currency = Balances;

		/// The overarching event type.
		type RuntimeEvent = RuntimeEvent;
		/// Precompiles associated with this EVM engine.
		type PrecompilesType = FrontierPrecompiles<Self>;
		type PrecompilesValue = PrecompilesValue;
		/// Chain ID of EVM.
		type ChainId = ();
		/// The block gas limit. Can be a simple constant, or an adjustment algorithm in another pallet.
		type BlockGasLimit = BlockGasLimit;
		/// EVM execution runner.
		type Runner = pallet_evm::runner::stack::Runner<Self>;

		/// To handle fee deduction for EVM transactions. An example is this pallet being used by `pallet_ethereum`
		/// where the chain implementing `pallet_ethereum` should be able to configure what happens to the fees
		/// Similar to `OnChargeTransaction` of `pallet_transaction_payment`
		type OnChargeTransaction = ();

		/// Called on create calls, used to record owner
		type OnCreate = ();

		/// Find author for the current block.
		type FindAuthor = ();

		/// Gas limit Pov size ratio.
		type GasLimitPovSizeRatio = GasLimitPovSizeRatio;

		/// Define the quick clear limit of storage clearing when a contract suicides. Set to 0 to disable it.
		type SuicideQuickClearLimit = SuicideQuickClearLimit;

		/// Get the timestamp for the current block.
		type Timestamp = Timestamp;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo = pallet_evm::weights::SubstrateWeight<Self>;
}



parameter_types! {
	pub const PostBlockAndTxnHashes: PostLogContent = PostLogContent::BlockAndTxnHashes;
}

impl pallet_ethereum::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type StateRoot = pallet_ethereum::IntermediateStateRoot<Self>;
	type PostLogContent = PostBlockAndTxnHashes;
	type ExtraDataLength = ConstU32<30>;
}

impl_runtime_apis! {
	impl apis::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			RuntimeExecutive::execute_block(block)
		}

		fn initialize_block(header: &Header) -> ExtrinsicInclusionMode {
			RuntimeExecutive::initialize_block(header)
		}
	}
	impl apis::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl apis::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: ExtrinsicFor<Runtime>) -> ApplyExtrinsicResult {
			RuntimeExecutive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> HeaderFor<Runtime> {
			RuntimeExecutive::finalize_block()
		}

		fn inherent_extrinsics(data: InherentData) -> Vec<ExtrinsicFor<Runtime>> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: Block,
			data: InherentData,
		) -> CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl apis::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: ExtrinsicFor<Runtime>,
			block_hash: <Runtime as frame_system::Config>::Hash,
		) -> TransactionValidity {
			RuntimeExecutive::validate_transaction(source, tx, block_hash)
		}
	}

	impl apis::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &HeaderFor<Runtime>) {
			RuntimeExecutive::offchain_worker(header)
		}
	}

	impl apis::SessionKeys<Block> for Runtime {
		fn generate_session_keys(_seed: Option<Vec<u8>>) -> Vec<u8> {
			Default::default()
		}

		fn decode_session_keys(
			_encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, apis::KeyTypeId)>> {
			Default::default()
		}
	}

	impl apis::AccountNonceApi<Block, interface::AccountId, interface::Nonce> for Runtime {
		fn account_nonce(account: interface::AccountId) -> interface::Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		interface::Balance,
	> for Runtime {
		fn query_info(uxt: ExtrinsicFor<Runtime>, len: u32) -> RuntimeDispatchInfo<interface::Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(uxt: ExtrinsicFor<Runtime>, len: u32) -> FeeDetails<interface::Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
		fn query_weight_to_fee(weight: Weight) -> interface::Balance {
			TransactionPayment::weight_to_fee(weight)
		}
		fn query_length_to_fee(length: u32) -> interface::Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn create_default_config() -> Vec<u8> {
			create_default_config::<RuntimeGenesisConfig>()
		}

		fn build_config(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_config::<RuntimeGenesisConfig>(config)
		}
	}
}

/// Some re-exports that the node side code needs to know. Some are useful in this context as well.
///
/// Other types should preferably be private.
// TODO: this should be standardized in some way, see:
// https://github.com/paritytech/substrate/issues/10579#issuecomment-1600537558
pub mod interface {
	use super::Runtime;
	use frame::deps::frame_system;

	pub type Block = super::Block;
	pub use frame::runtime::types_common::OpaqueBlock;
	pub type AccountId = <Runtime as frame_system::Config>::AccountId;
	pub type Nonce = <Runtime as frame_system::Config>::Nonce;
	pub type Hash = <Runtime as frame_system::Config>::Hash;
	pub type Balance = <Runtime as pallet_balances::Config>::Balance;
	pub type MinimumBalance = <Runtime as pallet_balances::Config>::ExistentialDeposit;
}
