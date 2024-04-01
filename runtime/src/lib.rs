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
		traits::Everything,
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

use frame_support::weights::{constants::WEIGHT_REF_TIME_PER_MILLIS, IdentityFee, Weight};

// Substrate FRAME
#[cfg(feature = "with-paritydb-weights")]
use frame_support::weights::constants::ParityDbWeight as RuntimeDbWeight;
#[cfg(feature = "with-rocksdb-weights")]
use frame_support::weights::constants::RocksDbWeight as RuntimeDbWeight;

use sp_runtime::{generic, traits::BlakeTwo256, Perbill};

/// Type of block number.
pub type BlockNumber = u32;

pub mod opaque {
	use super::*;

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	/// Opaque block header type.
	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	/// Opaque block type.
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;
}

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

		// our local pallet
		Template: pallet_minimal_template,
	}
);

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// We allow for 2000ms of compute with a 6 second average block time.
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
pub const MAXIMUM_BLOCK_WEIGHT: Weight =
	Weight::from_parts(WEIGHT_MILLISECS_PER_BLOCK * WEIGHT_REF_TIME_PER_MILLIS, u64::MAX);
pub const MAXIMUM_BLOCK_LENGTH: u32 = 5 * 1024 * 1024;

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
	::with_sensible_defaults(MAXIMUM_BLOCK_WEIGHT, NORMAL_DISPATCH_RATIO);
	pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
	::max_with_normal_ratio(MAXIMUM_BLOCK_LENGTH, NORMAL_DISPATCH_RATIO);
	pub const SS58Prefix: u8 = 42;
}

impl frame_system::Config for Runtime {
	/// The default type for storing how many extrinsics an account has signed.
	type Nonce = u32;

	type Block = Block;

	/// The default type for hashing blocks and tries.
	type Hash = sp_core::hash::H256;

	/// The default hashing algorithm used.
	type Hashing = sp_runtime::traits::BlakeTwo256;

	/// The default identifier used to distinguish between accounts.
	type AccountId = sp_runtime::AccountId32;

	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = sp_runtime::traits::AccountIdLookup<Self::AccountId, ()>;

	/// The maximum number of consumers allowed on a single account. Using 128 as default.
	type MaxConsumers = ConstU32<128>;

	/// The default data to be stored in an account.
	type AccountData = pallet_balances::AccountData<<Runtime as pallet_balances::Config>::Balance>;

	/// What to do if a new account is created.
	type OnNewAccount = ();

	/// What to do if an account is fully reaped from the system.
	type OnKilledAccount = ();

	/// Weight information for the extrinsics of this pallet.
	type SystemWeightInfo = ();

	/// This is used as an identifier of the chain.
	type SS58Prefix = SS58Prefix;

	/// Version of the runtime.
	type Version = Version;

	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = BlockWeights;

	/// The maximum length of a block (in bytes).
	type BlockLength = BlockLength;

	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RuntimeDbWeight;

	type RuntimeEvent = RuntimeEvent;

	/// The ubiquitous origin type injected by `construct_runtime!`.
	type RuntimeOrigin = RuntimeOrigin;

	/// The aggregated dispatch type available for extrinsics, injected by
	/// `construct_runtime!`.
	type RuntimeCall = RuntimeCall;

	/// The aggregated Task type, injected by `construct_runtime!`.
	type RuntimeTask = RuntimeTask;

	/// Converts a module to the index of the module, injected by `construct_runtime!`.
	type PalletInfo = PalletInfo;

	/// The basic call filter to use in dispatchable. Supports everything as the default.
	type BaseCallFilter = Everything;

	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	/// Using 256 as default.
	type BlockHashCount = ConstU32<256>;

	/// The set code logic, just the default since we're not a parachain.
	type OnSetCode = ();
	type SingleBlockMigrations = ();
	type MultiBlockMigrator = ();
	type PreInherents = ();
	type PostInherents = ();
	type PostTransactions = ();
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

#[cfg(test)]
mod tests {
	use super::{interface, Balances, Runtime, RuntimeOrigin, System};
	use sp_io;
	use sp_runtime::BuildStorage;

	use sp_core::{crypto::DEV_PHRASE, sr25519, Pair};
	use sp_runtime::AccountId32;

	use sp_runtime::MultiAddress::Id;

	fn get_account_id(name: &str) -> AccountId32 {
		let pair = sr25519::Pair::from_string(&format!("{}//{}", DEV_PHRASE, name), None).unwrap();
		let pub_key = pair.public();
		let account_id = interface::AccountId::from(pub_key);
		account_id
	}

	// Function to set up the externalities
	pub fn new_test_ext() -> sp_io::TestExternalities {
		let mut storage =
			frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();

		// Here you must include the balances in your genesis configuration.
		pallet_balances::GenesisConfig::<Runtime> {
			// Assuming Alice's account ID is correct and she should have some balance.
			balances: vec![(get_account_id("Alice"), 1000), (get_account_id("Bob"), 1000)],
		}
		.assimilate_storage(&mut storage)
		.unwrap();

		sp_io::TestExternalities::from(storage)
	}

	#[test]
	fn test_block_number() {
		new_test_ext().execute_with(|| {
			assert_eq!(System::block_number(), 0, "Block Number should be 0");
			System::set_block_number(5);
			assert_eq!(System::block_number(), 5, "Block Number should be 5");
		});
	}

	#[test]
	fn test_balance_transfer() {
		let ALICE: AccountId32 = get_account_id(&"Alice");
		let BOB: AccountId32 = get_account_id(&"Bob");
		new_test_ext().execute_with(|| {
			assert_eq!(Balances::usable_balance(ALICE.clone()), 1000);
			assert_eq!(Balances::usable_balance(BOB.clone()), 1000);
			let _ = Balances::transfer_keep_alive(
				RuntimeOrigin::signed(ALICE.clone()),
				Id(BOB.clone()),
				10,
			)
			.unwrap();
			assert_eq!(Balances::usable_balance(ALICE.clone()), 990);
			assert_eq!(Balances::usable_balance(BOB.clone()), 1010);
		})
	}
}
