use frame::deps::frame_support;
use frame::deps::frame_system;
use frame::prelude::inject_runtime_type;


pub struct OpmChainDefaultConfig<T, V>;

type Block<T, V> = frame::runtime::types_common::BlockOf<T, V>;

#[frame_support::register_default_impl(OpmChainDefaultConfig<T, V>)]
impl frame_system::DefaultConfig for OpmChainDefaultConfig<T, V> {
	type Block = Block<T, V>;
	type BlockHashCount = ConstU32<1024>;

  /// The default type for storing how many extrinsics an account has signed.
  type Nonce = u32;

  /// The default type for hashing blocks and tries.
  type Hash = sp_core::hash::H256;

  /// The default hashing algorithm used.
  type Hashing = sp_runtime::traits::BlakeTwo256;

  /// The default identifier used to distinguish between accounts.
  type AccountId = sp_runtime::AccountId32;

  /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
  type Lookup = sp_runtime::traits::AccountIdLookup<Self::AccountId, ()>;

  /// The maximum number of consumers allowed on a single account. Using 128 as default.
  type MaxConsumers = frame_support::traits::ConstU32<128>;

  /// The default data to be stored in an account.
  type AccountData = frame_system::AccountInfo<Self::Nonce, ()>;

  /// What to do if a new account is created.
  type OnNewAccount = ();

  /// What to do if an account is fully reaped from the system.
  type OnKilledAccount = ();

  /// Weight information for the extrinsics of this pallet.
  type SystemWeightInfo = ();

  /// This is used as an identifier of the chain.
  type SS58Prefix = ();

  /// Version of the runtime.
  type Version = ();

  /// Block & extrinsics weights: base values and limits.
  type BlockWeights = ();

  /// The maximum length of a block (in bytes).
  type BlockLength = ();

  /// The weight of database operations that the runtime can invoke.
  type DbWeight = ();

  /// The ubiquitous event type injected by `construct_runtime!`.
  #[inject_runtime_type]
  type RuntimeEvent = ();

  /// The ubiquitous origin type injected by `construct_runtime!`.
  #[inject_runtime_type]
  type RuntimeOrigin = ();

  /// The aggregated dispatch type available for extrinsics, injected by
  /// `construct_runtime!`.
  #[inject_runtime_type]
  type RuntimeCall = ();

  /// The aggregated Task type, injected by `construct_runtime!`.
  #[inject_runtime_type]
  type RuntimeTask = ();

  /// Converts a module to the index of the module, injected by `construct_runtime!`.
  #[inject_runtime_type]
  type PalletInfo = ();

  /// The basic call filter to use in dispatchable. Supports everything as the default.
  type BaseCallFilter = frame_support::traits::Everything;

  /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
  /// Using 256 as default.
  type BlockHashCount = frame_support::traits::ConstU32<256>;

  /// The set code logic, just the default since we're not a parachain.
  type OnSetCode = ();
  type SingleBlockMigrations = ();
  type MultiBlockMigrator = ();
  type PreInherents = ();
  type PostInherents = ();
  type PostTransactions = ();
}
