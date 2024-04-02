//! A shell pallet built with [`frame`].

#![cfg_attr(not(feature = "std"), no_std)]

use frame::prelude::*;

// Re-export all pallet parts, this is needed to properly import the pallet into the runtime.
pub use pallet::*;

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use super::*;

	/// The in-code storage version.
	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	#[pallet::config]
	pub trait Config<I: 'static = ()>: frame_system::Config {
		/// Because we want to allow for different types, we use a generic associated type.
		type ValueType: Parameter + Encode + Decode + Default + Copy;
		type RuntimeEvent: From<Event<Self, I>>
			+ IsType<<Self as frame_system::Config>::RuntimeEvent>;
	}

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T, I = ()>(_);

	#[pallet::storage]
	pub(super) type Value<T: Config<I>, I: 'static = ()> = StorageValue<_, T::ValueType, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config<I>, I: 'static = ()> {
			SetValue(T::ValueType),
	}

	#[pallet::call]
	impl<T: Config<I>, I: 'static> Pallet<T, I> {

		#[pallet::call_index(0)]
		#[pallet::weight(100)]
		pub fn set_value(origin: OriginFor<T>, value: T::ValueType) -> DispatchResult {
			ensure_signed(origin)?;

			Value::<T, I>::put(&value);

			Self::deposit_event(Event::SetValue(value));
			Ok(())
		}
	}

	impl<T: Config<I>, I: 'static> Pallet<T, I> {
		/// Return the extra "sid-car" data for `id`/`who`, or `None` if the account doesn't exist.
		pub fn get_value() -> T::ValueType {
			Value::<T, I>::get()
		}
	}
}
