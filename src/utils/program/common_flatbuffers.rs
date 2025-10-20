use std::collections::HashMap;

use crate::instr_flatbuffers::InstrContext;
use crate::utils::INDEXED_FEATURES;
use crate::{block_generated, context_generated, instr_generated, txn_generated};
use agave_feature_set::FeatureSet;
use solana_account::{Account, AccountSharedData};
use solana_account::{ReadableAccount, WritableAccount};
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_instruction::AccountMeta;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::v0::MessageAddressTableLookup;
use solana_message::{legacy, v0, MessageHeader, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_sdk_ids::{address_lookup_table, bpf_loader_upgradeable, config, stake};
use solana_signature::Signature;
use solana_stable_layout::stable_instruction::StableInstruction;
use solana_svm::rent_calculator::RENT_EXEMPT_RENT_EPOCH;
use solana_transaction::versioned::VersionedTransaction;

/* TODO: Split these conversions out into their own utility files */
impl From<&context_generated::Pubkey> for Pubkey {
    fn from(input: &context_generated::Pubkey) -> Self {
        input.0.into()
    }
}

impl From<&Pubkey> for context_generated::Pubkey {
    fn from(input: &Pubkey) -> Self {
        context_generated::Pubkey::new(&input.to_bytes())
    }
}

impl From<&context_generated::Signature> for Signature {
    fn from(input: &context_generated::Signature) -> Self {
        input.0.into()
    }
}

impl<'a> From<&context_generated::Hash> for Hash {
    fn from(input: &context_generated::Hash) -> Self {
        input.0.into()
    }
}

impl<'a> From<&context_generated::Account<'a>> for (Pubkey, Account) {
    fn from(input: &context_generated::Account<'a>) -> (Pubkey, Account) {
        (
            Pubkey::new_from_array(input.address().0),
            Account {
                lamports: input.lamports(),
                data: input.data().bytes().to_vec(),
                owner: Pubkey::new_from_array(input.owner().0),
                executable: input.executable(),
                rent_epoch: RENT_EXEMPT_RENT_EPOCH,
            },
        )
    }
}

impl<'a> From<&context_generated::FeatureSet<'a>> for FeatureSet {
    fn from(input: &context_generated::FeatureSet<'a>) -> Self {
        let mut feature_set = FeatureSet::default();
        for id in input.features().unwrap_or_default() {
            if let Some(pubkey) = INDEXED_FEATURES.get(&id) {
                feature_set.activate(pubkey, 0);
            }
        }
        feature_set
    }
}

impl<'a> From<&context_generated::Account<'a>> for AccountSharedData {
    fn from(input: &context_generated::Account<'a>) -> Self {
        let mut account_data = AccountSharedData::default();
        account_data.set_lamports(input.lamports());
        account_data.set_data_from_slice(input.data().bytes());
        account_data.set_owner(Pubkey::new_from_array(input.owner().0));
        account_data.set_executable(input.executable());
        account_data.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);
        account_data
    }
}

impl<'a> From<&txn_generated::CompiledInstruction<'a>> for CompiledInstruction {
    fn from(value: &txn_generated::CompiledInstruction<'a>) -> Self {
        CompiledInstruction {
            program_id_index: value.program_id_index() as u8,
            accounts: value.accounts().bytes().to_vec(),
            data: value.data().bytes().to_vec(),
        }
    }
}

impl<'a> From<&txn_generated::MessageHeader<'a>> for MessageHeader {
    fn from(value: &txn_generated::MessageHeader<'a>) -> Self {
        MessageHeader {
            num_required_signatures: std::cmp::max(1, value.num_required_signatures() as u8),
            num_readonly_signed_accounts: value.num_readonly_signed_accounts() as u8,
            num_readonly_unsigned_accounts: value.num_readonly_unsigned_accounts() as u8,
        }
    }
}

impl<'a> From<&txn_generated::AddressLookupTable<'a>> for MessageAddressTableLookup {
    fn from(value: &txn_generated::AddressLookupTable<'a>) -> Self {
        MessageAddressTableLookup {
            account_key: Pubkey::new_from_array(value.account_key().0),
            writable_indexes: value.writable_indexes().bytes().to_vec(),
            readonly_indexes: value.readonly_indexes().bytes().to_vec(),
        }
    }
}

impl<'a> From<block_generated::Inflation<'a>> for Inflation {
    fn from(input: block_generated::Inflation<'a>) -> Self {
        let mut inflation = Inflation::default();
        inflation.initial = input.initial();
        inflation.terminal = input.terminal();
        inflation.taper = input.taper();
        inflation.foundation = input.foundation();
        inflation.foundation_term = input.foundation_term();
        inflation
    }
}

impl<'a> From<&instr_generated::InstrContext<'a>> for InstrContext {
    fn from(input: &instr_generated::InstrContext<'a>) -> Self {
        let program_id = Pubkey::from(input.program_id());
        let feature_set = if let Some(features) = input.features() {
            FeatureSet::from(&features)
        } else {
            FeatureSet::default()
        };

        let accounts: Vec<(Pubkey, Account)> = input
            .account_states()
            .iter()
            .map(|acct_state| (&acct_state).into())
            .collect::<Vec<_>>();

        let instruction_accounts = input
            .instr_accounts()
            .iter()
            .map(|instr_account| {
                /* If the account index is out of bounds, this should be caught and
                fixed up in the mutator */
                AccountMeta {
                    pubkey: accounts[instr_account.index() as usize].0,
                    is_signer: instr_account.is_signer(),
                    is_writable: instr_account.is_writable(),
                }
            })
            .collect::<Vec<_>>();

        let instruction = StableInstruction {
            accounts: instruction_accounts.into(),
            data: input.instr_data().bytes().to_vec().into(),
            program_id,
        };

        Self {
            feature_set,
            accounts,
            instruction,
            cu_avail: input.cu_avail(),
        }
    }
}

pub fn build_output_account<'a>(
    address: &Pubkey,
    account: &AccountSharedData,
    builder: &mut flatbuffers::FlatBufferBuilder<'a>,
) -> flatbuffers::WIPOffset<context_generated::Account<'a>> {
    let data = builder.create_vector(account.data());
    context_generated::Account::create(
        builder,
        &context_generated::AccountArgs {
            address: Some(&address.into()),
            lamports: account.lamports(),
            data: Some(data),
            executable: account.executable(),
            owner: Some(&account.owner().into()),
        },
    )
}

/* Helper function to deserialize sysvar data. Panics if the sysvar is not found
or cannot be deserialized. */
pub fn get_sysvar<T: serde::de::DeserializeOwned + Default>(
    accounts: &HashMap<Pubkey, context_generated::Account>,
    sysvar_id: &Pubkey,
) -> T {
    accounts
        .get(sysvar_id)
        .and_then(|account| bincode::deserialize(&account.data().bytes()).ok())
        .unwrap()
}

pub fn get_dummy_bpf_native_programs() -> Vec<(Pubkey, AccountSharedData)> {
    vec![
        (
            address_lookup_table::id(),
            AccountSharedData::new(1u64, 0, &bpf_loader_upgradeable::id()),
        ),
        (
            config::id(),
            AccountSharedData::new(1u64, 0, &bpf_loader_upgradeable::id()),
        ),
        (
            stake::id(),
            AccountSharedData::new(1u64, 0, &bpf_loader_upgradeable::id()),
        ),
    ]
}

pub fn build_versioned_transaction(
    input_message: &txn_generated::TransactionMessage,
) -> VersionedTransaction {
    let header = MessageHeader::from(&input_message.header());
    let account_keys = input_message
        .account_keys()
        .iter()
        .map(|key| Pubkey::new_from_array(key.0))
        .collect::<Vec<Pubkey>>();
    let recent_blockhash = Hash::new_from_array(input_message.recent_blockhash().0);
    let instructions = input_message
        .instructions()
        .iter()
        .map(|instr| CompiledInstruction::from(&instr))
        .collect::<Vec<CompiledInstruction>>();

    let message = match input_message.is_legacy() {
        true => VersionedMessage::Legacy(legacy::Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        }),
        false => {
            let address_table_lookups = input_message
                .address_lookup_tables()
                .iter()
                .map(|lookup_table| MessageAddressTableLookup::from(&lookup_table))
                .collect::<Vec<MessageAddressTableLookup>>();

            VersionedMessage::V0(v0::Message {
                header,
                account_keys,
                recent_blockhash,
                instructions,
                address_table_lookups,
            })
        }
    };
    let mut signatures = input_message
        .signatures()
        .iter()
        .map(|item| item.into())
        .collect::<Vec<Signature>>();
    if signatures.is_empty() {
        // Default: valid txn with 1 empty signature (this keeps tests simpler)
        signatures.push(Signature::default());
    }

    VersionedTransaction {
        message,
        signatures,
    }
}
