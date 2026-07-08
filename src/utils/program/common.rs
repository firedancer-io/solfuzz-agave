use std::collections::HashMap;

use protosol::protos::{AcctState, TransactionMessage};
use solana_hash::Hash;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::v0::MessageAddressTableLookup;
use solana_message::{legacy, v0, MessageHeader, VersionedMessage};
use solana_pubkey::Pubkey;

/* Helper function to deserialize sysvar data. Panics if the sysvar is not found
or cannot be deserialized. */
pub fn get_sysvar<T: serde::de::DeserializeOwned + Default>(
    accounts: &HashMap<&[u8], &AcctState>,
    sysvar_id: &[u8],
) -> T {
    accounts
        .get(sysvar_id)
        .and_then(|account| bincode::deserialize(&account.data).ok())
        .unwrap()
}

pub fn build_versioned_message(value: &TransactionMessage) -> VersionedMessage {
    let header = if let Some(value_header) = value.header {
        MessageHeader::from(&value_header)
    } else {
        // Default: valid txn header with 1 signature (this keeps tests simpler)
        MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
        }
    };
    let account_keys = value
        .account_keys
        .iter()
        .map(|key| Pubkey::new_from_array(key.clone().try_into().unwrap()))
        .collect::<Vec<Pubkey>>();
    let recent_blockhash = if value.recent_blockhash.is_empty() {
        // Default: empty blockchash (this keeps tests simpler)
        Hash::new_from_array([0u8; 32])
    } else {
        Hash::new_from_array(value.recent_blockhash.clone().try_into().unwrap())
    };
    let instructions = value
        .instructions
        .iter()
        .map(CompiledInstruction::from)
        .collect::<Vec<CompiledInstruction>>();

    if value.is_legacy {
        let message = legacy::Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        };
        VersionedMessage::Legacy(message)
    } else {
        let address_table_lookups = value
            .address_table_lookups
            .iter()
            .map(MessageAddressTableLookup::from)
            .collect::<Vec<MessageAddressTableLookup>>();

        let message = v0::Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups,
        };

        VersionedMessage::V0(message)
    }
}
