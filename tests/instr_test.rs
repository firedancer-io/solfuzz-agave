use protosol::protos;
use solana_clock::Clock;
use solana_epoch_schedule::EpochSchedule;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sdk_ids::native_loader;
#[allow(deprecated)]
use solana_sysvar::recent_blockhashes::RecentBlockhashes;
use solana_sysvar::SysvarSerialize;
use solfuzz_agave::instr::execute_instr;

fn create_sysvar_account<T: SysvarSerialize>(id: &Pubkey, sysvar: T) -> protos::AcctState {
    protos::AcctState {
        address: id.to_bytes().to_vec(),
        owner: solana_sdk_ids::sysvar::id().to_bytes().to_vec(),
        lamports: 1,
        data: bincode::serialize(&sysvar).unwrap(),
        executable: false,
    }
}

fn make_sysvar_accounts() -> Vec<protos::AcctState> {
    vec![
        create_sysvar_account(&solana_sysvar::clock::id(), Clock::default()),
        create_sysvar_account(&solana_sysvar::rent::id(), Rent::default()),
        create_sysvar_account(
            &solana_sysvar::epoch_schedule::id(),
            EpochSchedule::default(),
        ),
        #[allow(deprecated)]
        create_sysvar_account(
            &solana_sysvar::recent_blockhashes::id(),
            RecentBlockhashes::default(),
        ),
    ]
}

fn with_sysvars(mut v: Vec<protos::AcctState>) -> Vec<protos::AcctState> {
    v.extend(make_sysvar_accounts());
    v
}

#[test]
fn test_system_program_exec() {
    let native_loader_id = native_loader::id().to_bytes().to_vec();

    // Ensure that a basic account transfer works
    let input = protos::InstrContext {
        program_id: vec![0u8; 32],
        accounts: with_sysvars(vec![
            protos::AcctState {
                address: vec![1u8; 32],
                owner: vec![0u8; 32],
                lamports: 1000,
                data: vec![],
                executable: false,
            },
            protos::AcctState {
                address: vec![2u8; 32],
                owner: vec![0u8; 32],
                lamports: 0,
                data: vec![],
                executable: false,
            },
            protos::AcctState {
                address: vec![0u8; 32],
                owner: native_loader_id.clone(),
                lamports: 10000000,
                data: b"Solana Program".to_vec(),
                executable: true,
            },
        ]),
        instr_accounts: vec![
            protos::InstrAcct {
                index: 0,
                is_signer: true,
                is_writable: true,
            },
            protos::InstrAcct {
                index: 1,
                is_signer: false,
                is_writable: true,
            },
        ],
        data: vec![
            // Transfer
            0x02, 0x00, 0x00, 0x00, // Lamports
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        cu_avail: 10000u64,
        features: None,
    };
    let output = execute_instr(input);
    assert_eq!(
        output,
        Some(protos::InstrEffects {
            result: 0,
            custom_err: 0,
            modified_accounts: with_sysvars(vec![
                protos::AcctState {
                    address: vec![1u8; 32],
                    owner: vec![0u8; 32],
                    lamports: 999,
                    data: vec![],
                    executable: false,
                },
                protos::AcctState {
                    address: vec![2u8; 32],
                    owner: vec![0u8; 32],
                    lamports: 1,
                    data: vec![],
                    executable: false,
                },
                protos::AcctState {
                    address: vec![0u8; 32],
                    owner: native_loader_id.clone(),
                    lamports: 10000000,
                    data: b"Solana Program".to_vec(),
                    executable: true,
                },
            ]),
            cu_avail: 9850u64,
            return_data: vec![],
        })
    );
}
