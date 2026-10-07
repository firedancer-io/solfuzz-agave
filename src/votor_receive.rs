//! Differential Alpenglow receive harness: datagrams run in order through sigverify and the consensus pool.

use agave_bls_sigverify::{
    bls_sigverifier::{SigVerifier, SigVerifierChannels, SigVerifierContext},
    generated_cert_types::GeneratedCertTypes,
};
use agave_votor::{consensus_pool::ConsensusPool, event::VotorEvent, PoolMessage, PoolVote};
use agave_votor_messages::{
    certificate::CertificateType,
    consensus_message::{Block, BLS_KEYPAIR_DERIVE_SEED},
    migration::MigrationStatus,
    sig_verified_messages::SigVerifiedBatch,
};
use agave_votor_transport::endpoint::{stub_ban_channel_for_tests, BanCommand, Datagram};
use crossbeam_channel::{bounded, Receiver};
use prost::Message;
use protosol::protos::{VotorCertKind, VotorReceiveCert, VotorReceiveContext, VotorReceiveEffects};
use solana_bls_signatures::Keypair as BLSKeypair;
use solana_clock::Slot;
use solana_epoch_schedule::EpochSchedule;
use solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo};
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_ledger::leader_schedule_cache::LeaderScheduleCache;
use solana_net_utils::SocketAddrSpace;
use solana_pubkey::Pubkey;
use solana_runtime::{
    bank::{Bank, SlotLeader},
    bank_forks::{BankForks, SharableBanks},
    genesis_utils::{create_genesis_config_with_alpenglow_vote_accounts, ValidatorVoteKeypairs},
};
use solana_signer::Signer;
use solana_svm::conformance::fd_hash::fd_hash_or_zero;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ffi::c_int;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

/// Default stakes for the tests, distinct so rank follows stake.
pub const VOTOR_VALIDATOR_STAKES: [u64; 4] = [4_000, 3_000, 2_000, 1_000];

/// Most validators an input may stake; validator i's keys are fixed.
pub const VOTOR_VALIDATOR_MAX: usize = 16;

/// Validator i's keypairs from fixed seeds; the BLS key derives from the vote keypair.
fn validator_keypairs(i: usize) -> ValidatorVoteKeypairs {
    let key = |tag: u8| Keypair::new_from_array([tag.wrapping_add(i as u8); 32]);
    ValidatorVoteKeypairs::new(key(0x10), key(0x40), key(0x70))
}

/// The BLS keypair of validator i, for fuzzers that sign votes.
pub fn votor_validator_bls_keypair(i: usize) -> BLSKeypair {
    BLSKeypair::derive_from_signer(&validator_keypairs(i).vote_keypair, BLS_KEYPAIR_DERIVE_SEED)
        .unwrap()
}

/// # Safety
/// Pointers must be valid for the given sizes (solfuzz C ABI).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sol_compat_votor_receive_v1(
    out_ptr: *mut u8,
    out_psz: *mut u64,
    in_ptr: *mut u8,
    in_sz: u64,
) -> c_int {
    if in_ptr.is_null() || in_sz == 0 {
        return 0;
    }
    let in_slice = unsafe { std::slice::from_raw_parts(in_ptr, in_sz as usize) };
    let Ok(context) = VotorReceiveContext::decode(in_slice) else {
        return 0;
    };
    let Some(effects) = execute_votor_receive(&context) else {
        return 0;
    };

    let out_psz_val = unsafe { *out_psz } as usize;
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_psz_val) };
    let out_vec = effects.encode_to_vec();
    if out_vec.len() > out_slice.len() {
        return 0;
    }
    out_slice[..out_vec.len()].copy_from_slice(&out_vec);
    unsafe {
        *out_psz = out_vec.len() as u64;
    }
    1
}

/// Root slot of the harness's bank, inside epoch 0.
pub const VOTOR_ROOT_SLOT: Slot = 100;

/// Root bank for one stake set, cached since a genesis bank is most of an input's cost.
struct VotorBank {
    sharable_banks: SharableBanks,
    leader_schedule: Arc<LeaderScheduleCache>,
    _bank_forks: Arc<RwLock<BankForks>>,
}

impl VotorBank {
    fn new(stakes: &[u64]) -> Self {
        let keypairs: Vec<ValidatorVoteKeypairs> =
            (0..stakes.len()).map(validator_keypairs).collect();
        let mut genesis = create_genesis_config_with_alpenglow_vote_accounts(
            1_000_000_000,
            &keypairs,
            stakes.to_vec(),
        );
        genesis.genesis_config.epoch_schedule = EpochSchedule::without_warmup();

        /* The warped bank needs its parent in a BankForks for the program cache */
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis.genesis_config));
        let genesis_bank = bank_forks.read().unwrap().root_bank();
        let root = Bank::warp_from_parent(genesis_bank, SlotLeader::default(), VOTOR_ROOT_SLOT);
        bank_forks.write().unwrap().insert(root);
        bank_forks
            .write()
            .unwrap()
            .set_root(VOTOR_ROOT_SLOT, None, None);
        let sharable_banks = bank_forks.read().unwrap().sharable_banks();
        let leader_schedule = Arc::new(LeaderScheduleCache::new_from_bank(&sharable_banks.root()));
        Self {
            sharable_banks,
            leader_schedule,
            _bank_forks: bank_forks,
        }
    }
}

/// Banks kept per thread, most recently used last.
const VOTOR_BANK_CACHE_MAX: usize = 32;

/// Per-thread state shared by inputs: identities, cached banks, cluster info.
struct VotorWorld {
    identities: Vec<Pubkey>,
    banks: RefCell<Vec<(Vec<u64>, Arc<VotorBank>)>>,
    /* Cluster info for the last shred version seen */
    cluster_info: RefCell<Option<Arc<ClusterInfo>>>,
}

thread_local! {
    static VOTOR_WORLD: VotorWorld = VotorWorld::new();
}

impl VotorWorld {
    fn new() -> Self {
        let identities = (0..VOTOR_VALIDATOR_MAX)
            .map(|i| validator_keypairs(i).node_keypair.pubkey())
            .collect();
        Self {
            identities,
            banks: RefCell::new(Vec::new()),
            cluster_info: RefCell::new(None),
        }
    }

    fn bank(&self, stakes: &[u64]) -> Arc<VotorBank> {
        let mut banks = self.banks.borrow_mut();
        if let Some(i) = banks.iter().position(|(s, _)| s == stakes) {
            let entry = banks.remove(i);
            let bank = entry.1.clone();
            banks.push(entry);
            return bank;
        }
        let bank = Arc::new(VotorBank::new(stakes));
        if banks.len() == VOTOR_BANK_CACHE_MAX {
            banks.remove(0);
        }
        banks.push((stakes.to_vec(), bank.clone()));
        bank
    }

    /// Our node is not one of the validators, so every datagram is
    /// external and own-vote handling stays out of scope. The cluster
    /// info only carries our identity and shred version.
    fn cluster_info(&self, shred_version: u16) -> Arc<ClusterInfo> {
        let mut cached = self.cluster_info.borrow_mut();
        if let Some(ci) = cached
            .as_ref()
            .filter(|ci| ci.my_shred_version() == shred_version)
        {
            return ci.clone();
        }
        let my_keypair = Keypair::new_from_array([0xEE; 32]);
        let mut contact_info = ContactInfo::new_localhost(&my_keypair.pubkey(), 0);
        contact_info.set_shred_version(shred_version);
        let ci = Arc::new(ClusterInfo::new(
            contact_info,
            Arc::new(my_keypair),
            SocketAddrSpace::Unspecified,
        ));
        *cached = Some(ci.clone());
        ci
    }
}

/// Returns None for inputs outside the harness's scope (shred version, root, stakes).
pub fn execute_votor_receive(context: &VotorReceiveContext) -> Option<VotorReceiveEffects> {
    VOTOR_WORLD.with(|world| execute_votor_receive_in(world, context))
}

fn execute_votor_receive_in(
    world: &VotorWorld,
    context: &VotorReceiveContext,
) -> Option<VotorReceiveEffects> {
    let shred_version = u16::try_from(context.shred_version).ok()?;
    let last_slot = EpochSchedule::without_warmup().get_last_slot_in_epoch(0);
    if context.root_slot != VOTOR_ROOT_SLOT || context.highest_parent_ready_slot > last_slot {
        return None;
    }
    let stakes = &context.validator_stakes;
    if stakes.is_empty()
        || stakes.len() > VOTOR_VALIDATOR_MAX
        || stakes.contains(&0)
        || stakes
            .iter()
            .try_fold(0u64, |a, s| a.checked_add(*s))
            .is_none()
    {
        return None;
    }
    let identities = &world.identities[..stakes.len()];
    let bank = world.bank(stakes);
    let sharable_banks = bank.sharable_banks.clone();
    let root_bank = sharable_banks.root();

    let cluster_info = world.cluster_info(shred_version);

    let root_block = Block {
        slot: root_bank.slot(),
        block_id: root_bank.block_id().unwrap_or_default(),
    };
    let parent_ready_slot = context
        .highest_parent_ready_slot
        .max(root_block.slot.saturating_add(1));
    let highest_parent_ready = Arc::new(RwLock::new((parent_ready_slot, root_block)));
    let migration_status = Arc::new(MigrationStatus::post_migration_status());
    let generated_cert_types = Arc::new(GeneratedCertTypes::default());

    let (ban_sender, mut ban_receiver) = stub_ban_channel_for_tests(1024);
    let (_packet_sender, packet_receiver) = bounded(1);
    let (_certificate_sender, certificate_receiver) = bounded(1);
    let (channel_to_repair, _repair_receiver) = bounded(1024);
    let (channel_to_reward, _reward_receiver) = bounded(1024);
    let (channel_to_pool, pool_receiver) = bounded(1024);
    let (channel_to_metrics, _metrics_receiver) = bounded(1024);
    let mut verifier = SigVerifier::new(
        SigVerifierContext {
            migration_status: migration_status.clone(),
            ban_sender,
            sharable_banks: sharable_banks.clone(),
            highest_parent_ready: highest_parent_ready.clone(),
            cluster_info: cluster_info.clone(),
            leader_schedule: bank.leader_schedule.clone(),
            num_threads: 1,
            generated_cert_types: generated_cert_types.clone(),
        },
        SigVerifierChannels::new(
            packet_receiver,
            certificate_receiver,
            channel_to_repair,
            channel_to_reward,
            channel_to_pool,
            channel_to_metrics,
        ),
    );
    let mut pool = ConsensusPool::new(
        cluster_info,
        &root_bank,
        generated_cert_types,
        migration_status,
        (parent_ready_slot, root_block),
    );

    let mut banned = BTreeSet::new();
    let mut results = Vec::with_capacity(context.datagrams.len());
    for datagram in &context.datagrams {
        let sender = datagram.sender as usize;
        let peer_pubkey = identities.get(sender).copied().unwrap_or_default();
        if banned.contains(&datagram.sender) {
            results.push(false);
            continue;
        }

        verifier
            .verify_and_send_inputs(
                &[Datagram {
                    peer_pubkey,
                    peer_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                    message: datagram.data.clone().into(),
                }],
                vec![],
            )
            .ok()?;

        let added = add_to_pool(&mut pool, &root_bank, &pool_receiver, &highest_parent_ready);
        results.push(added);

        while let Ok(BanCommand { peer, .. }) = ban_receiver.try_recv() {
            if let Some(idx) = identities.iter().position(|id| *id == peer) {
                banned.insert(idx as u32);
            }
        }
    }

    let mut certs: Vec<VotorReceiveCert> = pool
        .completed_certificates()
        .filter_map(|cert| votor_cert(cert.cert_type, &cert.bitmap, &cert.signature.0))
        .collect();
    certs.sort_by(|a, b| (a.kind, a.slot, &a.block_id).cmp(&(b.kind, b.slot, &b.block_id)));

    Some(VotorReceiveEffects {
        results,
        certs,
        banned: banned.into_iter().collect(),
    })
}

/// Adds sigverify's output to the pool and advances parent ready; returns whether anything was added.
fn add_to_pool(
    pool: &mut ConsensusPool,
    root_bank: &Bank,
    pool_receiver: &Receiver<SigVerifiedBatch>,
    highest_parent_ready: &RwLock<(u64, Block)>,
) -> bool {
    let mut added = false;
    let mut events = Vec::new();
    while let Ok(batch) = pool_receiver.try_recv() {
        added |= !batch.is_empty();
        let msg = match batch {
            SigVerifiedBatch::Votes(votes) => {
                PoolMessage::Votes(votes.into_iter().map(PoolVote::External).collect())
            }
            SigVerifiedBatch::Certificates(certs) => PoolMessage::Certificates(certs),
        };
        pool.add_pool_msg(root_bank, msg, &mut events);
    }
    for event in events {
        if let VotorEvent::ParentReady { slot, parent_block } = event {
            let mut highest = highest_parent_ready.write().unwrap();
            if slot > highest.0 {
                *highest = (slot, parent_block);
            }
        }
    }
    added
}

/// Converts a certificate to VotorReceiveCert with base2 bitmaps; genesis certs are skipped.
fn votor_cert(
    cert_type: CertificateType,
    bitmap: &[u8],
    signature: &[u8],
) -> Option<VotorReceiveCert> {
    let (kind, block_id) = match cert_type {
        CertificateType::Finalize(_) => (VotorCertKind::Final, None),
        CertificateType::FinalizeFast(b) => (VotorCertKind::FastFinal, Some(b.block_id)),
        CertificateType::Notarize(b) => (VotorCertKind::Notar, Some(b.block_id)),
        CertificateType::NotarizeFallback(b) => (VotorCertKind::NotarFallback, Some(b.block_id)),
        CertificateType::Skip(_) => (VotorCertKind::Skip, None),
        CertificateType::Genesis(_) => return None,
    };
    let (primary_bitmap, fallback_bitmap) =
        match solana_signer_store::decode(bitmap, VOTOR_BITMAP_BITS_MAX).ok()? {
            solana_signer_store::Decoded::Base2(bits) => (base2_bitmap(bits.iter_ones()), vec![]),
            solana_signer_store::Decoded::Base3(primary, fallback) => (
                base2_bitmap(primary.iter_ones()),
                base2_bitmap(fallback.iter_ones()),
            ),
        };
    Some(VotorReceiveCert {
        kind: kind as i32,
        slot: cert_type.slot(),
        block_id: block_id.unwrap_or(Hash::default()).as_ref().to_vec(),
        primary_bitmap,
        fallback_bitmap,
        signature_hash: fd_hash_or_zero(signature),
    })
}

const VOTOR_BITMAP_BITS_MAX: usize = 2000;

/// Base2 bitmap sized to the highest signer, so both sides agree.
fn base2_bitmap(ones: impl Iterator<Item = usize>) -> Vec<u8> {
    let ones: Vec<usize> = ones.collect();
    let len = ones.last().map_or(0, |i| i + 1);
    let mut out = vec![0u8];
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.resize(3 + len.div_ceil(8), 0);
    for i in ones {
        out[3 + i / 8] |= 1 << (i % 8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use agave_votor_messages::{
        consensus_message::VoteMessage,
        vote::Vote,
        wire::{get_vote_payload_to_sign, VersionedWireConsensusMessage},
    };
    use protosol::protos::VotorDatagram;
    use std::num::NonZero;

    const SHRED_VERSION: u16 = 42;
    /* First slot of the leader window after the root */
    const SLOT: u64 = VOTOR_ROOT_SLOT + 4;

    fn signed(sender: u32, vote: Vote) -> VotorDatagram {
        let kp = votor_validator_bls_keypair(sender as usize);
        let sig = kp.sign(&get_vote_payload_to_sign(vote, SHRED_VERSION));
        let msg = VoteMessage {
            vote,
            signature: sig.into(),
            rank: 0,
            stake: NonZero::new(1).unwrap(),
        };
        VotorDatagram {
            sender,
            data: wincode::serialize(&VersionedWireConsensusMessage::new_from_vote(
                msg,
                SHRED_VERSION,
            ))
            .unwrap(),
        }
    }

    fn run(datagrams: Vec<VotorDatagram>) -> VotorReceiveEffects {
        execute_votor_receive(&VotorReceiveContext {
            datagrams,
            root_slot: VOTOR_ROOT_SLOT,
            shred_version: SHRED_VERSION as u32,
            highest_parent_ready_slot: 0,
            validator_stakes: VOTOR_VALIDATOR_STAKES.to_vec(),
        })
        .unwrap()
    }

    fn notar(slot: u64) -> Vote {
        Vote::new_notarization_vote(Block {
            slot,
            block_id: Hash::new_from_array([7; 32]),
        })
    }

    fn kinds(effects: &VotorReceiveEffects) -> Vec<i32> {
        effects.certs.iter().map(|c| c.kind).collect()
    }

    #[test]
    fn final_certs_depend_on_arrival_order() {
        /* 0,1,2 crosses 60% then 80% (Notar then FastFinal); 2,1,0 jumps 50% to 90% (FastFinal only) */
        let forward = run((0..3).map(|i| signed(i, notar(SLOT))).collect());
        let reverse = run((0..3).rev().map(|i| signed(i, notar(SLOT))).collect());
        assert_eq!(forward.results, vec![true; 3]);
        assert_eq!(reverse.results, vec![true; 3]);
        assert_eq!(
            kinds(&forward),
            vec![VotorCertKind::FastFinal as i32, VotorCertKind::Notar as i32]
        );
        assert_eq!(kinds(&reverse), vec![VotorCertKind::FastFinal as i32]);
        assert_eq!(forward.certs[0], reverse.certs[0]);
        assert!(forward.banned.is_empty() && reverse.banned.is_empty());
    }

    #[test]
    fn below_quorum_forms_no_cert() {
        /* validators 2,3 hold 3000 of 10000 stake */
        let effects = run((2..4).map(|i| signed(i, notar(SLOT))).collect());
        assert_eq!(effects.results, vec![true; 2]);
        assert!(effects.certs.is_empty());
    }

    #[test]
    fn wrong_shred_version_rejected_without_ban() {
        let mut dg = signed(0, notar(SLOT));
        let n = dg.data.len();
        dg.data[n - 2] ^= 1;
        let effects = run(vec![dg]);
        assert_eq!(effects.results, vec![false]);
        assert!(effects.banned.is_empty());
    }

    #[test]
    fn bad_signature_bans_and_drops_later_votes() {
        /* signed by validator 1's key, sent as validator 0 */
        let mut bad = signed(1, notar(SLOT));
        bad.sender = 0;
        let effects = run(vec![bad, signed(0, Vote::new_skip_vote(SLOT + 1))]);
        assert_eq!(effects.results, vec![false, false]);
        assert_eq!(effects.banned, vec![0]);
    }

    #[test]
    fn sixteen_validators_rank_by_stake() {
        /* Validator i stakes i+1; the 11 largest hold 126 of 136 (93%), past FastFinal's 80% */
        let stakes: Vec<u64> = (1..=16).collect();
        let effects = execute_votor_receive(&VotorReceiveContext {
            datagrams: (5..16).map(|i| signed(i, notar(SLOT))).collect(),
            root_slot: VOTOR_ROOT_SLOT,
            shred_version: SHRED_VERSION as u32,
            highest_parent_ready_slot: 0,
            validator_stakes: stakes,
        })
        .unwrap();
        assert_eq!(effects.results, vec![true; 11]);
        assert!(effects
            .certs
            .iter()
            .any(|c| c.kind == VotorCertKind::FastFinal as i32));
    }

    #[test]
    fn unknown_sender_rejected() {
        let mut dg = signed(0, notar(SLOT));
        dg.sender = 99;
        let effects = run(vec![dg]);
        assert_eq!(effects.results, vec![false]);
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    #[test]
    #[ignore]
    fn per_input_time() {
        let ctx = VotorReceiveContext {
            datagrams: vec![],
            root_slot: VOTOR_ROOT_SLOT,
            shred_version: 42,
            highest_parent_ready_slot: 0,
            validator_stakes: VOTOR_VALIDATOR_STAKES.to_vec(),
        };
        execute_votor_receive(&ctx).unwrap();
        let n = 200;
        let t = std::time::Instant::now();
        for _ in 0..n {
            execute_votor_receive(&ctx).unwrap();
        }
        eprintln!("per input: {:?}", t.elapsed() / n);
    }
}
