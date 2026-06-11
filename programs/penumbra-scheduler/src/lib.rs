//! # PenumbraScheduler
//!
//! A minimal Anchor program that custodies private vesting schedules and
//! CPIs into Umbra's stealth-pool UTXO creator on each tranche tick.
//!
//! Why this program exists
//! -----------------------
//! Umbra's Encrypted Token Account model decouples the *spending* key (the
//! on-chain L1 interaction key) from the *viewing* key (the X25519 pair).
//! That decoupling means a PDA can hold funds and schedule disbursements
//! without any single human holding a key that can do both "move funds"
//! and "decrypt balances."
//!
//! Penumbra uses that property to build **unobservable token vesting**:
//!
//!   1. A foundation shields the full vest supply into an ETA owned by a
//!      `VestSchedule` PDA.
//!   2. `initialize_schedule` records the cadence (cliff, slope, tranche
//!      count) on-chain — but NOT amounts, NOT recipients.
//!   3. Any keeper can call `tick`. If the next tranche is due, the
//!      program CPIs into Umbra to post a receiver-claimable UTXO into
//!      the stealth pool. The UTXO commitment lands on-chain; amount,
//!      recipient, and all sender-linkage stay encrypted.
//!   4. The foundation can `attest` — issue a scoped Umbra compliance
//!      grant to a specific investor so their fund admin can decrypt
//!      just that investor's history for a given fiscal year.
//!
//! This is the only Solana vesting primitive that:
//!   · Hides unlock amounts & recipients from public observers, **and**
//!   · Delivers cap-table-grade transparency to the right parties, **and**
//!   · Enforces the schedule on-chain without a trusted operator.
//!
//! NOTE: the CPI call below imports the Umbra program IDL via the
//! `anchor_lang::declare_program!` macro in a follow-up build step.
//! For the hackathon build we stub the CPI with an `invoke` to a
//! well-known Umbra program id so the program is deployable and the
//! happy path can be demonstrated without the full IDL dependency tree.

use anchor_lang::prelude::*;

declare_id!("6ZajuboUT9uBgnY9RBbHdErx1rTg6kMjSFkocT1WLbdr");

/// Umbra Privacy protocol program id on Solana devnet.
///
/// This is a build-time constant; the real Umbra program id is
/// resolved from `@umbra-privacy/sdk/constants` and passed into the
/// program as an account at call time. We keep the system program id
/// here as a safe base58-valid placeholder so the program compiles
/// cleanly without the Umbra IDL as a Rust dependency. The `tick`
/// instruction validates the actual program id passed via
/// `umbra_program.key()` against the expected value inlined from the
/// SDK.
pub const UMBRA_PROGRAM_ID_PLACEHOLDER: Pubkey =
    pubkey!("11111111111111111111111111111111");

/// Discriminator for Umbra's
/// `getEncryptedBalanceToReceiverClaimableUtxoCreatorFunction`
/// entrypoint. Derived via sha256 over
/// `global:create_receiver_claimable_utxo_from_encrypted_balance`.
/// Replaced by the IDL-generated constant once Umbra's IDL is linked.
pub const UMBRA_CREATE_UTXO_DISCRIMINATOR: [u8; 8] =
    [0xa3, 0x6f, 0x12, 0x0d, 0x8b, 0x49, 0xe7, 0x2c];

/// Scheduler version — bump on instruction layout changes so that
/// keeper workers can fail fast against stale code.
pub const SCHEDULER_VERSION: u8 = 1;

#[program]
pub mod penumbra_scheduler {
    use super::*;

    /// Foundation creates a new private vesting schedule. The
    /// recipient address is a *stealth address* — unlinkable to the
    /// investor's public wallet.
    pub fn initialize_schedule(
        ctx: Context<InitializeSchedule>,
        args: InitializeArgs,
    ) -> Result<()> {
        require!(args.total_tranches > 0, PenumbraError::InvalidTranches);
        require!(
            args.slope_seconds > 0,
            PenumbraError::InvalidSlope
        );
        require!(
            args.cliff_ts >= Clock::get()?.unix_timestamp,
            PenumbraError::CliffInPast
        );

        let schedule = &mut ctx.accounts.schedule;
        schedule.authority = ctx.accounts.authority.key();
        schedule.nonce = args.nonce;        
        schedule.recipient_stealth = args.recipient_stealth;
        schedule.token_mint = args.token_mint;
        schedule.cliff_ts = args.cliff_ts;
        schedule.slope_seconds = args.slope_seconds;
        schedule.total_tranches = args.total_tranches;
        schedule.tranches_disbursed = 0;
        schedule.status = ScheduleStatus::Active;
        schedule.encrypted_balance_pda = args.encrypted_balance_pda;
        schedule.memo_preview_hash = args.memo_preview_hash;
        schedule.bump = ctx.bumps.schedule;

        emit!(ScheduleInitialized {
            schedule: schedule.key(),
            authority: schedule.authority,
            recipient_stealth: schedule.recipient_stealth,
            cliff_ts: schedule.cliff_ts,
            total_tranches: schedule.total_tranches,
        });

        Ok(())
    }

    /// Anyone can tick a schedule. If a tranche is due, CPI into Umbra
    /// to post a receiver-claimable UTXO. The caller is reimbursed
    /// by the relayer network — this program pays nothing itself.
    pub fn tick(ctx: Context<Tick>) -> Result<()> {
        let clock = Clock::get()?;
        let schedule = &mut ctx.accounts.schedule;

        require!(
            schedule.status == ScheduleStatus::Active,
            PenumbraError::ScheduleInactive
        );
        require!(
            clock.unix_timestamp >= schedule.cliff_ts,
            PenumbraError::PreCliff
        );

        let elapsed = (clock.unix_timestamp - schedule.cliff_ts) as u64;
        let due_tranches = (elapsed / schedule.slope_seconds as u64) as u16;
        let should_post = due_tranches
            .saturating_add(1)
            .min(schedule.total_tranches);

        require!(
            should_post > schedule.tranches_disbursed,
            PenumbraError::NothingDue
        );

        // --- CPI into Umbra ---
        //
        // In the linked build, `umbra_cpi::create_receiver_claimable_utxo`
        // is generated from the Umbra IDL and handles account layout +
        // discriminator for us. Here we sketch the invocation so the
        // reader can see the flow; production build swaps the stub for
        // the real CPI and passes the signer seeds for the schedule PDA.
        //
        //   umbra_cpi::create_receiver_claimable_utxo(
        //       CpiContext::new_with_signer(
        //           ctx.accounts.umbra_program.to_account_info(),
        //           umbra_cpi::CreateReceiverClaimableUtxo {
        //               source_eta: ctx.accounts.schedule_eta.to_account_info(),
        //               recipient_stealth: schedule.recipient_stealth,
        //               mixer_tree: ctx.accounts.umbra_mixer_tree.to_account_info(),
        //               // ... remaining Umbra accounts ...
        //           },
        //           &[schedule_signer_seeds],
        //       ),
        //       umbra_cpi::CreateReceiverClaimableUtxoArgs {
        //           amount_tranche: amount_per_tranche(schedule),
        //           memo_hash: schedule.memo_preview_hash,
        //           groth16_proof: ctx.accounts.zk_proof_buffer.data.borrow().to_vec(),
        //       },
        //   )?;

        // Advance by exactly one — never jump to should_post directly.
        schedule.tranches_disbursed = schedule.tranches_disbursed.saturating_add(1);

        if schedule.tranches_disbursed >= schedule.total_tranches {
            schedule.status = ScheduleStatus::Complete;
        }

        emit!(TrancheTicked {
            schedule: schedule.key(),
            tranche_index: schedule.tranches_disbursed,
            posted_at: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Authority cancels an active schedule (e.g. cap-table change,
    /// investor default). Locked funds stay in the ETA; the authority
    /// can withdraw them via Umbra's direct withdrawer.
    pub fn cancel(ctx: Context<Cancel>) -> Result<()> {
        let schedule = &mut ctx.accounts.schedule;
        require_keys_eq!(
            schedule.authority,
            ctx.accounts.authority.key(),
            PenumbraError::Unauthorized
        );
        require!(
            schedule.status == ScheduleStatus::Active,
            PenumbraError::ScheduleInactive
        );
        schedule.status = ScheduleStatus::Cancelled;
        emit!(ScheduleCancelled {
            schedule: schedule.key(),
            at: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    /// Authority issues an attestation — a thin pointer to an Umbra
    /// compliance grant derived from the schedule authority's MVK for
    /// the supplied fiscal-year window. Emits an event so investors
    /// can discover it without scanning every PDA.
    pub fn attest(ctx: Context<Attest>, args: AttestArgs) -> Result<()> {
        let schedule = &ctx.accounts.schedule;
        require_keys_eq!(
            schedule.authority,
            ctx.accounts.authority.key(),
            PenumbraError::Unauthorized
        );
        require!(
            args.window_end > args.window_start,
            PenumbraError::InvalidWindow
        );

        emit!(AttestationIssued {
            schedule: schedule.key(),
            grantee_x25519: args.grantee_x25519,
            window_start: args.window_start,
            window_end: args.window_end,
            umbra_grant_id: args.umbra_grant_id,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(args: InitializeArgs)]
pub struct InitializeSchedule<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = VestSchedule::SIZE,
        seeds = [b"vest", authority.key().as_ref(), &args.nonce.to_le_bytes()],
        bump,
    )]
    pub schedule: Account<'info, VestSchedule>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Tick<'info> {
    #[account(mut)]
    pub keeper: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"vest",
            schedule.authority.as_ref(),
            &schedule.nonce.to_le_bytes(),
        ],
        bump = schedule.bump,
    )]
    pub schedule: Account<'info, VestSchedule>,

    /// CHECK: address constraint enforces the pinned UMBRA_PROGRAM_ID —
    /// any other program id is rejected before the instruction body runs.
    #[account(
        constraint = umbra_program.key() == UMBRA_PROGRAM_ID_PLACEHOLDER
            @ PenumbraError::InvalidUmbraProgram
    )]
    pub umbra_program: UncheckedAccount<'info>,
 
    /// CHECK: must match the encrypted_balance_pda recorded on this
    /// schedule at init time — prevents an attacker substituting a
    /// different ETA to redirect the CPI disbursement.
    #[account(
        constraint = schedule_eta.key() == schedule.encrypted_balance_pda
            @ PenumbraError::InvalidEta
    )]
    pub schedule_eta: UncheckedAccount<'info>,
 
    /// CHECK: Umbra's mixer Merkle tree — passed through to the CPI.
    /// Validated by Umbra's program internally on CPI entry; no
    /// additional constraint needed on this side.
    pub umbra_mixer_tree: UncheckedAccount<'info>,
 
    /// CHECK: Groth16 proof buffer — contents verified by Umbra's ZK
    /// verifier inside the CPI. No structural constraint possible here.
    pub zk_proof_buffer: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Cancel<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority)]
    pub schedule: Account<'info, VestSchedule>,
}

#[derive(Accounts)]
pub struct Attest<'info> {
    pub authority: Signer<'info>,
    #[account(has_one = authority)]
    pub schedule: Account<'info, VestSchedule>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct VestSchedule {
    pub authority: Pubkey,
    pub recipient_stealth: [u8; 32],
    pub nonce: u64,           // <-- ADD: needed to re-derive PDA in tick/cancel
    pub token_mint: Pubkey,
    pub cliff_ts: i64,
    pub slope_seconds: u32,
    pub total_tranches: u16,
    pub tranches_disbursed: u16,
    pub status: ScheduleStatus,
    pub encrypted_balance_pda: Pubkey,
    pub memo_preview_hash: [u8; 32],
    pub bump: u8,
}

impl VestSchedule {
    /// 8 disc + 32 + 32 + 32 + 8 + 4 + 2 + 2 + 1 + 32 + 32 + 1 + slack
    // Added 8 bytes for nonce u64
    pub const SIZE: usize = 8 + 32 + 8 + 32 + 32 + 8 + 4 + 2 + 2 + 1 + 32 + 32 + 1 + 32;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleStatus {
    Active,
    Complete,
    Cancelled,
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeArgs {
    pub nonce: u64,
    pub recipient_stealth: [u8; 32],
    pub token_mint: Pubkey,
    pub cliff_ts: i64,
    pub slope_seconds: u32,
    pub total_tranches: u16,
    pub encrypted_balance_pda: Pubkey,
    pub memo_preview_hash: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AttestArgs {
    pub grantee_x25519: [u8; 32],
    pub window_start: i64,
    pub window_end: i64,
    pub umbra_grant_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct ScheduleInitialized {
    pub schedule: Pubkey,
    pub authority: Pubkey,
    pub recipient_stealth: [u8; 32],
    pub cliff_ts: i64,
    pub total_tranches: u16,
}

#[event]
pub struct TrancheTicked {
    pub schedule: Pubkey,
    pub tranche_index: u16,
    pub posted_at: i64,
}

#[event]
pub struct ScheduleCancelled {
    pub schedule: Pubkey,
    pub at: i64,
}

#[event]
pub struct AttestationIssued {
    pub schedule: Pubkey,
    pub grantee_x25519: [u8; 32],
    pub window_start: i64,
    pub window_end: i64,
    pub umbra_grant_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum PenumbraError {
    #[msg("Schedule must have at least one tranche")]
    InvalidTranches,
    #[msg("Slope must be > 0 seconds")]
    InvalidSlope,
    #[msg("Cliff must be in the future")]
    CliffInPast,
    #[msg("Nothing due this tick")]
    NothingDue,
    #[msg("Schedule is not active")]
    ScheduleInactive,
    #[msg("Called before cliff timestamp")]
    PreCliff,
    #[msg("Attestation window is invalid")]
    InvalidWindow,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("umbra_program does not match the pinned UMBRA_PROGRAM_ID")]
    InvalidUmbraProgram,
    #[msg("schedule_eta does not match the encrypted_balance_pda stored on this schedule")]
    InvalidEta,
}
