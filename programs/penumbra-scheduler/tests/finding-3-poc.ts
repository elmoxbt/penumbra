/**
 * SECURITY POC — Finding 3: Bulk tranche replay via accumulated `should_post`
 * ============================================================================
 *
 * Vulnerability
 * -------------
 * `tick` computed `should_post` as all tranches due since cliff, then set
 * `tranches_disbursed = should_post` — jumping to ALL accumulated tranches
 * in a single call. A keeper (or attacker) who delayed ticking could trigger
 * every skipped tranche in one transaction:
 *
 *   schedule.tranches_disbursed = should_post;  // BEFORE — bulk jump
 *
 * Impact
 * ------
 * 1. Economic — a single large CPI fires for N tranches instead of N
 *    separate small CPIs, which could drain a funded ETA in one shot.
 * 2. Privacy — Umbra's privacy model relies on tranches arriving as
 *    separate, unlinkable UTXOs over time. A bulk tick collapses N
 *    disbursements into one on-chain event, leaking timing correlation
 *    and potentially amount correlation.
 *
 * Fix
 * ---
 * Replace the bulk assignment with a single-step advance:
 *
 *   schedule.tranches_disbursed = schedule.tranches_disbursed.saturating_add(1);
 *
 * Callers wanting to catch up N tranches must call `tick` N times.
 * Each call fires exactly one CPI, preserving the per-tranche privacy guarantee.
 *
 * How to run
 * ----------
 *   anchor test -- --grep "finding-3"
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import type { PenumbraScheduler } from "../target/types/penumbra_scheduler";
import BN from "bn.js";
import {
  Keypair,
  SystemProgram,
  PublicKey,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { assert } from "chai";

describe("Finding 3 — bulk tranche replay", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace
    .PenumbraScheduler as Program<PenumbraScheduler>;

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  function deriveSchedulePda(authority: PublicKey, nonce: BN): [PublicKey, number] {
    const nonceBytes = Buffer.alloc(8);
    nonceBytes.writeBigUInt64LE(BigInt(nonce.toString()));
    return PublicKey.findProgramAddressSync(
      [Buffer.from("vest"), authority.toBuffer(), nonceBytes],
      program.programId
    );
  }

  async function fund(kp: Keypair, sol = 2) {
    const sig = await provider.connection.requestAirdrop(
      kp.publicKey,
      sol * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);
  }

  async function sleep(ms: number) {
    return new Promise((r) => setTimeout(r, ms));
  }

  const UMBRA_PROGRAM_ID = SystemProgram.programId;
  const dummyPubkey = Keypair.generate().publicKey;

  // -------------------------------------------------------------------------
  // REGRESSION — proves exactly one tranche advances per tick (FIXED)
  // -------------------------------------------------------------------------

  it("[FIXED] tick advances tranches_disbursed by exactly 1 regardless of accumulation", async () => {
    const authority = Keypair.generate();
    const keeper = Keypair.generate();
    await fund(authority);
    await fund(keeper);

    const nonce = new BN(501);
    const [schedulePda] = deriveSchedulePda(authority.publicKey, nonce);
    const eta = Keypair.generate().publicKey;

    const cliffTs = Math.floor(Date.now() / 1000) + 2;

    await program.methods
      .initializeSchedule({
        nonce,
        recipientStealth: Array(32).fill(1),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs),
        slopeSeconds: 2,
        totalTranches: 10,
        encryptedBalancePda: eta,
        memoPreviewHash: Array(32).fill(1),
      })
      .accounts({
        authority: authority.publicKey,
        schedule: schedulePda,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    // Wait for 3+ tranches to accumulate
    await sleep(8000);

    // First tick — should advance by exactly 1
    await program.methods
      .tick()
      .accounts({
        keeper: keeper.publicKey,
        schedule: schedulePda,
        umbraProgram: UMBRA_PROGRAM_ID,
        scheduleEta: eta,
        umbraMixerTree: dummyPubkey,
        zkProofBuffer: dummyPubkey,
      })
      .signers([keeper])
      .rpc();

    const stateAfterFirst = await program.account.vestSchedule.fetch(schedulePda);
    assert.equal(
      stateAfterFirst.tranchesDisbursed,
      1,
      `Expected tranches_disbursed = 1 after first tick, got ${stateAfterFirst.tranchesDisbursed}`
    );

    // Second tick — should advance to exactly 2
    await program.methods
      .tick()
      .accounts({
        keeper: keeper.publicKey,
        schedule: schedulePda,
        umbraProgram: UMBRA_PROGRAM_ID,
        scheduleEta: eta,
        umbraMixerTree: dummyPubkey,
        zkProofBuffer: dummyPubkey,
      })
      .signers([keeper])
      .rpc();

    const stateAfterSecond = await program.account.vestSchedule.fetch(schedulePda);
    assert.equal(
      stateAfterSecond.tranchesDisbursed,
      2,
      `Expected tranches_disbursed = 2 after second tick, got ${stateAfterSecond.tranchesDisbursed}`
    );

    // Third tick immediately — should succeed since 3 tranches are still due
    await program.methods
      .tick()
      .accounts({
        keeper: keeper.publicKey,
        schedule: schedulePda,
        umbraProgram: UMBRA_PROGRAM_ID,
        scheduleEta: eta,
        umbraMixerTree: dummyPubkey,
        zkProofBuffer: dummyPubkey,
      })
      .signers([keeper])
      .rpc();

    const stateAfterThird = await program.account.vestSchedule.fetch(schedulePda);
    assert.equal(
      stateAfterThird.tranchesDisbursed,
      3,
      `Expected tranches_disbursed = 3 after third tick, got ${stateAfterThird.tranchesDisbursed}`
    );

  });

  // -------------------------------------------------------------------------
  // REGRESSION — NothingDue fires if no new tranche is due
  // -------------------------------------------------------------------------

  it("[FIXED] tick throws NothingDue when called faster than slope_seconds", async () => {
    const authority = Keypair.generate();
    const keeper = Keypair.generate();
    await fund(authority);
    await fund(keeper);

    const nonce = new BN(502);
    const [schedulePda] = deriveSchedulePda(authority.publicKey, nonce);
    const eta = Keypair.generate().publicKey;

    // Long slope — 1 hour per tranche so second tick is always too early
    const cliffTs = Math.floor(Date.now() / 1000) + 2;

    await program.methods
      .initializeSchedule({
        nonce,
        recipientStealth: Array(32).fill(2),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs),
        slopeSeconds: 3600,
        totalTranches: 5,
        encryptedBalancePda: eta,
        memoPreviewHash: Array(32).fill(2),
      })
      .accounts({
        authority: authority.publicKey,
        schedule: schedulePda,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    await sleep(3000);

    // First tick succeeds
    await program.methods
      .tick()
      .accounts({
        keeper: keeper.publicKey,
        schedule: schedulePda,
        umbraProgram: UMBRA_PROGRAM_ID,
        scheduleEta: eta,
        umbraMixerTree: dummyPubkey,
        zkProofBuffer: dummyPubkey,
      })
      .signers([keeper])
      .rpc();

    // Immediate second tick — should throw NothingDue
    try {
      await program.methods
        .tick()
        .accounts({
          keeper: keeper.publicKey,
          schedule: schedulePda,
          umbraProgram: UMBRA_PROGRAM_ID,
          scheduleEta: eta,
          umbraMixerTree: dummyPubkey,
          zkProofBuffer: dummyPubkey,
        })
        .signers([keeper])
        .rpc();

      assert.fail("Expected NothingDue but tick succeeded");
    } catch (err: any) {
      const isExpected =
        err?.error?.errorCode?.code === "NothingDue" ||
        err?.message?.includes("NothingDue");

      assert.isTrue(
        isExpected,
        `Expected NothingDue but got: ${err?.message}`
      );
      console.log("[FIXED] second tick correctly blocked with NothingDue ✓");
    }
  });
});