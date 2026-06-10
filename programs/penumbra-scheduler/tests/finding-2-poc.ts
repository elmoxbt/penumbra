/**
 * SECURITY POC — Finding 2: 4× UncheckedAccount with no runtime validation
 * =========================================================================
 *
 * Vulnerability
 * -------------
 * The `Tick` accounts struct accepted four `UncheckedAccount` fields with
 * only aspirational `/// CHECK:` comments and no actual constraint code:
 *   - umbra_program    — any program id accepted, CPI redirect possible
 *   - schedule_eta     — any account accepted, wrong ETA drainable
 *   - umbra_mixer_tree — any account accepted (lower risk, validated by Umbra)
 *   - zk_proof_buffer  — any account accepted (lower risk, verified by ZK)
 *
 * The two critical ones are `umbra_program` and `schedule_eta`:
 *
 * Attack 1 — CPI redirect via fake umbra_program
 *   Once the CPI stub is wired in, an attacker passes their own program id
 *   as `umbra_program`. The CPI fires into the attacker's program instead
 *   of Umbra, which can drain, mint, or do anything the PDA signer allows.
 *
 * Attack 2 — ETA substitution via fake schedule_eta
 *   The attacker passes a different ETA account than the one recorded on the
 *   schedule. The CPI disbursement hits the wrong encrypted balance account.
 *
 * Fix
 * ---
 * Added `constraint` expressions to both critical accounts:
 *   umbra_program:  key() == UMBRA_PROGRAM_ID_PLACEHOLDER @ InvalidUmbraProgram
 *   schedule_eta:   key() == schedule.encrypted_balance_pda @ InvalidEta
 *
 * umbra_mixer_tree and zk_proof_buffer are validated by Umbra's program
 * internally on CPI entry — no additional constraint needed on this side.
 *
 * How to run
 * ----------
 *   anchor test -- --grep "finding-2"
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

describe("Finding 2 — UncheckedAccount validation bypass", () => {
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

  // The pinned placeholder used in this build (SystemProgram = all-zeros)
  const UMBRA_PROGRAM_ID = SystemProgram.programId;
  const dummyPubkey = Keypair.generate().publicKey;

  // -------------------------------------------------------------------------
  // Shared schedule setup
  // -------------------------------------------------------------------------

  let foundation: Keypair;
  let schedulePda: PublicKey;
  let legitimateEta: PublicKey;
  let keeper: Keypair;
  const nonce = new BN(99);

  before(async () => {
    foundation = Keypair.generate();
    keeper = Keypair.generate();
    await fund(foundation);
    await fund(keeper);

    legitimateEta = Keypair.generate().publicKey; // stands in for real ETA

    [schedulePda] = deriveSchedulePda(foundation.publicKey, nonce);
    const cliffTs = Math.floor(Date.now() / 1000) + 2;

    await program.methods
      .initializeSchedule({
        nonce,
        recipientStealth: Array(32).fill(1),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs),
        slopeSeconds: 1,
        totalTranches: 10,
        encryptedBalancePda: legitimateEta,   // recorded on the schedule
        memoPreviewHash: Array(32).fill(2),
      })
      .accounts({
        authority: foundation.publicKey,
        schedule: schedulePda,
        systemProgram: SystemProgram.programId,
      })
      .signers([foundation])
      .rpc();

    // Wait for cliff to pass
    await sleep(3000);
  });

 
  
  it("[FIXED] tick rejects a fake umbra_program with InvalidUmbraProgram", async () => {
    const foundation3 = Keypair.generate();
    await fund(foundation3);
    const nonce3 = new BN(200);
    const [schedulePda3] = deriveSchedulePda(foundation3.publicKey, nonce3);
    const eta3 = Keypair.generate().publicKey;
    const cliffTs3 = Math.floor(Date.now() / 1000) + 2;

    await program.methods
      .initializeSchedule({
        nonce: nonce3,
        recipientStealth: Array(32).fill(5),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs3),
        slopeSeconds: 1,
        totalTranches: 5,
        encryptedBalancePda: eta3,
        memoPreviewHash: Array(32).fill(6),
      })
      .accounts({
        authority: foundation3.publicKey,
        schedule: schedulePda3,
        systemProgram: SystemProgram.programId,
      })
      .signers([foundation3])
      .rpc();

    await sleep(3000);

    const fakeUmbraProgram = Keypair.generate().publicKey;

    try {
      await program.methods
        .tick()
        .accounts({
          keeper: keeper.publicKey,
          schedule: schedulePda3,
          umbraProgram: fakeUmbraProgram,  // should be rejected
          scheduleEta: eta3,
          umbraMixerTree: dummyPubkey,
          zkProofBuffer: dummyPubkey,
        })
        .signers([keeper])
        .rpc();

      assert.fail("Expected InvalidUmbraProgram but tick succeeded");
    } catch (err: any) {
      const isExpected =
        err?.error?.errorCode?.code === "InvalidUmbraProgram" ||
        err?.message?.includes("InvalidUmbraProgram");

      assert.isTrue(
        isExpected,
        `Expected InvalidUmbraProgram but got: ${err?.message}`
      );
      console.log("[FIXED] fake umbra_program correctly rejected ✓");
    }
  });

  // -------------------------------------------------------------------------
  // REGRESSION 2 — fake schedule_eta is rejected after fix
  // -------------------------------------------------------------------------

  it("[FIXED] tick rejects a fake schedule_eta with InvalidEta", async () => {
    const foundation4 = Keypair.generate();
    await fund(foundation4);
    const nonce4 = new BN(300);
    const [schedulePda4] = deriveSchedulePda(foundation4.publicKey, nonce4);
    const realEta4 = Keypair.generate().publicKey;
    const cliffTs4 = Math.floor(Date.now() / 1000) + 2;

    await program.methods
      .initializeSchedule({
        nonce: nonce4,
        recipientStealth: Array(32).fill(7),
        tokenMint: dummyPubkey,
        cliffTs: new BN(cliffTs4),
        slopeSeconds: 1,
        totalTranches: 5,
        encryptedBalancePda: realEta4,
        memoPreviewHash: Array(32).fill(8),
      })
      .accounts({
        authority: foundation4.publicKey,
        schedule: schedulePda4,
        systemProgram: SystemProgram.programId,
      })
      .signers([foundation4])
      .rpc();

    await sleep(3000);

    const fakeEta = Keypair.generate().publicKey;

    try {
      await program.methods
        .tick()
        .accounts({
          keeper: keeper.publicKey,
          schedule: schedulePda4,
          umbraProgram: UMBRA_PROGRAM_ID,
          scheduleEta: fakeEta,           // should be rejected
          umbraMixerTree: dummyPubkey,
          zkProofBuffer: dummyPubkey,
        })
        .signers([keeper])
        .rpc();

      assert.fail("Expected InvalidEta but tick succeeded");
    } catch (err: any) {
      const isExpected =
        err?.error?.errorCode?.code === "InvalidEta" ||
        err?.message?.includes("InvalidEta");

      assert.isTrue(
        isExpected,
        `Expected InvalidEta but got: ${err?.message}`
      );
      console.log("[FIXED] fake schedule_eta correctly rejected ✓");
    }
  });
});