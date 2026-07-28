// ============================================================================
// RiskProof — durable ApprovalTicket replay adapter
// ============================================================================
// Bridges ApprovalTicketVerifier's atomic consume-once contract to the local
// cross-process task/session ledger. The ledger receives only commitments:
// replayKey is already a domain-separated digest and is hashed once more before
// persistence; ticketDigest remains a commitment to the signed envelope.

import type {
  ApprovalTicketReplayRecord,
  ApprovalTicketReplayStore,
} from "./approval-ticket.js";
import { PersistentTaskLedger } from "./persistent-task-ledger.js";

export class PersistentLedgerApprovalReplayStore implements ApprovalTicketReplayStore {
  private readonly ledger: PersistentTaskLedger;

  constructor(ledger: PersistentTaskLedger) {
    if (!(ledger instanceof PersistentTaskLedger)) {
      throw new TypeError("PersistentLedgerApprovalReplayStore requires a PersistentTaskLedger");
    }
    this.ledger = ledger;
  }

  async consumeOnce(record: ApprovalTicketReplayRecord): Promise<boolean> {
    const result = await this.ledger.consumeNonce({
      nonce: record.replayKey,
      purpose: "approval_ticket",
      bindingDigest: record.ticketDigest,
      expiresAt: new Date(record.expiresAtMs).toISOString(),
    });
    return result.status === "consumed";
  }
}
