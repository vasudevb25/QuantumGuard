r"""
Phase 6c - risk-adaptive anchoring.

Takes the sealed partitions from Phase 5, scores each one (anchoring/
risk.py), and protects it at the level its score justifies:

    Tier 1  immediate   anchored to the ledger on its own, at once
    Tier 2  batched     held in a buffer; when the buffer fills, a
                        SECOND-ORDER Merkle tree is built over the
                        members' roots and the single batch root is
                        anchored
    Tier 3  local       local hash chain only - already provided by
                        Phase 5's prev_record_hash linkage

Why Tier 2 exists
-----------------
Tier 1 costs one ledger transaction per partition. Tier 3 costs nothing
but survives nothing. Tier 2 is the middle: N partitions share one
transaction, and because the batch is a Merkle tree, any individual
member can still be proven to have been anchored - the proof is the
sibling path from that member's root up to the batch root, plus the
ledger receipt for the batch root.

That property is what makes batching safe. Without it, batching would
mean "these N partitions were anchored together, trust us"; with it,
each member keeps an independent, checkable proof.

Second-order construction
-------------------------
The Phase 5 Merkle tree has leaves that are provenance relations. The
Tier-2 tree has leaves that are *already-signed partition roots*. The
same MerkleTree implementation serves both, which is why
crypto/integrity.py's tree was written over opaque leaf bytes rather
than over edges specifically.

    partition roots  r₁ r₂ r₃ r₄
                      \ /     \ /
                       h₁       h₂
                         \     /
                          batch root  ──▶  one ledger transaction
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from core import config
from crypto.integrity import MerkleTree, _merkle_leaf, verify_proof
from anchoring.ledger import LocalLedger, get_ledger
from anchoring.risk import TIER1, TIER2, TIER3, RiskPolicy, RiskScorer, summarise


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def batch_root(member_roots: list[str]) -> tuple[str, MerkleTree]:
    """Second-order Merkle root over already-sealed partition roots."""
    if not member_roots:
        raise ValueError("cannot build a batch over zero partitions")
    leaves = [_merkle_leaf(bytes.fromhex(root)) for root in member_roots]
    tree = MerkleTree(leaves)
    return tree.root_hex, tree


class AnchoringService:
    """Assigns tiers, anchors accordingly, and emits verifiable receipts."""

    def __init__(self, ledger=None, policy: RiskPolicy | None = None,
                 batch_size: int | None = None):
        self.ledger = ledger if ledger is not None else get_ledger()
        self.scorer = RiskScorer(policy)
        self.batch_size = batch_size or config.ANCHOR_BATCH_SIZE

    # ------------------------------------------------------------------

    def anchor_run(self, records: list[dict[str, Any]], graph=None,
                   report: dict[str, Any] | None = None,
                   partitions: list[dict[str, Any]] | None = None,
                   tamper_alert_indices: set[int] | None = None,
                   persist: bool = True) -> dict[str, Any]:
        """Score, tier and anchor every partition of one sealed run."""

        if not records:
            raise ValueError("no sealed partitions to anchor")

        scores = self.scorer.score_all(
            records, graph, report, partitions, tamper_alert_indices)
        by_index = {entry["partition_index"]: entry for entry in scores}
        run_id = records[0].get("run_id")

        anchors: list[dict[str, Any]] = []
        urgent: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []

        for record in sorted(records,
                             key=lambda item: item.get("partition_index", 0)):
            index = record.get("partition_index")
            entry = by_index[index]
            tier = entry["risk_tier"]
            root = record["merkle_root"]
            member = {"partition_index": index, "merkle_root": root,
                      "risk_score": entry["risk_score"],
                      "record_hash": record.get("record_hash")}

            if tier == TIER1:
                # Tier 1 means "without delay", not "alone". A single
                # urgent partition is anchored on its own; several
                # produced in the same pass share one transaction,
                # because holding none of them back costs nothing and
                # paying N transaction fees for simultaneous evidence
                # is exactly the waste the risk model exists to avoid.
                # Each member still keeps an independent inclusion proof,
                # so sharing a transaction costs no provability.
                urgent.append(member)

            elif tier == TIER2:
                pending.append(member)
                if len(pending) >= self.batch_size:
                    anchors.extend(self._flush(pending, run_id, TIER2))
                    pending = []

            else:  # TIER3 - local chain only, no ledger transaction
                anchors.append({
                    "tier": TIER3, "partition_index": index,
                    "merkle_root": root, "risk_score": entry["risk_score"],
                    "receipt": None, "inclusion": None,
                })

        if urgent:
            anchors.extend(self._flush(urgent, run_id, TIER1))

        # anchor whatever is left in the buffer rather than losing it
        if pending:
            anchors.extend(self._flush(pending, run_id, TIER2))

        result = {
            "run_id": run_id,
            "created_at": _now(),
            "policy": {
                "tier1_threshold": self.scorer.policy.tier1_threshold,
                "tier2_threshold": self.scorer.policy.tier2_threshold,
                "batch_size": self.batch_size,
            },
            "summary": summarise(scores),
            "ledger_transactions": len({
                item["receipt"]["transaction_id"] for item in anchors
                if item["receipt"] is not None
            }),
            "scores": scores,
            "anchors": sorted(anchors, key=lambda item: item["partition_index"]),
        }

        if persist:
            self.save_report(result)
        return result

    # ------------------------------------------------------------------

    def _flush(self, pending: list[dict[str, Any]], run_id: str | None,
               tier: str) -> list[dict[str, Any]]:
        """Anchor a group of partitions under one ledger transaction.

        A single partition is anchored directly by its own root. Two or
        more share a second-order Merkle tree, and each keeps the
        sibling path proving its root sits under the anchored batch
        root - so batching never costs a partition its independent
        provability.
        """
        if len(pending) == 1:
            item = pending[0]
            receipt = self.ledger.anchor({
                "kind": "partition",
                "run_id": run_id,
                "partition_index": item["partition_index"],
                "merkle_root": item["merkle_root"],
                "record_hash": item.get("record_hash"),
                "risk_score": item["risk_score"],
            })
            return [{
                "tier": tier,
                "partition_index": item["partition_index"],
                "merkle_root": item["merkle_root"],
                "risk_score": item["risk_score"],
                "receipt": receipt,
                "inclusion": None,
            }]

        member_roots = [item["merkle_root"] for item in pending]
        root, tree = batch_root(member_roots)

        receipt = self.ledger.anchor({
            "kind": "batch",
            "run_id": run_id,
            "tier": tier,
            "merkle_root": root,
            "member_count": len(member_roots),
            "member_roots": member_roots,
            "partition_indices": [item["partition_index"] for item in pending],
        })

        return [
            {
                "tier": tier,
                "partition_index": item["partition_index"],
                "merkle_root": item["merkle_root"],
                "risk_score": item["risk_score"],
                "receipt": receipt,
                "inclusion": {
                    "batch_root": root,
                    "leaf_index": position,
                    "path": tree.proof(position),
                },
            }
            for position, item in enumerate(pending)
        ]

    # ------------------------------------------------------------------

    def verify_anchor(self, anchor: dict[str, Any]) -> dict[str, Any]:
        """Verify one partition's anchor independently of the local archive."""

        tier = anchor["tier"]
        result = {"partition_index": anchor["partition_index"], "tier": tier,
                  "ledger_ok": False, "inclusion_ok": None, "ok": False,
                  "reason": None}

        if tier == TIER3:
            # Tier 3 makes no external claim, so there is nothing to
            # verify here. It is reported as ok with its limitation named
            # rather than silently passed.
            result.update(ok=True, ledger_ok=None,
                          reason="tier 3: local chain only, no external anchor")
            return result

        inclusion = anchor.get("inclusion")
        # A batched partition must be traced to a root the LEDGER holds. Taken
        # from the anchor alone, the batch root could be anything the attacker
        # built a valid path to.
        wanted = inclusion.get("batch_root") if inclusion else anchor["merkle_root"]
        receipt = self.ledger.lookup(wanted) if wanted else None
        if receipt is None or (inclusion and receipt["anchored"].get("merkle_root") != wanted):
            result["reason"] = "no ledger receipt found for this root"
            return result
        result["ledger_ok"] = True

        if not inclusion:
            # anchored directly by its own root; the ledger lookup above
            # is the whole proof
            result["ok"] = True
            return result

        # batched: the ledger holds the batch root, so this partition's
        # own root must be proven to sit under it
        try:
            result["inclusion_ok"] = verify_proof(
                _merkle_leaf(bytes.fromhex(anchor["merkle_root"])),
                inclusion.get("path", []),
                bytes.fromhex(inclusion["batch_root"]),
            )
        except (KeyError, ValueError) as exc:
            result["reason"] = f"malformed inclusion proof: {exc}"
            return result

        result["ok"] = bool(result["inclusion_ok"])
        if not result["ok"]:
            result["reason"] = "inclusion proof does not reach the batch root"
        return result

    def alerted_partitions(self, records, graph=None, report=None,
                           partitions=None) -> set[int]:
        """Partitions holding the evidence behind a TAMPERED verdict.

        Falls back to the highest-scoring partition when the alert cannot be
        localised, so a tampered verdict always escalates something without
        escalating everything.
        """
        if not report or not report.get("tampered"):
            return set()
        scores = self.scorer.score_all(records, graph, report, partitions)
        hits = {entry["partition_index"] for entry in scores
                if entry["evidence"]["blocking_violations"]
                or entry["evidence"]["flagged_nodes"]
                or entry["evidence"]["unattested_gaps"]}
        return hits or {max(scores, key=lambda e: e["risk_score"])["partition_index"]}

    def cross_check(self, records: list[dict[str, Any]]) -> list[str]:
        """Compare the sealed evidence with what the ledger recorded for it.

        This is the check anchoring exists for. Evidence rewritten and
        re-signed by someone holding the keys passes every local test, but
        its roots no longer match the ones anchored earlier.
        """
        if not records:
            return []
        run_id = records[0].get("run_id")
        sealed = {record["partition_index"]: record["merkle_root"] for record in records}
        problems = []
        for receipt in self.ledger.receipts():
            payload = receipt["anchored"]
            if payload.get("run_id") != run_id:
                continue
            if payload.get("kind") == "partition":
                pairs = [(payload["partition_index"], payload["merkle_root"])]
            else:
                pairs = zip(payload.get("partition_indices", []),
                            payload.get("member_roots", []))
            for index, root in pairs:
                if sealed.get(index) != root:
                    problems.append(
                        f"partition {index}: sealed root does not match the root "
                        f"anchored in block {receipt['block_number']}")
        return problems

    def verify_run(self, anchoring_report: dict[str, Any],
                   verifier=None) -> dict[str, Any]:
        """Verify the ledger itself, then every anchor it issued."""

        ledger = self.ledger.verify(verifier)
        checks = [self.verify_anchor(anchor)
                  for anchor in anchoring_report.get("anchors", [])]

        failures = [check for check in checks if not check["ok"]]
        externally_anchored = sum(1 for check in checks
                                  if check["tier"] in (TIER1, TIER2))

        return {
            "ok": ledger["ok"] and not failures,
            "ledger": ledger,
            "anchors_checked": len(checks),
            "externally_anchored": externally_anchored,
            "local_only": len(checks) - externally_anchored,
            "failures": failures,
            "checks": checks,
        }

    # ------------------------------------------------------------------

    @staticmethod
    def save_report(result: dict[str, Any],
                    path: str | Path | None = None) -> Path:
        output = Path(path or config.ANCHOR_REPORT)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return output

    @staticmethod
    def load_report(path: str | Path | None = None) -> dict[str, Any]:
        return json.loads(Path(path or config.ANCHOR_REPORT)
                          .read_text(encoding="utf-8"))


def format_report(result: dict[str, Any]) -> str:
    """Console rendering of an anchoring run."""

    summary = result["summary"]
    tiers = summary["by_tier"]
    lines = [
        "=" * 62,
        "  QuantumGuard - Risk-Adaptive Anchoring",
        "=" * 62,
        f"  partitions          : {summary['partitions']}",
        f"  risk score          : min {summary['score_min']}  "
        f"mean {summary['score_mean']}  max {summary['score_max']}",
        "-" * 62,
        f"  tier 1 (immediate)  : {tiers.get(TIER1, 0)}",
        f"  tier 2 (batched)    : {tiers.get(TIER2, 0)}",
        f"  tier 3 (local only) : {tiers.get(TIER3, 0)}",
        f"  ledger transactions : {result['ledger_transactions']}",
    ]

    anchored = [item for item in result["anchors"] if item["tier"] != TIER3]
    if anchored:
        lines.append("-" * 62)
        lines.append("  externally anchored:")
        for item in anchored[:10]:
            receipt = item["receipt"]
            lines.append(
                f"    [{item['partition_index']:>3}] {item['tier']:<16} "
                f"score {item['risk_score']:.3f}  "
                f"block {receipt['block_number']}  "
                f"tx {receipt['transaction_id'][:12]}..."
            )
        if len(anchored) > 10:
            lines.append(f"    ... {len(anchored) - 10} more")

    lines.append("=" * 62)
    return "\n".join(lines)
