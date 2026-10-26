#!/usr/bin/env python3
"""SOC-AZ-001 v3: manual, read-only Azure RBAC review with retained GitHub checkpoint.

The checkpoint contains only SHA-256 operation digests and outcomes. It is stored
as a GitHub Actions artifact (retention-limited), not as permanent incident storage.
No Azure resources or roles are modified.
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPOSITORY = "adamsawas10/multi-cloud-soc-incident-response"
ARTIFACT_NAME = "soc-az-001-v3-checkpoint"
STATE_FILE = Path("state/soc-az-001-checkpoint.json")
RBAC = {
    "microsoft.authorization/roleassignments/write": "ROLE_ASSIGNMENT_WRITE",
    "microsoft.authorization/roleassignments/delete": "ROLE_ASSIGNMENT_DELETE",
    "microsoft.authorization/roledefinitions/write": "ROLE_DEFINITION_WRITE",
    "microsoft.authorization/roledefinitions/delete": "ROLE_DEFINITION_DELETE",
}
OUTCOMES = {
    "CONFLICTING_REVIEW", "COMPLETED_REVIEW", "FAILED_ATTEMPT_REVIEW",
    "PENDING_NOT_CONFIRMED", "UNKNOWN_STATUS_REVIEW",
}
REVIEW = {"CONFLICTING_REVIEW", "COMPLETED_REVIEW", "FAILED_ATTEMPT_REVIEW"}


def field(v):
    if isinstance(v, dict):
        return str(v.get("value") or v.get("localizedValue") or "")
    return v if isinstance(v, str) else ""


def event_timestamp(value):
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return d if d.tzinfo is not None else None
    except (AttributeError, ValueError):
        return None


def outcome_of(states):
    if "succeeded" in states and "failed" in states:
        return "CONFLICTING_REVIEW"
    if "succeeded" in states:
        return "COMPLETED_REVIEW"
    if "failed" in states:
        return "FAILED_ATTEMPT_REVIEW"
    if states & {"started", "accepted"}:
        return "PENDING_NOT_CONFIRMED"
    return "UNKNOWN_STATUS_REVIEW"


def summarize(records):
    if not isinstance(records, list):
        raise ValueError("Invalid Azure response structure")
    grouped = {}
    seen_events = set()
    inspected = 0
    unverifiable = 0
    for r in records:
        if not isinstance(r, dict):
            continue
        operation = field(r.get("operationName")).strip().lower()
        category = field(r.get("category")).strip().lower()
        if operation not in RBAC or category != "administrative":
            continue
        if event_timestamp(field(r.get("eventTimestamp"))) is None:
            continue
        eid = field(r.get("eventDataId")).strip().lower()
        if eid and eid in seen_events:
            continue
        if eid:
            seen_events.add(eid)
        inspected += 1
        op_id = field(r.get("operationId")).strip().lower()
        correlation_id = field(r.get("correlationId")).strip().lower()
        resource = field(r.get("resourceId")).strip().lower()
        if op_id:
            basis = ["op", op_id, operation, resource]
        elif correlation_id:
            basis = ["corr", correlation_id, operation, resource]
        elif eid:
            basis = ["event", eid, operation, resource]
        else:
            # Without any durable event identity, do not invent deduplication.
            unverifiable += 1
            continue
        digest = hashlib.sha256(json.dumps(basis, separators=(",", ":")).encode()).hexdigest()
        item = grouped.setdefault(digest, {"kind": RBAC[operation], "statuses": set()})
        status = field(r.get("status")).strip().lower()
        item["statuses"].add(status if status in {"succeeded", "failed", "started", "accepted"} else "other")
    return inspected, unverifiable, {
        digest: {"kind": item["kind"], "outcome": outcome_of(item["statuses"]),
                 "statuses": sorted(item["statuses"])}
        for digest, item in grouped.items()
    }


def validate_state(state):
    if not isinstance(state, dict) or state.get("version") != 1:
        raise ValueError("Unrecognized checkpoint version")
    seen = state.get("seen")
    if not isinstance(seen, dict) or len(seen) > 20000:
        raise ValueError("Invalid checkpoint structure")
    for key, value in seen.items():
        if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None:
            raise ValueError("Invalid checkpoint key")
        if not isinstance(value, dict) or set(value) != {"kind", "outcome", "statuses"}:
            raise ValueError("Invalid checkpoint entry")
        statuses = value["statuses"]
        if (value["kind"] not in RBAC.values() or not isinstance(statuses, list)
                or not statuses or len(statuses) > 5 or any(
                    x not in {"succeeded", "failed", "started", "accepted", "other"}
                    for x in statuses
                ) or value["outcome"] != outcome_of(set(statuses))):
            raise ValueError("Invalid checkpoint outcome")
    return seen


def changes(current, previous, baseline):
    all_seen = dict(previous)
    new = Counter()
    revised = Counter()
    for digest, item in current.items():
        old = previous.get(digest)
        if old is not None and old["kind"] != item["kind"]:
            raise ValueError("Conflicting operation identity in checkpoint")
        # Monotonic union: an earlier success cannot regress to pending when
        # a subsequent 7-day query returns only the operation's START record.
        statuses = set(item["statuses"]) | set(old["statuses"] if old else [])
        combined = {"kind": item["kind"], "statuses": sorted(statuses),
                    "outcome": outcome_of(statuses)}
        if old is None:
            if not baseline and combined["outcome"] in REVIEW:
                new[(combined["kind"], combined["outcome"])] += 1
        elif old["outcome"] != combined["outcome"]:
            if not baseline and combined["outcome"] in REVIEW:
                revised[(combined["kind"], combined["outcome"])] += 1
        all_seen[digest] = combined
    if len(all_seen) > 20000:
        raise ValueError("Checkpoint capacity exceeded; no new state written")
    return all_seen, new, revised


def api_json(url, token):
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "soc-az001-readonly-tracker",
    })
    with urllib.request.urlopen(req, timeout=25) as res:
        return json.load(res)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def download_artifact(artifact_id, token):
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "soc-az001-readonly-tracker",
    })
    try:
        urllib.request.build_opener(NoRedirect()).open(req, timeout=25)
        raise ValueError("Unexpected artifact API response")
    except urllib.error.HTTPError as exc:
        if exc.code != 302:
            raise ValueError("Could not download checkpoint") from None
        target = exc.headers.get("Location", "")
    if urllib.parse.urlparse(target).scheme != "https":
        raise ValueError("Invalid artifact download redirect")
    # Never forward the GitHub bearer token to the signed archive URL.
    with urllib.request.urlopen(target, timeout=35) as res:
        archive = res.read(8_000_001)
    if len(archive) > 8_000_000:
        raise ValueError("Checkpoint archive is unexpectedly large")
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        if z.namelist() != ["soc-az-001-checkpoint.json"]:
            raise ValueError("Unexpected checkpoint artifact content")
        data = z.read("soc-az-001-checkpoint.json")
        if len(data) > 6_000_000:
            raise ValueError("Checkpoint file too large")
        state = json.loads(data)
    return validate_state(state)


def load_previous(token):
    # Read only GitHub Actions artifacts from the protected main-branch workflow.
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts?name={ARTIFACT_NAME}&per_page=100"
    response = api_json(url, token)
    artifacts = [a for a in response.get("artifacts", [])
                 if a.get("name") == ARTIFACT_NAME and not a.get("expired")
                 and (a.get("workflow_run") or {}).get("head_branch") == "main"]
    artifacts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    if not artifacts:
        return {}, True
    return download_artifact(artifacts[0]["id"], token), False


def read_azure(subscription):
    process = subprocess.run(
        ["az", "monitor", "activity-log", "list", "--subscription", subscription,
         "--offset", "7d", "--max-events", "500", "--output", "json", "--only-show-errors"],
        check=True, capture_output=True, text=True, timeout=120,
    )
    return json.loads(process.stdout)


def write_outputs(all_seen, stats):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"version": 1, "seen": all_seen}, separators=(",", ":")) + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("## SOC-AZ-001 v3 — Azure RBAC review\n\n")
            f.write("| Measurement | Count / status |\n|---|---|\n")
            for k, v in stats.items():
                f.write(f"| {k} | {v} |\n")
            f.write("\nManual, retention-limited checkpoint; no raw identifiers or audit records are stored.\n")


def self_test():
    def r(status, eid="a", operation_id="op-1", op="roleAssignments/write", cat="Administrative"):
        return {"category": {"value": cat},
                "operationName": {"value": "Microsoft.Authorization/" + op},
                "status": {"value": status}, "eventDataId": eid,
                "operationId": operation_id, "resourceId": "/subscriptions/test/resource",
                "eventTimestamp": "2026-10-25T01:35:49Z"}
    _, _, a = summarize([r("Started", "a"), r("Succeeded", "b")])
    assert len(a) == 1 and next(iter(a.values()))["outcome"] == "COMPLETED_REVIEW"
    _, _, b = summarize([r("Succeeded"), r("Succeeded")])
    assert len(b) == 1
    _, _, c = summarize([r("Failed"), r("Succeeded", "b")])
    assert next(iter(c.values()))["outcome"] == "CONFLICTING_REVIEW"
    assert summarize([r("Succeeded", cat="Security")])[2] == {}
    assert summarize([r("Succeeded", op="policyAssignments/write")])[2] == {}
    _, _, pending = summarize([r("Started")])
    all_seen, new, revised = changes(pending, {}, True)
    assert not new and not revised
    _, new, revised = changes(a, all_seen, False)
    assert not new and sum(revised.values()) == 1
    _, new, revised = changes(a, {}, False)
    assert sum(new.values()) == 1 and not revised
    _, new, revised = changes(a, a, False)
    assert not new and not revised
    checkpoint, _, _ = changes(a, pending, False)
    # The later START-only response must not downgrade a stored completion.
    after, new, revised = changes(pending, checkpoint, False)
    assert after == checkpoint and not new and not revised
    assert validate_state({"version": 1, "seen": a}) == a
    try:
        validate_state({"version": 1, "seen": {"bad": {"kind": "test", "outcome": "pass"}}})
        raise AssertionError("Malformed checkpoint unexpectedly accepted")
    except ValueError:
        pass
    print("PASS: 12 offline grouping, deduplication and checkpoint checks")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    try:
        sub = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
        token = os.environ.get("GH_TOKEN", "").strip()
        if not sub or not token or os.environ.get("GITHUB_REF") != "refs/heads/main":
            raise ValueError("Missing authentication or unexpected execution branch")
        prev, baseline = load_previous(token)
        records = read_azure(sub)
        inspected, untrackable, current = summarize(records)
        if not isinstance(records, list):
            raise ValueError("Unexpected Azure Activity Log response")
        if not records:
            raise ValueError("Zero Activity Log events; cannot validate coverage")
        merged, new, revised = changes(current, prev, baseline)
        stats = {
            "Azure events retrieved (max 500)": len(records),
            "RBAC records inspected": inspected,
            "RBAC records missing stable IDs": untrackable,
            "Grouped RBAC operations": len(current),
            "Checkpoint": "BASELINE" if baseline else "RESTORED",
            "New review signals": sum(new.values()),
            "Updated review signals": sum(revised.values()),
        }
        write_outputs(merged, stats)
        print("PASS: Azure OIDC and Activity Log query completed")
        for key, val in stats.items():
            print(f"{key}: {val}")
        if baseline:
            print("BASELINE: Existing findings were recorded without issuing alerts")
        for (kind, state), n in sorted((new + revised).items()):
            print(f"::warning title=SOC-AZ-001 Review::{kind} / {state}: {n} new or changed review signal(s)")
        if len(records) >= 500:
            print("WARNING: Query hit the 500-event cap; results may be incomplete")
        print("PASS: Privacy-safe, retention-limited checkpoint ready for upload")
        print("LIMIT: Artifacts expire; no continuous monitoring, durable DB or AWS OIDC")
        return 0
    except Exception as exc:
        # Never print exception bodies or raw Azure data/identifiers.
        print(f"INCOMPLETE: V3 checkpoint or telemetry validation failed ({type(exc).__name__}); no new checkpoint published")
        return 2


if __name__ == "__main__":
    sys.exit(main())
