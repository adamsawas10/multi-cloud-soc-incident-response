#!/usr/bin/env python3
"""SOC-INT-001: privacy-limited, operator-mediated AWS/Azure SOC snapshot.

Read-only proof of integration. Azure input is a GitHub Actions v3 checkpoint
obtained by the operator. AWS input is the historical, verified SOC-001 DynamoDB
incident in us-east-2. No continuous ingestion or cloud writes are performed.

Usage:
  python3 unify_soc_live_sources_v2.py --self-test
  python3 unify_soc_live_sources_v2.py --checkpoint-file ~/soc-az-001-checkpoint.json

Optional, advanced API mode: GH_TOKEN with repository Actions:read permission
may be provided in the process environment. No token is written to files/logs.
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = "adamsawas10/multi-cloud-soc-incident-response"
REPO_ID = 1424056177
ARTIFACT_NAME = "soc-az-001-v3-checkpoint"
ZIP_MEMBER = "soc-az-001-checkpoint.json"
RUN_PATH = ".github/workflows/soc-azure-rbac-tracking.yml"
TABLE = "cloud-soc-incidents"
REGION = "us-east-2"
OUTPUT = Path.home() / "soc-unified" / "output" / "unified_soc_snapshot.json"
KINDS = {"ROLE_ASSIGNMENT_WRITE", "ROLE_ASSIGNMENT_DELETE",
         "ROLE_DEFINITION_WRITE", "ROLE_DEFINITION_DELETE"}
STATES = {"started", "accepted", "succeeded", "failed", "other"}
OUTCOMES = {"CONFLICTING_REVIEW", "COMPLETED_REVIEW", "FAILED_ATTEMPT_REVIEW",
            "PENDING_NOT_CONFIRMED", "UNKNOWN_STATUS_REVIEW"}


def utcstamp(value):
    if not isinstance(value, str):
        raise ValueError("Missing timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp is not timezone-aware")
    return result.astimezone(timezone.utc)


def derived_outcome(states):
    states = set(states)
    if "succeeded" in states and "failed" in states:
        return "CONFLICTING_REVIEW"
    if "succeeded" in states:
        return "COMPLETED_REVIEW"
    if "failed" in states:
        return "FAILED_ATTEMPT_REVIEW"
    if states & {"started", "accepted"}:
        return "PENDING_NOT_CONFIRMED"
    return "UNKNOWN_STATUS_REVIEW"


def validate_checkpoint(obj):
    if not isinstance(obj, dict) or obj.get("version") != 1:
        raise ValueError("Invalid checkpoint version")
    seen = obj.get("seen")
    if not isinstance(seen, dict) or len(seen) > 20000:
        raise ValueError("Invalid checkpoint records")
    for digest, item in seen.items():
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            raise ValueError("Invalid digest")
        if not isinstance(item, dict) or set(item) != {"kind", "outcome", "statuses"}:
            raise ValueError("Invalid checkpoint record fields")
        statuses = item["statuses"]
        if (item["kind"] not in KINDS or item["outcome"] not in OUTCOMES
                or not isinstance(statuses, list) or not 1 <= len(statuses) <= 5
                or any(s not in STATES for s in statuses)
                or item["outcome"] != derived_outcome(statuses)):
            raise ValueError("Invalid checkpoint classification")
    return seen


def read_local_checkpoint(path):
    path = Path(path).expanduser()
    if not path.is_file() or path.stat().st_size > 5_000_000:
        raise ValueError("Checkpoint missing or exceeds size limit")
    seen = validate_checkpoint(json.loads(path.read_text(encoding="utf-8")))
    return seen, None, None, "OPERATOR_DOWNLOADED_GITHUB_ARTIFACT"


def github_api(path, token):
    url = f"https://api.github.com/repos/{REPO}/{path}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "User-Agent": "SOC-INT-001-integration-validator",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.load(res)
    except urllib.error.HTTPError as error:
        raise ValueError(f"GitHub API HTTP {error.code} while reading artifact metadata") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def download_github_zip(artifact_id, token):
    url = f"https://api.github.com/repos/{REPO}/actions/artifacts/{artifact_id}/zip"
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "SOC-INT-001-integration-validator",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        urllib.request.build_opener(NoRedirect()).open(request, timeout=30)
        raise ValueError("Unexpected GitHub artifact download response")
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise ValueError(f"GitHub artifact download returned HTTP {error.code}") from None
        redirect = error.headers.get("Location", "")
    parsed = urllib.parse.urlsplit(redirect)
    host = (parsed.hostname or "").lower()
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port
            or not (host.endswith(".blob.core.windows.net")
                    or host == "objects.githubusercontent.com"
                    or host.endswith(".githubusercontent.com"))):
        raise ValueError("Untrusted artifact storage redirect")
    # Do not forward a GitHub bearer token to the signed storage URL.
    with urllib.request.urlopen(redirect, timeout=40) as res:
        body = res.read(6_000_001)
    if len(body) > 6_000_000:
        raise ValueError("Artifact download too large")
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        if z.namelist() != [ZIP_MEMBER] or z.getinfo(ZIP_MEMBER).file_size > 5_000_000:
            raise ValueError("Unexpected artifact contents")
        return validate_checkpoint(json.loads(z.read(ZIP_MEMBER)))


def read_authenticated_github_checkpoint(token, max_age_hours):
    if not token:
        raise ValueError("GitHub direct mode needs a short-lived GH_TOKEN with Actions:read; use --checkpoint-file instead")
    data = github_api(f"actions/artifacts?name={ARTIFACT_NAME}&per_page=100", token)
    artifacts = [a for a in data.get("artifacts", []) if isinstance(a, dict)
                 and a.get("name") == ARTIFACT_NAME and a.get("expired") is False
                 and isinstance(a.get("workflow_run"), dict)
                 and a["workflow_run"].get("head_branch") == "main"
                 and a["workflow_run"].get("repository_id") == REPO_ID
                 and a["workflow_run"].get("head_repository_id") == REPO_ID]
    if not artifacts:
        raise ValueError("No valid, unexpired v3 checkpoint artifact")
    artifacts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    artifact = artifacts[0]
    timestamp = utcstamp(artifact["created_at"])
    age_hours = (datetime.now(timezone.utc) - timestamp).total_seconds() / 3600
    if age_hours < -0.1 or age_hours > max_age_hours:
        raise ValueError("Latest checkpoint is outside the permitted freshness window")
    run_id = artifact["workflow_run"].get("id")
    if not isinstance(run_id, int):
        raise ValueError("GitHub workflow run ID invalid")
    run = github_api(f"actions/runs/{run_id}", token)
    if (run.get("conclusion") != "success" or run.get("head_branch") != "main"
            or run.get("event") != "workflow_dispatch"
            or str(run.get("path", "")).split("@", 1)[0] != RUN_PATH):
        raise ValueError("Checkpoint did not come from approved successful workflow")
    artifact_id = artifact.get("id")
    if not isinstance(artifact_id, int):
        raise ValueError("Invalid checkpoint artifact ID")
    seen = download_github_zip(artifact_id, token)
    return seen, timestamp.isoformat(), round(age_hours, 2), "AUTHENTICATED_GITHUB_ARTIFACT_API"


def normalize_azure(seen, checkpoint_timestamp):
    return [{
        "cloud_provider": "AZURE", "record_kind": "AUDIT_OBSERVATION",
        "detection_id": "SOC-AZ-001", "record_key_digest": key,
        "event_type": "RBAC_CHANGE_OBSERVATION", "event_timestamp": None,
        "checkpoint_created_at": checkpoint_timestamp,
        "operation": record["kind"], "operation_status": record["outcome"],
        "severity": "INFO", "status": "OBSERVED", "response_action": "LOG_ONLY",
    } for key, record in sorted(seen.items())]


def aws_incident():
    import boto3
    from boto3.dynamodb.conditions import Attr
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    kw = {"FilterExpression": Attr("detection_id").eq("SOC-001")}
    found = []
    while True:
        result = table.scan(**kw)
        for item in result.get("Items", []):
            if (item.get("cloud_provider") == "AWS"
                    and item.get("detection_id") == "SOC-001"
                    and str(item.get("detected_at", "")).startswith("2026-10-25T02:06:45")):
                found.append(item)
        if "LastEvaluatedKey" not in result:
            break
        kw["ExclusiveStartKey"] = result["LastEvaluatedKey"]
    if len(found) != 1:
        raise ValueError("Expected one verified historical SOC-001 incident")
    item = found[0]
    incident_id = item.get("incident_id")
    if not isinstance(incident_id, str) or not incident_id:
        raise ValueError("Incident ID unavailable")
    severity = str(item.get("severity", "MEDIUM")).upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} or item.get("response_action") != "LOG_ONLY":
        raise ValueError("Unexpected historical incident fields")
    return [{
        "cloud_provider": "AWS", "record_kind": "SECURITY_INCIDENT",
        "detection_id": "SOC-001",
        "record_key_digest": hashlib.sha256(("aws-soc001:" + incident_id).encode()).hexdigest(),
        "event_type": "SSH_AUTH_FAILURE_ALARM",
        "event_timestamp": utcstamp(str(item["detected_at"])).isoformat(),
        "checkpoint_created_at": None, "operation": "CLOUDWATCH_ALARM_TRIGGERED",
        "operation_status": "ALARM", "severity": severity,
        "status": "DETECTED", "response_action": "LOG_ONLY",
    }]


def self_test():
    key = "a" * 64
    item = {"kind": "ROLE_ASSIGNMENT_WRITE", "outcome": "COMPLETED_REVIEW",
            "statuses": ["started", "succeeded"]}
    seen = validate_checkpoint({"version": 1, "seen": {key: item}})
    assert len(normalize_azure(seen, None)) == 1
    assert normalize_azure(seen, None)[0]["event_timestamp"] is None
    assert derived_outcome(["failed", "succeeded"]) == "CONFLICTING_REVIEW"
    assert derived_outcome(["started"]) == "PENDING_NOT_CONFIRMED"
    try:
        validate_checkpoint({"version": 1, "seen": {"not-a-hash": item}})
        raise AssertionError("Unsafe checkpoint identifier accepted")
    except ValueError:
        pass
    try:
        validate_checkpoint({"version": 1, "seen": {key: dict(item, outcome="FAILED_ATTEMPT_REVIEW")}})
        raise AssertionError("Inconsistent checkpoint status accepted")
    except ValueError:
        pass
    sample = normalize_azure(seen, None)
    blob = json.dumps(sample)
    assert all(x not in blob for x in ("subscriptionId", "tenantId", "caller", "resourceId", "incident_id"))
    assert utcstamp("2026-10-25T01:35:49Z").year == 2026
    print("PASS: Offline schema, outcome, privacy, time checks")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--checkpoint-file", type=Path, help="Local JSON extracted from v3 GitHub Actions checkpoint")
    p.add_argument("--max-age-hours", type=float, default=168)
    args = p.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        self_test()
        if args.checkpoint_file:
            seen, checkpoint_at, age, mode = read_local_checkpoint(args.checkpoint_file)
        else:
            seen, checkpoint_at, age, mode = read_authenticated_github_checkpoint(
                os.environ.get("GH_TOKEN", ""), args.max_age_hours)
        azure = normalize_azure(seen, checkpoint_at)
        aws = aws_incident()
        output = {
            "schema_version": "1.0",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "pipeline_mode": "ON_DEMAND_HISTORICAL_SNAPSHOT",
            "continuous_ingestion": False,
            "azure_source_mode": mode,
            "azure_provenance_verified_by_api": mode == "AUTHENTICATED_GITHUB_ARTIFACT_API",
            "azure_checkpoint_age_hours": age,
            "events": aws + azure,
        }
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
            f.write("\n")
        os.chmod(OUTPUT, 0o600)
        print(f"PASS: Azure checkpoint loaded ({mode})")
        print(f"PASS: {len(azure)} Azure RBAC observations normalized")
        print(f"PASS: {len(aws)} AWS SOC-001 incident read from DynamoDB")
        print(f"PASS: Unified dataset: {len(azure) + len(aws)} records")
        if age is None:
            print("LIMIT: Manually supplied checkpoint; original creation time/provenance not independently verified")
        print("LIMIT: Historical, manual/on-demand snapshot; not automatic cross-cloud delivery")
        print("PRIVACY: No raw Azure event content or AWS incident IDs displayed")
        print(f"OUTPUT: {OUTPUT}")
        print("OVERALL RESULT: PASS")
        return 0
    except Exception as error:
        # Error body, paths, and cloud identifiers are intentionally excluded.
        if isinstance(error, ValueError) and str(error).startswith("GitHub"):
            print(str(error), file=sys.stderr)
        else:
            print(f"INCOMPLETE: {type(error).__name__}; no verified unified snapshot", file=sys.stderr)
        print("Hint: download the latest v3 artifact from GitHub, extract its JSON, and run with --checkpoint-file", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
