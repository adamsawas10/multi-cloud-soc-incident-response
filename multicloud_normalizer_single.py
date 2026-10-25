#!/usr/bin/env python3
"""Standalone, read-only historical Azure + AWS SOC event normalizer.

Includes two manually curated, privacy-minimized Azure Activity Log records.
Reads the previously verified AWS SOC-001 incident from DynamoDB.
Writes local JSON; does not configure, deploy, or change cloud resources.
Azure is not polled live in this version.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
EXPECTED_AWS_ALARM = "SOC001-SSH-BruteForce-5in5m"
EXPECTED_AWS_TIME_PREFIX = "2026-10-25T02:06:45"
SCHEMA = "cloud-soc-unified-v1"

# Historical Azure audit events; these are sanitized samples, NOT an Azure API feed.
AZURE_SAMPLE_EVENTS = [
    {
        "eventTimestamp": "2026-10-25T01:36:20.8133638Z",
        "category": {
            "value": "Administrative"
        },
        "operationName": {
            "value": "Microsoft.Authorization/policyAssignments/write"
        },
        "eventName": {
            "value": "BeginRequest"
        },
        "status": {
            "value": "Started"
        },
        "level": "Informational",
        "resourceType": {
            "value": "Microsoft.Authorization/policyAssignments"
        },
        "resourceProviderName": {
            "value": "Microsoft.Authorization"
        }
    },
    {
        "eventTimestamp": "2026-10-25T01:35:49.557765Z",
        "category": {
            "value": "Security"
        },
        "operationName": {
            "value": "Microsoft.Subscription/Subscriptions/write"
        },
        "eventName": {
            "value": ""
        },
        "status": {
            "value": "Succeeded"
        },
        "level": "Informational",
        "resourceType": {
            "value": ""
        },
        "resourceProviderName": {
            "value": ""
        }
    }
]


def field(record, key):
    value = record.get(key)
    if isinstance(value, dict):
        return str(value.get("value") or "").strip()
    return str(value or "").strip()


def stable_id(prefix, fields):
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return prefix + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def validate_utc_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("missing timezone in timestamp")
    return value


def azure_event_type(operation, source_status):
    lowered = operation.lower()
    if lowered == "microsoft.authorization/policyassignments/write":
        return "POLICY_ASSIGNMENT_" + (
            "STARTED" if source_status.lower() == "started" else "CHANGED"
        )
    if lowered == "microsoft.subscription/subscriptions/write":
        return "SUBSCRIPTION_CREATED" if source_status.lower() == "succeeded" else "SUBSCRIPTION_CHANGE"
    return "AZURE_ACTIVITY_OBSERVED"


def normalize_azure(record):
    operation = field(record, "operationName")
    category = field(record, "category")
    source_status = field(record, "status")
    timestamp = field(record, "eventTimestamp")
    level = field(record, "level")
    resource_type = field(record, "resourceType")

    if not all((operation, category, source_status, timestamp)):
        raise ValueError("missing Azure operation, category, status, or time")
    validate_utc_timestamp(timestamp)
    if level and level.lower() not in ("informational", "information"):
        # Unfamiliar levels should be reviewed, not silently mapped to INFO.
        raise ValueError("unrecognized Azure level; manual severity review required")

    identity = [operation, category, source_status, timestamp, resource_type]
    return {
        "schema_version": SCHEMA,
        "record_id": stable_id("azure-event-", identity),
        "record_type": "AUDIT_EVENT",
        "cloud_provider": "AZURE",
        "source_service": "Azure Activity Log",
        "event_type": azure_event_type(operation, source_status),
        "event_timestamp": timestamp,
        "operation": operation,
        "category": category,
        "severity": "INFO",
        "status": "OBSERVED",
        "source_status": source_status,
        "resource_type": resource_type or None,
        "response_action": "LOG_ONLY",
        "threat_confirmed": False,
        "evidence_type": "HISTORICAL_AUDIT_RECORD",
    }


def normalize_aws(item):
    """Use only whitelisted fields; never export original incident UUID or reason."""
    detected = str(item.get("detected_at") or "")
    validate_utc_timestamp(detected)
    raw_id = str(item.get("incident_id") or "")
    if not raw_id:
        raise ValueError("missing AWS incident ID")
    return {
        "schema_version": SCHEMA,
        "record_id": stable_id("aws-event-", [raw_id]),
        "record_type": "DETECTION_INCIDENT",
        "cloud_provider": "AWS",
        "source_service": "CloudWatch Alarm / Lambda / DynamoDB",
        "event_type": "SSH_AUTH_FAILURE_THRESHOLD",
        "event_timestamp": detected,
        "operation": str(item.get("alarm_name") or ""),
        "category": "DETECTION",
        "severity": str(item.get("severity") or "UNKNOWN"),
        "status": str(item.get("status") or "UNKNOWN"),
        "source_status": "ALARM",
        "resource_type": "EC2",
        "detection_id": str(item.get("detection_id") or ""),
        "response_action": str(item.get("response_action") or "UNKNOWN"),
        "threat_confirmed": False,
        "evidence_type": "HISTORICAL_CONTROLLED_TEST",
    }


def load_azure(path=None):
    if path is None:
        value = AZURE_SAMPLE_EVENTS
    else:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    if isinstance(value, dict):
        value = value.get("events", value.get("value"))
    if not isinstance(value, list):
        raise ValueError("Azure JSON must contain an event array")
    if not value:
        raise ValueError("Azure JSON contains no events")
    return [normalize_azure(v) for v in value]


def fetch_matching_aws(region, table_name):
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:
        raise RuntimeError("boto3 not installed (use AWS CloudShell)") from exc

    table = boto3.resource("dynamodb", region_name=region).Table(table_name)
    eligible = []
    cursor = None
    # Read up to 300 entries, with a hard cap to prevent unbounded scans.
    for _ in range(3):
        arguments = {"Limit": 100}
        if cursor:
            arguments["ExclusiveStartKey"] = cursor
        try:
            response = table.scan(**arguments)
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError("AWS DynamoDB read failed: " + str(exc)) from exc
        for item in response.get("Items", []):
            if (
                item.get("cloud_provider") == "AWS"
                and item.get("detection_id") == "SOC-001"
                and item.get("alarm_name") == EXPECTED_AWS_ALARM
                and str(item.get("detected_at", "")).startswith(EXPECTED_AWS_TIME_PREFIX)
                and item.get("response_action") == "LOG_ONLY"
            ):
                eligible.append(item)
        cursor = response.get("LastEvaluatedKey")
        if not cursor:
            break
    if cursor:
        raise RuntimeError("Scan limit reached; unable to establish a complete match")
    if len(eligible) != 1:
        raise RuntimeError(f"Expected exactly 1 historical SOC-001 AWS incident; found {len(eligible)}")
    return normalize_aws(eligible[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azure-file", type=Path, default=None,
                        help="Optional sanitized JSON file; otherwise use embedded historical sample")
    parser.add_argument("--aws-mode", choices=("live", "skip"), default="live")
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--table", default="cloud-soc-incidents")
    parser.add_argument("--output", type=Path, default=Path.home() / "soc-normalizer" / "output" / "unified_events.json")
    args = parser.parse_args()

    try:
        azure = load_azure(args.azure_file)
        print(f"PASS: Parsed and normalized {len(azure)} Azure historical audit event(s) (bundled, sanitized)")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print("INCOMPLETE: Azure input could not be verified:", exc)
        return 2

    records = list(azure)
    aws_verified = False
    if args.aws_mode == "live":
        try:
            aws = fetch_matching_aws(args.region, args.table)
            records.append(aws)
            aws_verified = True
            print("PASS: Found and normalized the historical AWS SOC-001 incident")
        except (RuntimeError, ValueError) as exc:
            print("INCOMPLETE: AWS live read was not verified:", exc)
    else:
        print("INCOMPLETE: AWS read intentionally skipped")

    records.sort(key=lambda x: (x["event_timestamp"], x["record_id"]))
    result = {
        "schema_version": SCHEMA,
        "mode": "READ_ONLY_HISTORICAL_NORMALIZATION",
        "source_status": "Azure curated historical records; AWS read from DynamoDB" if aws_verified
                         else "Azure historical records only; AWS unverified",
        "continuous_azure_ingestion": False,
        "cross_cloud_incident_delivery": False,
        "event_count": len(records),
        "providers": sorted({r["cloud_provider"] for r in records}),
        "records": records,
    }
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except OSError as exc:
        print("INCOMPLETE: Cannot save output:", exc)
        return 2

    print("OUTPUT:", args.output)
    print("PROVIDERS:", ", ".join(result["providers"]))
    if aws_verified and len(azure) >= 1 and len(result["providers"]) == 2:
        print("PASS: Unified AWS + Azure historical event dataset written")
        print("NOT YET DONE: Live Azure polling, cross-cloud delivery, alerting, response")
        return 0
    print("INCOMPLETE: AWS + Azure unified data not fully verified")
    return 2


if __name__ == "__main__":
    sys.exit(main())
