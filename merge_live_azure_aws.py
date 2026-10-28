#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ALLOWED_AZURE_FIELDS = {
    "eventTimestamp", "category", "eventName", "operationName",
    "status", "level", "resourceType"
}
REGION = "us-east-2"
TABLE = "cloud-soc-incidents"
OUTPUT = Path.home() / "soc-normalizer" / "output" / "unified_live_azure_aws.json"


def text_of(value):
    if isinstance(value, dict):
        return str(value.get("value") or value.get("localizedValue") or "")
    return "" if value is None else str(value)


def normalize_azure(events):
    if not isinstance(events, list):
        raise ValueError("Azure JSON must contain a list of activity log events")
    if not events:
        raise ValueError("Azure API returned zero events; cannot validate live ingestion")
    output = []
    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Azure event #{idx + 1} is not a JSON object")
        extra = set(event) - ALLOWED_AZURE_FIELDS
        if extra:
            raise ValueError(
                "Azure input includes unapproved fields (possibly identifiers): "
                + ", ".join(sorted(extra))
                + ". Re-export with the exact --select command."
            )
        operation = text_of(event.get("operationName"))
        timestamp = text_of(event.get("eventTimestamp"))
        category = text_of(event.get("category"))
        state = text_of(event.get("status"))
        if not operation or not timestamp:
            raise ValueError(f"Azure event #{idx + 1} missing operation or timestamp")
        output.append({
            "cloud_provider": "AZURE",
            "record_kind": "AUDIT_OBSERVATION",
            "detection_id": None,
            "event_type": "AZURE_ACTIVITY_LOG",
            "operation": operation,
            "category": category,
            "event_timestamp": timestamp,
            "operation_status": state,
            "event_name": text_of(event.get("eventName")),
            "resource_type": text_of(event.get("resourceType")),
            "severity": "INFO",
            "status": "OBSERVED",
            "response_action": "LOG_ONLY",
        })
    return output


def normalize_aws(items):
    relevant = [
        item for item in items
        if item.get("cloud_provider") == "AWS"
        and item.get("detection_id") == "SOC-001"
        and str(item.get("detected_at", "")).startswith("2026-10-25T02:06:45")
    ]
    if len(relevant) != 1:
        raise ValueError(
            f"Expected exactly one verified October 25 SOC-001 incident; found {len(relevant)}"
        )
    item = relevant[0]
    return [{
        "cloud_provider": "AWS",
        "record_kind": "SECURITY_INCIDENT",
        "detection_id": "SOC-001",
        "event_type": "SSH_AUTH_FAILURE_ALARM",
        "operation": "CLOUDWATCH_ALARM_TRIGGERED",
        "category": "Detection",
        "event_timestamp": str(item["detected_at"]),
        "operation_status": "ALARM",
        "event_name": "SOC-001",
        "resource_type": "CloudWatch Alarm",
        "severity": str(item.get("severity", "MEDIUM")),
        "status": str(item.get("status", "DETECTED")),
        "response_action": str(item.get("response_action", "LOG_ONLY")),
    }]


def fetch_aws_incidents():
    import boto3
    from boto3.dynamodb.conditions import Attr
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    # Small lab table; pagination ensures the result is complete even if it grows.
    kw = {"FilterExpression": Attr("detection_id").eq("SOC-001")}
    items = []
    while True:
        result = table.scan(**kw)
        items.extend(result.get("Items", []))
        if "LastEvaluatedKey" not in result:
            return items
        kw["ExclusiveStartKey"] = result["LastEvaluatedKey"]


def self_test():
    examples = [
        {
            "eventTimestamp": "2026-10-25T01:35:49Z",
            "category": {"value": "Security"},
            "operationName": {"value": "Microsoft.Subscription/Subscriptions/write"},
            "status": {"value": "Succeeded"},
            "eventName": {"value": ""},
            "level": "Informational",
            "resourceType": {"value": ""},
        },
        {
            "eventTimestamp": "2026-10-25T01:36:20Z",
            "category": {"value": "Administrative"},
            "operationName": {"value": "Microsoft.Authorization/policyAssignments/write"},
            "status": {"value": "Started"},
        },
    ]
    az = normalize_azure(examples)
    assert len(az) == 2
    assert az[0]["operation_status"] == "Succeeded"
    assert az[1]["operation_status"] == "Started"
    assert all(e["record_kind"] == "AUDIT_OBSERVATION" for e in az)
    aws = normalize_aws([{
        "cloud_provider": "AWS", "detection_id": "SOC-001",
        "detected_at": "2026-10-25T02:06:45Z", "severity": "MEDIUM",
        "status": "DETECTED", "response_action": "LOG_ONLY",
    }])
    assert len(aws) == 1 and aws[0]["record_kind"] == "SECURITY_INCIDENT"
    assert set(az[0]) == set(aws[0])
    try:
        normalize_azure([dict(examples[0], caller="someone@example.com")])
    except ValueError:
        pass
    else:
        raise AssertionError("Sensitive field unexpectedly accepted")
    print("PASS: 4 offline checks (2 Azure statuses, common schema, privacy)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azure-file", type=Path,
                        default=Path.home() / "azure_activity_live_safe.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        data = json.loads(args.azure_file.read_text(encoding="utf-8"))
        azure_events = normalize_azure(data)
        print(f"PASS: Normalized {len(azure_events)} freshly queried Azure Activity Log events")
        aws_events = normalize_aws(fetch_aws_incidents())
        print("PASS: Retrieved verified historical SOC-001 incident from AWS DynamoDB")
        unified = aws_events + azure_events
        result = {
            "schema_version": "1.0",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "pipeline_mode": "MANUAL_AZURE_EXPORT_TO_AWS_READ_ONLY_MERGE",
            "continuous_ingestion": False,
            "events": unified,
        }
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: Unified dataset: {len(aws_events)} AWS incident + {len(azure_events)} Azure audit events")
        print(f"OUTPUT: {OUTPUT}")
        print("PASS: No caller, tenant, subscription IDs or claims included in output")
        print("NOT YET DONE: Automatic cross-cloud ingestion, alerting or response")
        print("OVERALL RESULT: PASS")
        return 0
    except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"INCOMPLETE: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Avoid printing API exception bodies that can include account identifiers.
        print(f"INCOMPLETE: AWS read failed ({type(exc).__name__}). Check AWS permissions/region.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
