#!/usr/bin/env python3
"""Read-only validation of the October 25, 2026 SOC-001 AWS lab test."""

import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

REGION = "us-east-2"
ALARM = "SOC001-SSH-BruteForce-5in5m"
LOG_GROUP = "/cloud-soc/ubuntu/security"
LAMBDA_LOG_GROUP = "/aws/lambda/cloud-soc-incident-processor"
TABLE = "cloud-soc-incidents"
TEST_MESSAGE = "Invalid user cloud-soc-test-invalid"
EXPECTED_EVENTS = 6


def utc(hour, minute, second=0):
    return datetime(2026, 10, 25, hour, minute, second, tzinfo=timezone.utc)


def milliseconds(value):
    return int(value.timestamp() * 1000)


def events_in_window(logs, group, start, end):
    pages = logs.get_paginator("filter_log_events").paginate(
        logGroupName=group,
        startTime=milliseconds(start),
        endTime=milliseconds(end),
    )
    for page in pages:
        yield from page.get("events", [])


results = []
context = {}


def run_check(label, check):
    try:
        passed, detail = check()
        status = "PASS" if passed else "FAIL"
    except (ClientError, BotoCoreError, ValueError, KeyError, TypeError) as exc:
        status = "INCOMPLETE"
        detail = f"Could not verify: {type(exc).__name__}: {exc}"
    results.append(status)
    print(f"{status}: {label} - {detail}")


logs = boto3.client("logs", region_name=REGION)
cloudwatch = boto3.client("cloudwatch", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)


def check_ssh_logs():
    events = list(events_in_window(logs, LOG_GROUP, utc(2, 5, 35), utc(2, 5, 45)))
    matched = [e for e in events if TEST_MESSAGE in e.get("message", "")]
    return len(matched) == EXPECTED_EVENTS, f"found {len(matched)}/{EXPECTED_EVENTS} SSH events"


def check_metric():
    alarms = cloudwatch.describe_alarms(AlarmNames=[ALARM]).get("MetricAlarms", [])
    if len(alarms) != 1:
        return False, "expected exactly one existing metric alarm"
    alarm = alarms[0]
    if not alarm.get("Namespace") or not alarm.get("MetricName"):
        return False, "alarm uses metric math; direct metric check needs adaptation"
    response = cloudwatch.get_metric_statistics(
        Namespace=alarm["Namespace"],
        MetricName=alarm["MetricName"],
        Dimensions=alarm.get("Dimensions", []),
        StartTime=utc(2, 0),
        EndTime=utc(2, 15),
        Period=300,
        Statistics=["Sum"],
    )
    values = [float(point["Sum"]) for point in response.get("Datapoints", [])]
    peak = max(values, default=0)
    return peak >= 5, f"maximum five-minute count = {peak:g} (threshold = 5)"


def check_alarm_history():
    pages = cloudwatch.get_paginator("describe_alarm_history").paginate(
        AlarmName=ALARM,
        HistoryItemType="StateUpdate",
        StartDate=utc(2, 5),
        EndDate=utc(2, 15),
    )
    for page in pages:
        for item in page.get("AlarmHistoryItems", []):
            data = json.loads(item.get("HistoryData") or "{}")
            old = data.get("oldState") or {}
            new = data.get("newState") or {}
            old_value = old.get("stateValue") or old.get("value")
            new_value = new.get("stateValue") or new.get("value")
            summary = item.get("HistorySummary", "").lower()
            if (old_value == "OK" and new_value == "ALARM") or (
                "from ok to in alarm" in summary
            ):
                return True, f"OK -> ALARM at {item['Timestamp'].isoformat()}"
    return False, "no OK -> ALARM transition in the expected test window"


def check_lambda_log():
    ids = set()
    for event in events_in_window(logs, LAMBDA_LOG_GROUP, utc(2, 6, 40), utc(2, 7, 15)):
        message = event.get("message", "")
        if "SOC_INCIDENT_STORED" not in message:
            continue
        first_brace = message.find("{")
        if first_brace < 0:
            continue
        try:
            payload = json.loads(message[first_brace:])
        except json.JSONDecodeError:
            continue
        incident = payload.get("incident") or {}
        if (
            payload.get("event_type") == "SOC_INCIDENT_STORED"
            and incident.get("alarm_name") == ALARM
            and incident.get("detection_id") == "SOC-001"
            and str(incident.get("detected_at", "")).startswith("2026-10-25T02:06:45")
            and incident.get("incident_id")
        ):
            ids.add(str(incident["incident_id"]))
    context["lambda_ids"] = ids
    return len(ids) == 1, f"found {len(ids)} matching stored-incident log(s)"


def check_dynamodb():
    ids = context.get("lambda_ids", set())
    if len(ids) != 1:
        raise ValueError("No unique Lambda incident ID to look up")

    incident_id = next(iter(ids))
    response = dynamodb.Table(TABLE).get_item(
        Key={"incident_id": incident_id},
        ConsistentRead=True,
    )
    item = response.get("Item")
    if not item:
        return False, "Lambda incident ID not found in DynamoDB"

    valid = (
        item.get("detection_id") == "SOC-001"
        and item.get("cloud_provider") == "AWS"
        and item.get("alarm_name") == ALARM
        and str(item.get("detected_at", "")).startswith("2026-10-25T02:06:45")
        and item.get("response_action") == "LOG_ONLY"
    )
    return valid, "Lambda incident ID found; expected attributes " + (
        "MATCH" if valid else "DO NOT MATCH"
    )


if __name__ == "__main__":
    print("SOC-001 HISTORICAL DETECTION VALIDATION | 2026-10-25 UTC")
    print("Read-only AWS checks. This does not test current pipeline health.\n")
    run_check("SSH log ingestion", check_ssh_logs)
    run_check("CloudWatch metric threshold", check_metric)
    run_check("CloudWatch alarm transition", check_alarm_history)
    run_check("Lambda stored-incident log", check_lambda_log)
    run_check("DynamoDB incident persistence", check_dynamodb)

    print("\nCURRENT TELEMETRY HEALTH: NOT TESTED (requires an independent heartbeat)")
    if all(status == "PASS" for status in results):
        print("OVERALL HISTORICAL RESULT: PASS")
        sys.exit(0)
    if "FAIL" in results:
        print("OVERALL HISTORICAL RESULT: FAIL")
        sys.exit(1)
    print("OVERALL HISTORICAL RESULT: INCOMPLETE")
    sys.exit(2)
