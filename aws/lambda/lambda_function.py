
import json
import logging
import boto3

from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

EXPECTED_ALARM = "SOC001-SSH-BruteForce-5in5m"
TABLE_NAME = "cloud-soc-incidents"

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    detail = event.get("detail", {})
    state = detail.get("state", {})
    alarm_name = detail.get("alarmName")

  
    if (
        event.get("source") != "aws.cloudwatch"
        or event.get("detail-type") != "CloudWatch Alarm State Change"
        or alarm_name != EXPECTED_ALARM
        or state.get("value") != "ALARM"
    ):
        logger.info("Event ignored: not a matching SOC alarm.")
        return {
            "statusCode": 200,
            "result": "IGNORED"
        }

    
    incident = {
        "incident_id": event.get("id") or context.aws_request_id,
        "detected_at": event.get("time"),
        "cloud_provider": "AWS",
        "region": event.get("region"),
        "detection_id": "SOC-001",
        "alarm_name": alarm_name,
        "severity": "MEDIUM",
        "status": "DETECTED",
        "reason": state.get("reason", "Unknown"),
        "source_ip": None,
        "response_action": "LOG_ONLY"
    }

   
    try:
        table.put_item(
            Item=incident,
            ConditionExpression="attribute_not_exists(incident_id)"
        )

    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info(
                "Duplicate incident ignored: %s",
                incident["incident_id"]
            )
            return {
                "statusCode": 200,
                "result": "INCIDENT_ALREADY_EXISTS"
            }

        logger.exception("Failed to save incident in DynamoDB")
        raise

   
    logger.warning(json.dumps({
        "event_type": "SOC_INCIDENT_STORED",
        "incident": incident
    }))

    return {
        "statusCode": 200,
        "result": "INCIDENT_STORED",
        "incident": incident
    }
