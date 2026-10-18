
# Multi-Cloud SOC & Automated Incident Response Platform

**Status:** In Progress | AWS Implementation Operational | Azure Integration Planned

## Overview

A hands-on cloud security engineering project focused on building a Security Operations Center (SOC) workflow across AWS and Microsoft Azure.

The project explores security log collection, threat detection, event-driven automation, and centralized incident management.

The AWS implementation currently detects repeated SSH authentication failures, generates security alerts, processes alarm events using AWS Lambda, and stores structured incident records in Amazon DynamoDB.

Microsoft Azure integration and additional incident response capabilities are planned.

## Architecture

Current AWS workflow:

Ubuntu EC2
    |
    v
CloudWatch Agent
    |
    v
CloudWatch Logs
    |
    v
Metric Filter + CloudWatch Alarm
    |
    +----> Amazon SNS (Email Alerts)
    |
    v
Amazon EventBridge
    |
    v
AWS Lambda (Python)
    |
    v
Amazon DynamoDB (Incident Storage)

## Technologies

- **Cloud:** Amazon Web Services (AWS)
- **Networking:** VPC, Subnets, Route Tables, Security Groups
- **Systems:** Ubuntu Linux, SSH
- **Monitoring:** CloudWatch Logs, Metric Filters, CloudWatch Alarms
- **Automation:** EventBridge, AWS Lambda, Python, Boto3
- **Notifications:** Amazon SNS
- **Storage:** Amazon DynamoDB
- **Access Control:** AWS IAM
- **Planned:** Microsoft Azure

## Implemented Features

### 1. Security Monitoring
- Deployed an Ubuntu EC2 instance in a custom VPC.
- Configured CloudWatch Agent to collect SSH authentication events.
- Centralized authentication logs in CloudWatch Logs.

### 2. SSH Threat Detection
- Created a metric filter for failed and invalid SSH authentication attempts.
- Configured an alarm threshold of five failures within a five-minute CloudWatch period.
- Integrated Amazon SNS for email notifications.

### 3. Event-Driven Incident Processing
- Configured EventBridge to detect relevant CloudWatch alarm-state changes.
- Developed a Python Lambda function to create structured security incident records.
- Recorded incident severity, detection ID, timestamp, and alarm context.

### 4. Persistent Incident Storage
- Created a DynamoDB table for incident records.
- Configured least-privilege IAM permissions for Lambda database writes.
- Implemented duplicate incident protection using conditional writes.

## Testing and Validation

Completed tests include:

- Generated controlled failed SSH authentication attempts.
- Verified that Ubuntu recorded the authentication events.
- Confirmed log ingestion into CloudWatch.
- Troubleshot a metric filter mismatch involving nested JSON log fields.
- Verified automatic CloudWatch alarm activation and SNS email delivery.
- Verified EventBridge-triggered Lambda execution.
- Tested Lambda incident processing and DynamoDB storage.
- Retrieved a saved incident directly from DynamoDB.

A final integrated test from live SSH detection through DynamoDB storage is still pending.

## Current Limitations

- The detection counts authentication failures across the monitored instance rather than correlating them by source IP.
- Automated response currently records incidents; it does not perform IP blocking or host isolation.
- Incident enrichment and multi-cloud correlation are not yet implemented.
- Azure integration is not yet complete.

## Roadmap

- [x] AWS cloud infrastructure
- [x] Centralized Linux security monitoring
- [x] SSH authentication-failure detection
- [x] Automated security notifications
- [x] EventBridge and Lambda incident processing
- [x] DynamoDB incident storage
- [ ] Complete integrated AWS detection-to-storage validation
- [ ] Microsoft Azure security telemetry integration
- [ ] Unified multi-cloud incident processing
- [ ] Incident enrichment and safe response actions
- [ ] Architecture documentation and final demonstration

## Project Purpose

This project is being developed to strengthen practical skills in cloud security, Linux administration, detection engineering, IAM, Python automation, and incident response.

It is an educational security lab and portfolio project, not a production SOC deployment.
