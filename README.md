
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

### Verified AWS End-to-End Test — October 25, 2026 (UTC)

Six controlled invalid-user SSH attempts were recorded on Ubuntu EC2 and ingested into CloudWatch Logs.

- CloudWatch SSH authentication failure metric reached 6.
- The SOC-001 alarm entered ALARM at 02:06:45 UTC, approximately 67 seconds after the test.
- The SNS notification action executed successfully.
- AWS Lambda executed and recorded `SOC_INCIDENT_STORED`.
- A matching new security incident was independently confirmed in DynamoDB.

**Limitations:** Detection remains instance-wide rather than per-source-IP. Response is currently `LOG_ONLY`. EventBridge delivery metrics were not independently inspected for this run. Azure integration and automatic containment remain planned.


### Live SSH Telemetry Validation — October 25, 2026 (UTC)

A controlled, unauthenticated SSH connection was generated locally on the Ubuntu EC2 instance to verify the active security log ingestion pipeline.

**Results:**
- The OpenSSH service responded successfully.
- The Ubuntu SSH journal recorded a new connection on an ephemeral local port.
- The corresponding connection event was independently retrieved from Amazon CloudWatch Logs using AWS CLI.
- The live EC2-to-CloudWatch telemetry path passed this point-in-time validation.

**Limitations:** This test demonstrates successful ingestion of a new event. It does not establish continuous monitoring availability or test failure recovery. Scheduled heartbeat validation remains planned.

## Current Limitations

- The detection counts authentication failures across the monitored instance rather than correlating them by source IP.
- Automated response currently records incidents; it does not perform IP blocking or host isolation.
- Incident enrichment and multi-cloud correlation are not yet implemented.
- Azure integration is not yet complete.


### AWS + Azure API-Backed Event Normalization — October 25, 2026 (UTC)

Implemented and tested a Python-based multi-cloud event normalization workflow.

**Verified results:**
- Retrieved three real Azure Activity Log events through Azure CLI.
- Sanitized audit data to exclude subscription identifiers, caller identities, and authentication claims.
- Retrieved the previously validated AWS SOC-001 incident from DynamoDB.
- Normalized one AWS incident and three Azure audit observations into a common JSON schema.
- Passed four offline checks and the live-data normalization test with exit code 0.

**Current limitation:** Azure events are transferred manually between cloud environments. Automatic ingestion, continuous monitoring, cross-cloud alerting, and response orchestration remain planned.




### SOC-AZ-001 — Azure RBAC Change Detection - October 26, 2026 (UTC)

Implemented an automated, read-only Azure RBAC monitoring workflow using GitHub Actions and Microsoft Entra OIDC authentication.

**Verified capabilities:**
- Successful GitHub-to-Azure federated authentication.
- Azure Activity Log retrieval and detection workflow execution.
- Five built-in tests covering successful, pending, failed, and unrelated administrative operations.
- Classification of privileged-access changes into human-review signals.
- Privacy-conscious logging without publishing raw Azure audit records.

**Validation:** GitHub Actions run #1 succeeded on October 26, 2026.

**Limitations:** The workflow executes manually, queries up to 200 events from a seven-day window, and does not yet provide continuous monitoring, deduplication, incident persistence, or automatic response. A successful run does not establish that a real RBAC change was detected.





### SOC-AZ-001 v3 — Cross-Run Detection Tracking (October 26, 2026)

Implemented privacy-conscious Azure RBAC event tracking using GitHub Actions, Microsoft Entra OIDC, and retention-limited checkpoint artifacts.

**Verified Results:**
- Successfully retrieved 9 real Azure Activity Log events.
- Inspected 4 RBAC records and grouped them into 2 candidate operations.
- Confirmed all inspected RBAC records had stable identifiers.
- First workflow run successfully established the baseline checkpoint.
- Second workflow run successfully restored the previous checkpoint.
- Confirmed 0 new review signals and 0 updated review signals during the second run.
- Both GitHub Actions executions completed successfully.
- Checkpoint artifacts contain hashed operation identifiers and classification states rather than raw Azure audit records.

**Security Controls:**
- Read-only Azure permissions with OIDC authentication.
- No permanent cloud credentials or additional Azure infrastructure.
- No automatic blocking or resource modifications.
- Privacy-conscious logging and duplicate-alert suppression.

**Limitations:** Execution remains manual. Checkpoints are retention-limited GitHub Actions artifacts rather than permanent incident storage. Automated scheduling, durable incident persistence, and cross-cloud response orchestration remain future milestones.


## Roadmap

- [x] AWS cloud infrastructure
- [x] Centralized Linux security monitoring
- [x] SSH authentication-failure detection
- [x] Automated security notifications
- [x] EventBridge and Lambda incident processing
- [x] DynamoDB incident storage
- [x] Complete integrated AWS detection-to-storage validation
- [ ] Microsoft Azure security telemetry integration
- [ ] Unified multi-cloud incident processing
- [ ] Incident enrichment and safe response actions
- [ ] Architecture documentation and final demonstration

## Project Purpose

This project is being developed to strengthen practical skills in cloud security, Linux administration, detection engineering, IAM, Python automation, and incident response.

It is an educational security lab and portfolio project, not a production SOC deployment.
