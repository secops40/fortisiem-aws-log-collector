# FortiSIEM AWS Log Collector

FortiSIEM AWS Log Collector is a lightweight utility designed to run directly on a **FortiSIEM node**.

It receives Amazon S3 event notifications through either `S3 -> SQS` or `S3 -> SNS -> SQS`, retrieves the referenced S3 log objects (gzip or plain text, any file name), adds FortiSIEM-compatible metadata to every log line, and writes the processed gzip files locally for FortiSIEM ingestion.

The processed log directory is linked into the FortiSIEM syslog cache, for example:

`/opt/phoenix/cache/syslog/98.87.170.71 -> /usr/local/fortisiem-aws-log-collector/logs/processed`

> **Note:** This is a community project and is not an official Fortinet product.

---

## Features

- Designed to run directly on a FortiSIEM node
- Supports `S3 -> SQS`
- Supports `S3 -> SNS -> SQS`
- Supports SNS Raw Message Delivery
- Automatically detects the SQS message format
- Supports multiple SQS queues concurrently
- Supports independent AWS credentials and regions per log source
- Supports EC2 IAM Role through the standard boto3 credential chain
- Optionally saves the original S3 objects for debugging
- Adds a configurable **Log Keyword** and FortiSIEM metadata to every log line (standard log types)
- Supports AWS Security Hub findings in EventBridge JSON format (plain or gzip JSON), one output line per finding
- Accepts gzip or plain-text objects with any file name (including extension-less Kinesis Firehose objects)
- Always writes processed logs as `.gz`
- Supports a flat processed-log directory
- Prefixes processed filenames with the configured log name
- Prevents known filename collisions in flat-output mode
- Uses SQLite for duplicate-event tracking
- Uses SQS long polling
- Extends SQS message visibility while a message is being processed
- Deletes an SQS message only after successful processing
- Runs as a systemd service under `admin:admin`
- Compatible with Python 3.9+

---

## Architecture

```text
                    +----------------+
                    |     AWS S3     |
                    +-------+--------+
                            |
             +--------------+--------------+
             |                             |
             v                             v
        +---------+                    +---------+
        |   SQS   |                    |   SNS   |
        +----+----+                    +----+----+
             |                              |
             |                              v
             |                         +---------+
             |                         |   SQS   |
             |                         +----+----+
             |                              |
             +---------------+--------------+
                             |
                             v
                  +---------------------+
                  | AWS Log Collector   |
                  +----------+----------+
                             |
                  +----------+----------+
                  |                     |
                  v                     v
          Optional Raw Logs      Processed Logs
          logs/raw/              logs/processed/
                                      |
                                      v
                       /opt/phoenix/cache/syslog/
                              <reptDevIpAddr>
```

The collector determines the message format automatically. No setting is required to choose between `S3 -> SQS` and `S3 -> SNS -> SQS`.

When SNS Raw Message Delivery is enabled, the SQS body has the same effective S3 event structure as a direct `S3 -> SQS` notification, so both are handled by the same parser path.

---

## Log Transformation

Each source log line is transformed into:

```text
<Log Keyword>:phCustId=<id>,reptDevIpAddr=<ip>,reptDevName=<name>,msg=<original log line>
```

Example configuration:

```json
{
  "log_keyword": "VPCFlow log",
  "phCustId": "1",
  "reptDevIpAddr": "98.87.170.71",
  "reptDevName": "amazon.com"
}
```

Original VPC Flow Log line:

```text
2 700000000000 eni-123456 10.0.0.1 8.8.8.8 12345 443 6 10 500 ACCEPT OK
```

Processed line:

```text
VPCFlow log:phCustId=1,reptDevIpAddr=98.87.170.71,reptDevName=amazon.com,msg=2 700000000000 eni-123456 10.0.0.1 8.8.8.8 12345 443 6 10 500 ACCEPT OK
```

### AWS Security Hub

Security Hub findings use a different output format. Each finding is written as one line without the FortiSIEM metadata prefix:

```text
[AWS_SECURITY_HUB_EVENT_DATA] = {"SchemaVersion":"2018-10-08","Id":"arn:aws:securityhub:..."}
```

To enable Security Hub mode, set `log_keyword` to the reserved value:

```json
"log_keyword": "AWS_SECURITY_HUB_EVENT_DATA"
```

The collector parses the EventBridge envelope and writes one line per finding. See [Supported Object Format](#supported-object-format) for accepted input.

---

### S3 Key Filter (`s3_key_include_regex`)

Optional, per collector. When set, only S3 objects whose key matches the regular expression (`re.search`) are processed. Non-matching objects are skipped, logged at INFO, and treated as handled, so the SQS message is deleted and no error is raised. When omitted, nothing is filtered.

Typical use: a CloudTrail bucket also contains `CloudTrail-Digest/` and `Config/` objects. Process only `CloudTrail/`:

```json
"s3_key_include_regex": "/CloudTrail/"
```

`/CloudTrail/` (with slashes) does not match `/CloudTrail-Digest/`, and it also works for Organization trails (`AWSLogs/o-xxxx/<account id>/CloudTrail/...`). The `log` value may be any unique label, for example `cloudtrail-acct1` and `cloudtrail-acct2`. It does not need to be exactly `cloudtrail`.

If you can, also configure a prefix or suffix filter on the S3 Event Notification so unwanted objects never reach SQS.

---

### CloudTrail Records Splitting

When `log_keyword` starts with `AWS_S3_LOG_CLOUDTRAIL`, the collector parses each CloudTrail file (`{"Records":[...]}`) and writes **one record per line**, using the same prefix as other log types:

```
AWS_S3_LOG_CLOUDTRAIL:phCustId=1,reptDevIpAddr=...,reptDevName=...,msg={"eventVersion":"1.11",...}
```

A file without a `Records` array is treated as an error. An empty `Records` array produces an empty output. Combine with `s3_key_include_regex: "/CloudTrail/"` so Digest and Config files are never parsed.

---

### Log Keyword

`log_keyword` is the text written at the beginning of every processed log line (standard log types).

Examples:

```json
"log_keyword": "VPCFlow log"
```

```json
"log_keyword": "GuardDuty log"
```

The previous `logmark` configuration name has been replaced by `log_keyword`. The collector still accepts `logmark` as a backward-compatibility fallback for older configurations, but new configurations should use `log_keyword`.

---

## Directory Layout

Recommended installation path:

```text
/usr/local/fortisiem-aws-log-collector/
├── collector.py
├── config.json
├── config.json.example
├── requirements.txt
├── fortisiem-aws-log-collector.service
├── README.md
├── venv/
└── logs/
    ├── state.db
    ├── processed/
    └── raw/              # created/used only when write_raw_logs=true
```

### Processed Logs

The recommended setting is:

```json
"preserve_s3_path": false
```

With this setting, processed logs are written into a single flat directory:

```text
/usr/local/fortisiem-aws-log-collector/logs/processed/
├── vpcflow_xxxxx1.log.gz
├── vpcflow_xxxxx2.log.gz
├── guardduty_xxxxx1.jsonl.gz
├── guardduty_xxxxx2.jsonl.gz
└── securityhub_<delivery-stream-name>-1-YYYY-MM-DD-HH-MM-SS-<uuid>.gz
```

The filename format is:

```text
<log>_<original-filename>
```

For example:

```text
vpcflow_700000000000_vpcflowlogs_us-west-2_xxxxx.log.gz
```

Output is always gzip. A name already ending in `.gz` is kept; any other name (including no extension) gets `.gz` appended.

Re-delivered events for the same S3 object always resolve to the same output filename.

If `preserve_s3_path` is `true`, processed files preserve the `<log>/<bucket>/<S3 object key>` hierarchy instead.

---

## Optional Raw Logs

Saving the original S3 objects is optional and is primarily intended for debugging or parser troubleshooting.

The recommended production setting is:

```json
"write_raw_logs": false
```

With `write_raw_logs=false`:

- the original S3 object is **not** saved under `logs/raw`
- the source gzip object is streamed from S3
- only the processed gzip file is persisted locally

To keep the original S3 objects temporarily for debugging:

```json
"write_raw_logs": true
```

Raw files are then stored under `raw_dir` while preserving the original S3 hierarchy:

```text
logs/raw/
└── vpcflow/
    └── my-log-bucket/
        └── AWSLogs/
            └── 700000000000/
                └── vpcflowlogs/
                    └── us-west-2/
                        └── 2026/
                            └── 07/
                                └── 28/
                                    └── original.log.gz
```

`write_raw_logs` can be configured globally or overridden for an individual collector.

---

# Configuration

Create `config.json` from the supplied example file and adjust it for your environment.

Example:

```json
{
  "log_level": "INFO",
  "raw_dir": "/usr/local/fortisiem-aws-log-collector/logs/raw",
  "output_dir": "/usr/local/fortisiem-aws-log-collector/logs/processed",
  "state_db": "/usr/local/fortisiem-aws-log-collector/logs/state.db",
  "write_raw_logs": false,
  "preserve_s3_path": false,
  "visibility_timeout": 300,
  "visibility_heartbeat": 120,
  "wait_time_seconds": 20,
  "max_messages": 5,
  "collectors": [
    {
      "log": "vpcflow",
      "sqs": "https://sqs.us-west-2.amazonaws.com/700000000000/vpcflow",
      "region": "us-west-2",
      "aws_access_key_id": "AKIAxxxxxxxxxxxxxxxx",
      "aws_secret_access_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "aws_session_token": "",
      "log_keyword": "VPCFlow log",
      "phCustId": "1",
      "reptDevIpAddr": "98.87.170.71",
      "reptDevName": "amazon.com"
    },
    {
      "log": "guardduty",
      "sqs": "https://sqs.us-west-2.amazonaws.com/700000000000/guardduty",
      "region": "us-west-2",
      "log_keyword": "GuardDuty log",
      "phCustId": "1",
      "reptDevIpAddr": "98.87.170.71",
      "reptDevName": "amazon.com"
    }
  ]
}
```

## Global and Per-Collector Settings

The following settings can be defined globally and overridden per collector:

- `process_mode`
- `write_raw_logs`
- `preserve_s3_path`
- `raw_dir`
- `output_dir`
- `workers` (parallel pollers for one queue, 1-32)
- `max_messages` (messages per SQS poll, 1-10)
- SQS polling and visibility settings

For example, raw logging can remain disabled globally but be enabled temporarily for one source:

```json
{
  "write_raw_logs": false,
  "collectors": [
    {
      "log": "vpcflow",
      "write_raw_logs": true
    }
  ]
}
```

---

## AWS Credentials

Credentials are configured independently for each collector. This allows different log sources to use different AWS accounts.

### Static Credentials

```json
{
  "aws_access_key_id": "AKIAxxxxxxxxxxxxxxxx",
  "aws_secret_access_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "aws_session_token": ""
}
```

`aws_session_token` is optional and is used for temporary STS credentials.

The same collector-specific AWS session is used for both SQS and S3 access.

### EC2 IAM Role / Default boto3 Credential Chain

If `aws_access_key_id` and `aws_secret_access_key` are omitted, the collector uses the standard boto3 credential provider chain.

This allows an EC2-hosted FortiSIEM node to use its attached Instance IAM Role without storing static credentials in `config.json`.

---

## Required AWS Permissions

Typical permissions are:

```text
sqs:ReceiveMessage
sqs:DeleteMessage
sqs:ChangeMessageVisibility
s3:GetObject
s3:GetObjectVersion
```

If the S3 objects are encrypted with SSE-KMS, the AWS identity may also require:

```text
kms:Decrypt
```

The collector does not call SNS directly. In an `S3 -> SNS -> SQS` architecture, SNS only delivers the S3 notification to SQS.

---

# Installation on FortiSIEM

This project is intended to be installed directly on a FortiSIEM node under:

```text
/usr/local/fortisiem-aws-log-collector
```

The installation procedure intentionally does **not** install, replace, or upgrade the FortiSIEM operating system's Python packages. It uses the Python already available on the system only to create an isolated virtual environment under the project directory.

## Clone the Repository

```bash
cd /usr/local

sudo git clone \
  https://github.com/secops40/fortisiem-aws-log-collector.git \
  fortisiem-aws-log-collector
```

Set ownership:

```bash
sudo chown -R admin:admin /usr/local/fortisiem-aws-log-collector
```

Change to the project directory:

```bash
cd /usr/local/fortisiem-aws-log-collector
```

---

## Create the Python Virtual Environment

Use the existing Python on the FortiSIEM node to create an isolated virtual environment:

```bash
sudo -u admin python3 -m venv \
  /usr/local/fortisiem-aws-log-collector/venv
```

Upgrade pip **inside the virtual environment only**:

```bash
sudo -u admin /usr/local/fortisiem-aws-log-collector/venv/bin/pip \
  install --upgrade pip
```

Install the collector dependencies into the virtual environment:

```bash
sudo -u admin /usr/local/fortisiem-aws-log-collector/venv/bin/pip \
  install -r /usr/local/fortisiem-aws-log-collector/requirements.txt
```

No packages are installed into the FortiSIEM system Python environment.

---

## Create the Configuration

```bash
cd /usr/local/fortisiem-aws-log-collector
sudo -u admin cp config.json.example config.json
sudo -u admin vi config.json
```

If `config.json` contains AWS credentials, restrict its permissions:

```bash
sudo chmod 600 /usr/local/fortisiem-aws-log-collector/config.json
sudo chown admin:admin /usr/local/fortisiem-aws-log-collector/config.json
```

Never commit a `config.json` containing real AWS credentials to GitHub.

Recommended `.gitignore` entries:

```text
config.json
venv/
logs/
*.db
*.db-shm
*.db-wal
__pycache__/
*.pyc
```

---

## Create the Runtime Directory

For the recommended production configuration with `write_raw_logs=false`:

```bash
sudo mkdir -p /usr/local/fortisiem-aws-log-collector/logs/processed
sudo chown -R admin:admin /usr/local/fortisiem-aws-log-collector/logs
```

If raw logging is enabled for debugging, the collector creates the required `logs/raw` hierarchy automatically.

---

# Validate the Configuration

Run the configuration check as `admin`:

```bash
sudo -u admin /usr/local/fortisiem-aws-log-collector/venv/bin/python \
  /usr/local/fortisiem-aws-log-collector/collector.py --check-config
```

Expected output includes:

```text
Configuration OK
```

---

# Run in Foreground

Before enabling the service, run the collector manually as `admin`:

```bash
sudo -u admin /usr/local/fortisiem-aws-log-collector/venv/bin/python \
  /usr/local/fortisiem-aws-log-collector/collector.py
```

This matches the user and group used by the systemd service, so newly created files should be owned by `admin:admin`.

Typical startup log:

```text
Starting collector=vpcflow region=us-west-2 credentials=config queue=https://...
```

For a direct S3 notification or SNS Raw Message Delivery, the collector logs a direct/raw S3 message format. For a normal SNS envelope, it logs `S3 -> SNS -> SQS` internally.

Press `Ctrl+C` to stop foreground mode.

---

# Install as a systemd Service

The repository includes:

```text
fortisiem-aws-log-collector.service
```

The supplied service runs as:

```ini
User=admin
Group=admin
```

Install the service file:

```bash
sudo cp \
  /usr/local/fortisiem-aws-log-collector/fortisiem-aws-log-collector.service \
  /etc/systemd/system/fortisiem-aws-log-collector.service
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable the service at boot and start it immediately:

```bash
sudo systemctl enable --now fortisiem-aws-log-collector
```

Check status:

```bash
sudo systemctl status fortisiem-aws-log-collector
```

Follow logs:

```bash
sudo journalctl -u fortisiem-aws-log-collector -f
```

Show the latest 100 log entries:

```bash
sudo journalctl -u fortisiem-aws-log-collector -n 100 --no-pager
```

Restart after modifying `config.json` or `collector.py`:

```bash
sudo systemctl restart fortisiem-aws-log-collector
```

Stop the service:

```bash
sudo systemctl stop fortisiem-aws-log-collector
```

Disable the service:

```bash
sudo systemctl disable --now fortisiem-aws-log-collector
```

---

# Link Processed Logs into FortiSIEM

FortiSIEM reads incoming syslog files under:

```text
/opt/phoenix/cache/syslog/
```

Create a symbolic link whose name matches the `reptDevIpAddr` configured in `config.json`.

For example, with:

```json
"reptDevIpAddr": "98.87.170.71"
```

create:

```bash
sudo ln -sfn \
  /usr/local/fortisiem-aws-log-collector/logs/processed \
  /opt/phoenix/cache/syslog/98.87.170.71
```

The resulting mapping is:

`/opt/phoenix/cache/syslog/98.87.170.71 -> /usr/local/fortisiem-aws-log-collector/logs/processed`

Verify:

```bash
ls -la /opt/phoenix/cache/syslog/
```

The symlink itself may be owned by `root:root`; this is normal. What matters is that FortiSIEM can read the target directory and the processed log files.

## Multiple Reporter IPs

Do not point multiple FortiSIEM reporter IP directories to the same processed directory, because FortiSIEM would see the same files under multiple reporter identities.

Do **not** configure this:

```text
98.87.170.71 -> /usr/local/fortisiem-aws-log-collector/logs/processed
98.87.170.72 -> /usr/local/fortisiem-aws-log-collector/logs/processed
98.87.170.73 -> /usr/local/fortisiem-aws-log-collector/logs/processed
```

All collectors sharing the same `output_dir` should therefore normally use the same `reptDevIpAddr`.

If separate reporter IPs are required, use separate processed output directories and create one FortiSIEM symlink for each reporter IP.

---

# SQS Processing Behavior

## Long Polling

The default setting is:

```json
"wait_time_seconds": 20
```

This does **not** mean that the collector checks SQS only once every 20 seconds.

A ReceiveMessage request waits for up to 20 seconds. If a message arrives during that period, SQS returns it immediately. After processing, the collector starts the next long-poll request.

Each configured collector has its own worker thread and polls its own SQS queue independently.

## Visibility Timeout

Default settings:

```json
"visibility_timeout": 300,
"visibility_heartbeat": 120
```

While processing a message, the collector periodically extends the SQS visibility timeout. This helps prevent another consumer from receiving the same message while a large S3 object is still being downloaded or transformed.

The SQS message is deleted only after all processable S3 records in that message complete successfully.

If processing fails, the message is not deleted and becomes available again according to the queue's visibility timeout and redrive policy.

---

# Duplicate Protection

S3 event notifications use at-least-once delivery semantics, so duplicate delivery is possible.

The collector stores local processing state in:

```text
/usr/local/fortisiem-aws-log-collector/logs/state.db
```

The event identity is derived from S3 object information including:

```text
Bucket
Object Key
Version ID
ETag
Sequencer
```

Already processed events are ignored.

---

# Supported SQS Message Formats

## `S3 -> SQS`

Example body:

```json
{
  "Records": [
    {
      "eventSource": "aws:s3",
      "eventName": "ObjectCreated:Put",
      "awsRegion": "us-west-2",
      "s3": {
        "bucket": {
          "name": "example-bucket"
        },
        "object": {
          "key": "AWSLogs/example.log.gz"
        }
      }
    }
  ]
}
```

SNS Raw Message Delivery produces the same effective S3 event payload and is processed by the same path.

## `S3 -> SNS -> SQS`

Example SQS body:

```json
{
  "Type": "Notification",
  "TopicArn": "arn:aws:sns:us-west-2:123456789012:aws-logs",
  "Message": "{\"Records\":[{\"eventSource\":\"aws:s3\"}]}"
}
```

The collector automatically decodes the JSON in the SNS `Message` field before processing the S3 records.

---

# Multiple Log Sources

Multiple queues can be configured in one collector process.

Example:

```json
{
  "collectors": [
    {
      "log": "vpcflow",
      "sqs": "https://sqs.us-west-2.amazonaws.com/111111111111/vpcflow",
      "region": "us-west-2",
      "log_keyword": "VPCFlow log",
      "phCustId": "1",
      "reptDevIpAddr": "98.87.170.71",
      "reptDevName": "amazon.com"
    },
    {
      "log": "guardduty",
      "sqs": "https://sqs.us-east-1.amazonaws.com/222222222222/guardduty",
      "region": "us-east-1",
      "aws_access_key_id": "AKIAxxxxxxxxxxxxxxxx",
      "aws_secret_access_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "log_keyword": "GuardDuty log",
      "phCustId": "1",
      "reptDevIpAddr": "98.87.170.71",
      "reptDevName": "amazon.com"
    }
  ]
}
```

Typical AWS log sources include VPC Flow Logs, GuardDuty, CloudTrail, AWS WAF, ALB logs, and AWS Security Hub findings when their S3 notifications are delivered through a supported SQS path.

---

# Running Tests

```bash
python3 -m unittest discover -s tests -v
```

No additional dependencies are required beyond the standard library.

---

# Updating the Collector

Stop the service:

```bash
sudo systemctl stop fortisiem-aws-log-collector
```

Pull the latest code as `admin`:

```bash
cd /usr/local/fortisiem-aws-log-collector
sudo -u admin git pull
```

Refresh virtual-environment dependencies if `requirements.txt` changed:

```bash
sudo -u admin /usr/local/fortisiem-aws-log-collector/venv/bin/pip \
  install -r /usr/local/fortisiem-aws-log-collector/requirements.txt
```

Validate the configuration:

```bash
sudo -u admin /usr/local/fortisiem-aws-log-collector/venv/bin/python \
  /usr/local/fortisiem-aws-log-collector/collector.py --check-config
```

Start the service:

```bash
sudo systemctl start fortisiem-aws-log-collector
```

Check status:

```bash
sudo systemctl status fortisiem-aws-log-collector
```

---

# Troubleshooting

## Validate Configuration

```bash
sudo -u admin /usr/local/fortisiem-aws-log-collector/venv/bin/python \
  /usr/local/fortisiem-aws-log-collector/collector.py --check-config
```

## Check Service

```bash
sudo systemctl status fortisiem-aws-log-collector
```

## Follow Service Logs

```bash
sudo journalctl -u fortisiem-aws-log-collector -f
```

## Check Process User

```bash
ps -ef | grep collector.py
```

The collector should normally run as `admin`.

## Check Processed File Ownership

```bash
ls -l /usr/local/fortisiem-aws-log-collector/logs/processed
```

New files should normally be owned by `admin:admin`.

## AWS AccessDenied

Verify SQS permissions:

```text
sqs:ReceiveMessage
sqs:DeleteMessage
sqs:ChangeMessageVisibility
```

Verify S3 permissions:

```text
s3:GetObject
s3:GetObjectVersion
```

For KMS-encrypted objects, also verify:

```text
kms:Decrypt
```

## No Messages Received

Check:

1. S3 Event Notification configuration
2. SQS queue contents
3. SNS subscription if using `S3 -> SNS -> SQS`
4. SQS queue policy
5. AWS permissions
6. Collector logs

```bash
sudo journalctl -u fortisiem-aws-log-collector -f
```

## Raw Logs for Debugging

If you need to compare processed output with the original AWS object, temporarily set:

```json
"write_raw_logs": true
```

Restart the service:

```bash
sudo systemctl restart fortisiem-aws-log-collector
```

Raw objects will then be stored under `raw_dir`. After troubleshooting, change `write_raw_logs` back to `false` to avoid retaining unnecessary copies.

## Process Mode (`process_mode`)

Controls how each S3 object is handled. It can be set globally and overridden per collector.

| Value | Behavior | Output name |
|---|---|---|
| `full` (default) | Add FortiSIEM prefix (or split/extract for CloudTrail / Security Hub), write gzip | `<log>_<name>.gz` |
| `raw` | Download as-is, content untouched | `<log>_<name>` (no `.gz` added) |
| `raw_gz` | Download as-is, but guarantee gzip: gzip input is stored unchanged, plain text is compressed whole | `<log>_<name>.gz` |

```json
{
  "process_mode": "full",
  "collectors": [
    { "log": "windows", "sqs": "https://sqs.us-west-2.amazonaws.com/700000000000/windows", "process_mode": "raw_gz" }
  ]
}
```

Notes:

- In `raw` / `raw_gz` mode, `log_keyword`, `phCustId`, `reptDevIpAddr` and `reptDevName` are **not required** and are ignored.
- `write_raw_logs` is ignored (the downloaded file is already the unmodified object).
- `raw` mode keeps the original file name, so FortiSIEM must be able to read files without a `.gz` extension.

## Supported Object Format

File name and extension do **not** matter. Gzip is detected from the file content, and the output is always `.gz`.

| Input content | Accepted | Notes |
|---|---|---|
| gzip | Yes | e.g. `.log.gz`, `.json.gz`, or no extension |
| Plain text (one event per line) | Yes | e.g. Firehose objects such as `<delivery-stream-name>-1-YYYY-MM-DD-HH-MM-SS-<uuid>` |

Content requirements by `log_keyword`:

- **Standard log types** — any text, one event per line. CRLF is normalised and blank lines are skipped.
- **CloudTrail** (`AWS_S3_LOG_CLOUDTRAIL*`) — must be JSON with a `Records` array.
- **AWS Security Hub** (`AWS_SECURITY_HUB_EVENT_DATA`) — must be EventBridge JSON.

To limit which objects are processed, use `s3_key_include_regex`.

---

# License

This project is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for details.

---

# Disclaimer

This project is provided as an open-source utility for AWS log collection and FortiSIEM log-preparation workflows.

It is not an official Fortinet product and is not supported by Fortinet Technical Support.
