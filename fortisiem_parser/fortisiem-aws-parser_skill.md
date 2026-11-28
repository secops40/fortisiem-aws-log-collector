---
name: create-fortisiem-aws-parser
description: Create, validate, and review custom FortiSIEM XML Event Parsers for AWS log sources (such as AWS WAF, AWS Network Firewall, Route 53 Resolver DNS, CloudTrail, and VPC Flow Logs) ingested via S3 or syslog. Use when the user asks to write, generate, debug, or review a FortiSIEM XML parser from AWS sample logs.
---

# Create FortiSIEM AWS Parser

Generate production-ready FortiSIEM custom XML event parsers for AWS logs ingested through S3 pipelines, strictly adhering to FortiSIEM 7.6.1 Parser Specification, built-in patterns, and built-in functions.

## When to Use

- The user provides an AWS log sample (e.g., `AWS_S3_WAF`, `AWS_S3_FIREWALL`, `AWS_S3_LOG_DNS`, `AWS_S3_LOG_CLOUDTRAIL`) and asks to create a FortiSIEM parser.
- The user wants to debug or validate a FortiSIEM XML parser failing validation or attribute mapping.
- The user asks how many `eventType` values a FortiSIEM parser will generate.

## Core Parser Architecture & Rules

### 1. XML Structure & Tag Integrity (Web UI Ready)

- **Omit Outer Wrapper Tags**: Omit `<eventParser>` and `<deviceType>` wrapper tags because FortiSIEM Web UI generates them automatically. Provide only:
  - `<eventFormatRecognizer>`
  - `<patternDefinitions>` (only if custom patterns are actually referenced)
  - `<parsingInstructions>`
- **Strict XML Tag Matching (ZERO TOLERANCE)**: Every `<setEventAttribute ...>` tag MUST close with `</setEventAttribute>`. **NEVER** write `</setAttribute>` — FortiSIEM immediately rejects it with `Opening and ending tag mismatch`.

### 2. Header + JSON Body Extraction

AWS S3 logs arriving in FortiSIEM typically share the prefix structure `PREFIX:phCustId=...,reptDevIpAddr=...,reptDevName=...,msg={...}`. Extract the prefix and raw JSON body first:

```xml
<collectFieldsByRegex src="$_rawmsg">
    <regex><![CDATA[^<PREFIX>:phCustId=<_custId:gPatInt>,reptDevIpAddr=<reptDevIpAddr:gPatIpAddr>,reptDevName=<reptDevName:gPatStrComma>,msg=<_body:gPatMesgBody>]]></regex>
</collectFieldsByRegex>
```

### 3. Strict Regex & Pattern Rules (Critical)

- **No Inline Regex in Capture Groups**: Inside `<regex>`, `<attrName:patternName>` MUST reference either a built-in pattern (`gPatInt`, `gPatIpAddr`, `gPatStr`, `gPatStrComma`, `gPatStrDQ`, `gPatMesgBody`, `gPatYear`, `gPatMon`, `gPatMonNum`, `gPatDay`, `gPatTime`, `gPatTimeZone`) or a pattern explicitly defined in `<patternDefinitions>`. Writing inline character classes like `<awsRegion:[a-z]+-[a-z]+-\d+>` causes immediate validation failure (`parsing error: collectFieldsByRegex`).
- **No Unused Patterns**: Do not declare patterns in `<patternDefinitions>` unless they are referenced inside `<parsingInstructions>`.
- **Anonymous Captures**: Use `<:patternName>` when matching delimiters or suffixes that do not need to be stored in an attribute.

### 4. Mandatory Timestamp Normalization (`deviceTime`)

**Every generated AWS parser MUST explicitly extract and populate `deviceTime`.** Never omit `deviceTime` or fall back to collector receipt time (`phRecvTime`). Verify the timestamp format in the sample log and use the exact FortiSIEM 7.6.1 built-in conversion method:

- **13-digit Unix Epoch (milliseconds)** (e.g., AWS WAF `timestamp`):
  - **NEVER** pass single Epoch values (10-digit or 13-digit) to `toDateTime()` — `toDateTime()` does NOT accept single Epoch arguments and throws `PH_PARSER_WRONG_PARAMETER` (`getTimeSecIntValue`).
  - Extract the raw millisecond field into `_eventTime`, parse it as an integer via `<regex><![CDATA[^<_timestamp:gPatInt>$]]></regex>`, convert milliseconds to seconds with `divide($_timestamp, 1000)` into `eventTime`, and copy to `deviceTime`:
    ```xml
    <when test="exist _eventTime">
        <switch>
            <case>
                <collectFieldsByRegex src="$_eventTime">
                    <regex><![CDATA[^<_timestamp:gPatInt>$]]></regex>
                </collectFieldsByRegex>
                <setEventAttribute attr="eventTime">divide($_timestamp, 1000)</setEventAttribute>
                <setEventAttribute attr="deviceTime">$eventTime</setEventAttribute>
            </case>
            <default/>
        </switch>
    </when>
    ```
- **10-digit Unix Epoch (seconds)** (e.g., VPC Flow Logs `start` / `end`):
  - Parse via `<regex><![CDATA[^<_timestamp:gPatInt>$]]></regex>` and assign directly to `eventTime` and `deviceTime` (`<setEventAttribute attr="deviceTime">$_timestamp</setEventAttribute>`). Do NOT call `toDateTime($_timestamp)`.
- **ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ` or with offset)** (e.g., CloudTrail `eventTime`, Route 53 DNS `query_timestamp`, Network Firewall `event.timestamp`):
  - Always prefer ISO 8601 strings over Epoch fields when both exist in the log. Extract components with `gPatYear`, `gPatMon` (or `gPatMonNum`), `gPatDay`, `gPatTime` (and optional `gPatTimeZone`) and call `toDateTime($_mon, $_day, $_year, $_time)` (or 5-argument `toDateTime($_mon, $_day, $_year, $_time, $_zone)`).

### 5. Temporary Variables (`_`) & Standard Attributes (Critical)

- **Underscore Prefix for Temporary Variables (`_var`)**: FortiSIEM silently drops any unprefixed attribute name not registered in its built-in Event Attribute dictionary, causing `exist` checks to always evaluate to `false`. **ALWAYS** store intermediate or non-standard fields used in `<when>`, `<choose>`, or `combineMsgId()` into underscore-prefixed temporary variables (`_rcode`, `_action`, `_srcIpAddr`, `_destIpAddr`).
- **String Concatenation**: Always use `combineMsgId("Prefix-", $_var)`. Never use `combine()`.
- **Case Conversion**: Use `toUpper($_var)` or `toLower($_var)`.
- **Single-Line Function Calls**: Keep function calls (`toDateTime(...)`, `divide(...)`, `combineMsgId(...)`) on a single line inside `<setEventAttribute>` without line breaks inside parentheses.
- **Standard Attributes**: Map fields to standard FortiSIEM attributes verified in official AWS parsers (`accountId`, `awsRegion`, `vpcId`, `ec2InstanceId`, `policyName`, `serviceName`, `resourceId`, `resourceName`, `fwRule`, `fwAction`, `actionName`, `sessionId`, `srcIpAddr`, `srcIpPort`, `srcName`, `destIpAddr`, `destIpPort`, `destName`, `ipProto`, `appName`, `uriStem`, `uriQuery`, `httpMethod`, `httpVersion`, `appClientVersion`, `tlsVersion`, `tlsCipher`, `correlationId`, `status`, `details`, `errReason`, `eventAction`, `eventSeverity`).
- **IP Validation**: Store raw JSON IP strings into temporary variables (`_srcIpAddr`, `_destIpAddr`) first, then validate with `gPatIpAddr` before assigning to `srcIpAddr` / `destIpAddr` (fallback to `srcName` / `destName`).
- **Protocol Normalization**: Convert protocol strings (`TCP`, `UDP`, `ICMP`) to IANA numbers (`6`, `17`, `1`).

### 6. Fallback `eventType` & Enumeration

- Always initialize a fallback `eventType` (e.g., `AWS-WAF-Generic`, `AWS-NetworkFirewall-Generic`, `AWS-Route53-DNS-Generic`) right after header extraction so malformed or truncated JSON logs remain trackable.
- Whenever generating a parser, explicitly list all possible `eventType` values it can produce so the user knows which Event Types to pre-register in FortiSIEM.

## Workflow Steps

1. **Inspect Sample Log**: Identify the log prefix, timestamp precision/format, ARN fields, nested JSON paths, and array structures (e.g., HTTP `headers` arrays where keys must be matched by regex rather than fixed array index `[0]`).
2. **Draft XML Parser**: Build `<eventFormatRecognizer>`, `<patternDefinitions>`, and `<parsingInstructions>` following the rules above.
3. **Self-Verify Before Output**:
   - Confirm zero occurrences of `</setAttribute>` — every `<setEventAttribute>` must close with `</setEventAttribute>`.
   - Confirm every intermediate or non-standard variable used in `exist`, `test`, or `combineMsgId` starts with `_`.
   - Confirm `deviceTime` is explicitly populated and zero single-argument `toDateTime()` calls exist.
   - Confirm zero inline regexes exist inside `<attr:pattern>` tags, and every pattern in `<patternDefinitions>` is used.
4. **Deliver Output**: Provide the clean XML block, a field mapping summary based on the user's sample log, and the exact list of `eventType` values generated.

## Gotchas

- **Array Index Traps**: In AWS WAF logs, `httpRequest.headers` and `ruleGroupList` have dynamic element ordering. Never hardcode `headers[0]` or `ruleGroupList[0]` for fields that can appear at any index; extract them via regex against `$_body`.
- **No Unnecessary Diffs**: If reviewing an existing parser that already passes all syntax and logic rules, state clearly that no changes are required rather than re-outputting identical XML. If fixes are needed, specify exact line numbers and reasons.