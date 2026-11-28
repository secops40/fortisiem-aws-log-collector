---
name: create-fortisiem-dashboard
description: Generate valid, importable FortiSIEM Dashboard XML files while strictly preventing silent import failures caused by mismatched customer IDs, incompatible schema versions, or unsupported query syntax.
---

# FortiSIEM Dashboard XML Generator

## Overview
This skill guides the creation of FortiSIEM Dashboard XML configurations (`<DashboardConfigs>`). FortiSIEM's XML import validator is notoriously strict and frequently rejects files silently (`Fail`) due to mismatched `custId`, wrong schema formatting (legacy semicolon vs. modern JSON `<dataParam>`), missing structural tags, or unsupported SQL/event attributes.

---

## Step 1: Mandatory Pre-Flight Inquiry (NEVER SKIP)
Before generating **any** FortiSIEM Dashboard XML, you **MUST** first ask the user for the target environment's baseline parameters:
1. **Reference Template (Strongly Recommended)**: Ask the user to paste any exported Dashboard XML from the target FortiSIEM environment. This automatically reveals the exact `custId`, `Role ID`, and schema version (legacy vs. modern JSON).
2. **Manual Parameters (If no template is provided)**: Explicitly ask for:
   - Target **`custId`** (e.g., `1`, `2000`, etc.) — **NEVER hardcode or guess**.
   - Target **`Role ID`** inside `<userRoles>` (default fallback `1076451` only if user confirms).
3. **Log Source & Attributes**:
   - If a **Custom Parser XML** is provided, extract exact `eventType` values and mapped attributes strictly from `<parsingInstructions>`.
   - If **no Parser XML** is provided:
     - For standard/built-in devices (e.g., FortiGate, Windows, Linux, AWS CloudTrail, Cisco), use standard FortiSIEM `eventType` and common attributes (`srcIpAddr`, `destIpAddr`, `destIpPort`, `user`, `fwAction`, `totBytes`, `eventSeverity`).
     - For custom logs, ask the user for the exact `eventType` prefix/values and available attributes before generating XML.

---

## Step 2: Strict Schema & Structural Rules (Anti-Fail Checklist)
Ensure every generated XML adheres to these non-negotiable rules:

### 1. Schema Alignment
- **Modern JSON Format** (standard for newer FortiSIEM versions):
  - `<dataParam>` uses valid JSON strings (e.g., `{"display":"Donut","timeWindow":86400000,"numResults":10,"autoRefresh":5,"innerTimeWindow":3600000,"trendInterval":"auto","chartSet":"0","timeWindowInMins":1440,"timeRange":"Last 24 hours","custIds":[],"resultLimit":10}`).
  - `naturalId` and `dataProviderNaturalId` MUST use the `PH_Report_...` prefix (avoid `Cust_Report_...` if the target environment expects `PH_Report_...`).
- **Legacy Semicolon Format** (if indicated by user's reference XML):
  - Match the exact semicolon-delimited `<dataParam>` structure (`display=...;timeWindow=...;`) and `<displaySettings>` syntax from the reference file.

### 2. Mandatory XML Tags (Never Omit)
Every `<Report>` block **MUST** include:
- `<CustomerScope groupByEachCustomer="true"><Include>{custId}</Include><Exclude/></CustomerScope>`
- `<userRoles><roles custId="{custId}">{roleId}</roles></userRoles>`
- `<OrderByClause><AttrList>COUNT(*) DESC</AttrList></OrderByClause>` (Include even on single-value `Gauge` widgets).
- `<ReportInterval><Low>1795751104</Low><High>1795754703</High></ReportInterval>`
- `<SyncOrgs/>`, `<TrendInterval>auto</TrendInterval>`, and `<TimeZone/>`.

### 3. Query & Attribute Safety (Prevent Validator Rejection)
- **NO `COUNT(DISTINCT ...)`**: Never use `COUNT(DISTINCT attr)` in `<SelectClause>`. Use standard `COUNT(*) "Count"` or `SUM(...)`.
- **NO Special Characters in Aliases**: Column aliases inside double quotes in `<AttrList>` must only contain alphanumeric characters and spaces (e.g., `"Total Bytes"`). **NEVER** include `/` (slashes), `&`, or parentheses inside aliases (e.g., avoid `"Error/Block Count"`).
- **Standard Dictionary Attributes Only**: Only use verified, built-in FortiSIEM attributes in `<SingleEvtConstr>` and `<GroupByAttr>` (e.g., `eventType`, `srcIpAddr`, `destIpAddr`, `destName`, `awsRegion`, `vpcId`, `ec2InstanceId`, `fwAction`, `fwRule`, `appName`, `dnsQueryType`, `ipProto`, `details`, `totBytes`).
  - **AVOID** unregistered custom attributes like `domainEntropy` in `<SingleEvtConstr>`.
  - **AVOID** Threat Intelligence groups (`Group@PH_SYS_MALWARE_DOMAIN`) or GeoIP filters unless the user confirms they are enabled in their environment.
- **Strict XML Entity Escaping**: Always escape `&` as `&amp;`, `<` as `&lt;`, and `>` as `&gt;` inside `<name>`, `<Description>`, and `<SingleEvtConstr>`.
- **Sankey Chart Constraints**: When `<dataParam>` uses `"display":"Sankey"`, `<GroupByAttr>` and `<SelectClause>` must contain **exactly 2 dimension fields + 1 metric** (`field1,field2,COUNT(*) "Count"`).

---

## Step 3: Widget Layout & Design Best Practices
- **24-Column Grid System**: Design dashboards on a 24-unit horizontal grid (`horizontalCell` sums to `24` per row, `posX` starting at `0`).
  - Top Row KPIs (`Gauge`): 4 widgets × `horizontalCell="6"`, `verticalCell="6"` at `posY="0"`.
  - Middle Row Breakdowns (`Donut`, `Bar`, `ClusterBubble`): 3 widgets × `horizontalCell="8"`, `verticalCell="5"`.
  - Flow & Trend Row (`Sankey`, `Line`): 2 widgets × `horizontalCell="12"`, `verticalCell="10"`.
  - Bottom Detail Table (`Table`): 1 full-width widget `horizontalCell="24"`, `verticalCell="7"` at `posX="0"`.
- **Avoid Functional Overlap**: Ensure each widget serves a distinct analytical purpose (e.g., separate time-series trends, specific error types like `NXDOMAIN` vs. `Firewall-BLOCK`, entity-level aggregation, and detailed forensic tables).
- **Post-Generation Guidance**: After outputting the XML, briefly explain what each section monitors and how to spot anomalies.