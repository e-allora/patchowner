# Refactor Idea
To transform **patchowner.com** from a proof-of-concept into a venture-backed enterprise cybersecurity business, starts with **product refinement**.

## 1. Product Refinement: From Local Proof-of-Concept to Scalable Enterprise SaaS

Currently, patchowner.com operates as a local replay tool that ingests CSV inventories, evaluates a Carnegie Mellon SSVC 2.0 decision tree against 90 days of CISA KEV data, and simulates 3-way notice routing. To make the product enterprise-ready and investable -->four deliberate upgrades:

* **Automated Asset & Vulnerability Syncing:** Transition away from manual CSV uploads by building live API connectors into enterprise CMDBs (e.g., ServiceNow) and vulnerability scanners (e.g., Tenable, Qualys).
* **Multi-Tenant MSP/SOC Architecture:** Build multi-tenant capability so managed security providers—such as **CyberTrust Massachusetts**—and enterprise security leads can manage vulnerability routing across multiple client entities or business units from a single dashboard.
* **Layered Policy Engine & Restrained Ingestion:** Expand beyond CISA KEV to include vendor advisories and NIST NVD, while implementing a hierarchical policy model (**Platform Baseline → Org Policy → Team Policy → Asset Owner**) that enforces strict alert budgets to eliminate alert fatigue.
* **Role-Based Experience & Action Paths:** Preserve the core doctrine that *"the product speaks rarely, clearly, and only to the right person"*. Ensure asset owners receive 1-sentence explanations with clear action buttons (**Open Fix, Acknowledge, Assign, Does Not Apply**), while executives receive calm status lines without raw CVE numbers.


## 1. Live Asset Discovery & Continuous Ingestion Engine

* **Enterprise CMDB & Scanner Connectors:** Replace manual CSV file imports with live API integrations into enterprise inventory systems (**ServiceNow CMDB**) and vulnerability scanners (**Tenable**, **Qualys**, and **SentinelOne Ranger Insights**). Automatically ingest asset metadata including environment tags (`production`, `staging`, `test`), internet exposure status (`open`, `controlled`, `small`), and assigned contacts (`owner_email`, `team`, `accountable`, `oncall`).
* **Multi-Source Advisory Funnel:** Expand beyond CISA KEV to continuously pull vendor advisories (e.g., Fortinet, Microsoft, Cisco) and NIST NVD. Process incoming feeds through a **3-stage advisory filter**:
  1. *Source Trust:* Validate advisory authenticity and provenance.
  2. *Relevance Matching:* Evaluate technology vendor and product names against tracked inventory using match confidence tiers (**exact**, **likely**, **possible**). Discard or quiet irrelevant CVE noise before it reaches any user.
  3. *Urgency & Routing:* Pass matched assets through the Carnegie Mellon SSVC 2.0 decision tree to calculate action states (**Act now**, **Update soon**, **Plan update**, **Defer**).


## 2. Multi-Tenant Architecture for MSPs, SOCs & CyberTrust Massachusetts

* **Unified Multi-Tenant Control:** Upgrade backend services (`patchowner/web.py`) to support multi-tenancy. This enables Managed Security Service Providers (MSSPs) and organizations like **CyberTrust Massachusetts** to monitor and manage vulnerability routing across dozens of distinct client entities (municipalities, healthcare networks, small businesses) from a single master dashboard.
* **Tenant Isolation & Custom Risk Appetite:**
  * Enforce strict row-level tenant data separation across asset inventories, action histories, and follow-through tracking (`out/state.json` / state database).
  * Allow each client entity or municipality to customize its own SSVC decision tree matrix, escalation SLA windows, and alert suppression rules.

## 3. Granular Policy Control & Alert Fatigue Engineering

* **6-Tier Policy Hierarchy:** Enforce a layered governance model where higher-level organizational policies cannot be bypassed by local user preferences:
  1. *Platform Baseline:* Ingestion guardrails, minimum source provenance, anti-spam thresholds.
  2. *Organization Policy:* CISO/Security Lead mandates (e.g., compulsory KEV alerts, urgency SLAs).
  3. *Business Unit Policy:* BU-specific routing rules (e.g., finance systems vs. dev repositories).
  4. *Team Policy:* Group-level routing (e.g., route Kubernetes advisories to Platform Engineering).
  5. *Asset Policy:* Asset-level rules (e.g., maintenance windows, exposure overrides, exceptions).
  6. *Individual Preferences:* Channel choices (Slack, Teams, Email, Mobile Push), quiet hours—*without* allowing users to mute required critical alerts.
* **Visual Policy Builder & 90-Day Simulation:**
  * Provide a visual `WHEN / THEN` policy creation interface for security administrators.
  * **90-Day Policy Simulation:** Before activating any new rule, allow security leads to test: *"Show me what this policy would have done over the last 90 days"* (displaying expected alert volume, recipient distribution, suppressed notices, and unassigned assets).
* **Auditable Suppression & Alert Budgets:** Define tenant-level alert volume budgets (e.g., max 1–3 urgent notices per week for asset owners) to eliminate alert fatigue. Require explicit, temporary, or auditable reasons for any suppressed notice (e.g., asset retired, compensating control active, temporary exception with expiration date) and display "Why was this not sent?" logs for auditors.


## 4. Role-Based Action Paths & Decision-Routing UX

* **3-Way Recipient Routing Engine:**
  * **Fixer (Asset Owner / Engineer):** Receives a 1-sentence plain-English explanation (*"Act now, because it's reachable from the internet, the attack can run by itself, and it would hurt a lot"*) accompanied by 5 direct action buttons: **Open Fix**, **Acknowledge**, **Assign**, **Does Not Apply**, and **Fixed**.
  * **Accountable Person (Manager / Infrastructure Lead):** Receives a calm 1-line status summary per asset *without raw CVE numbers or technical noise*.
  * **Escalation Contact:** Alerted only if SLA windows pass without action (e.g., Act Now: 2-hour acknowledgment, 8-hour plan, 24-hour escalation).
* **The 5-Page Security Control Center:** Structure the web UI around five focused screens:
  1. *Policies:* Edit SSVC decision trees, set SLA windows, and run policy simulations.
  2. *Technology Inventory:* Manage asset owners, criticality tags, version confidence, and exposure badges.
  3. *Alerts:* Triage actionable items ("Act now", "Update soon", "Plan update", "Watch") with match confidence metrics.
  4. *Routing:* Manage team mappings, identity provider directory sync, on-call schedules, and executive summary lists.
  5. *Health & Trust:* Monitor 11 continuous health checks (inventory coverage gaps, feed freshness, follow-through tracking, unassigned assets).

 To transition **patchowner.com** from a single-tenant script (`inventory.csv` + `out/state.json`) into a live, multi-tenant enterprise backend, we must replace flat files with a PostgreSQL database and a FastAPI REST layer.

This technical blueprint details the **database schema**, **API endpoints**, and **backend execution engine** required to scale the platform.



## 1. Multi-Tenant Relational Database Schema (PostgreSQL)

To enforce strict tenant isolation across Managed Security Service Providers (MSSPs) and corporate entities, every table includes a indexed `tenant_id` foreign key paired with PostgreSQL Row-Level Security (RLS).

```sql
-- 1. TENANTS & ORGANIZATIONS
CREATE TABLE tenants (
    tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. USERS & IDENTITY DIRECTORY SYNC
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL, -- 'admin', 'fixer', 'accountable', 'escalation'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- 3. ASSETS (Evolved from examples/inventory.csv)
CREATE TABLE assets (
    asset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    asset_name VARCHAR(255) NOT NULL,
    vendor VARCHAR(255) NOT NULL,
    product VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    environment VARCHAR(50) DEFAULT 'production', -- 'production', 'staging', 'test'
    internet_exposed BOOLEAN DEFAULT FALSE,
    criticality VARCHAR(50) DEFAULT 'medium',     -- 'low', 'medium', 'high', 'critical'
    
    -- SSVC Explicit Overrides
    ssvc_exposure_override VARCHAR(50),            -- 'small', 'controlled', 'open'
    ssvc_human_impact_override VARCHAR(50),        -- 'low', 'medium', 'high', 'very high'
    
    -- Ownership & Routing Contacts
    owner_id UUID REFERENCES users(user_id),
    accountable_id UUID REFERENCES users(user_id),
    oncall_id UUID REFERENCES users(user_id),
    escalate_to_id UUID REFERENCES users(user_id),
    
    -- Exception & Lifecycle Tracking
    status VARCHAR(50) DEFAULT 'active',           -- 'active', 'retired'
    exception_until DATE,
    exception_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. GLOBAL ADVISORIES & VULNERABILITIES (Shared Across Tenants)
CREATE TABLE advisories (
    advisory_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(100) UNIQUE NOT NULL,           -- e.g., 'CVE-2026-1234'
    source VARCHAR(100) NOT NULL,                  -- 'CISA_KEV', 'NVD', 'VENDOR'
    vendor VARCHAR(255) NOT NULL,
    product VARCHAR(255) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    exploitation_state VARCHAR(50) NOT NULL,       -- 'none', 'public_poc', 'active'
    automatable VARCHAR(50) DEFAULT 'yes',         -- 'no', 'yes'
    published_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. POLICIES & SSVC DECISION TREES (Evolved from ssvc.py)
CREATE TABLE policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    level VARCHAR(50) NOT NULL,                    -- 'platform', 'org', 'bu', 'team', 'asset'
    ssvc_tree_rules JSONB NOT NULL,                -- SEI SSVC 2.0 decision matrix
    sla_windows JSONB NOT NULL,                    -- Acknowledge, Plan, Escalate hours per urgency
    alert_budgets JSONB NOT NULL,                  -- Max urgent notices per week per user
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6. MATCHED NOTICES & ROUTING DISPATCHES (Evolved from decide.py)
CREATE TABLE notices (
    notice_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    advisory_id UUID NOT NULL REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    match_confidence VARCHAR(50) NOT NULL,         -- 'exact', 'likely', 'possible'
    
    -- Evaluated SSVC Decision Output
    urgency VARCHAR(50) NOT NULL,                  -- 'Act now', 'Update soon', 'Plan update', 'Defer'
    ssvc_vector VARCHAR(100) NOT NULL,             -- e.g., 'SSVCv2/A:Y/E:A/H:H/Se:O/'
    one_sentence_reason TEXT NOT NULL,
    
    -- Suppression Metadata
    is_suppressed BOOLEAN DEFAULT FALSE,
    suppression_reason TEXT,                       -- 'retired', 'active_exception', 'policy_defer'
    
    -- SLA Deadlines
    ack_deadline TIMESTAMP WITH TIME ZONE,
    plan_deadline TIMESTAMP WITH TIME ZONE,
    escalation_deadline TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 7. ACTION HISTORY & AUDIT TRAIL (Evolved from patchowner/state.py)
CREATE TABLE action_states (
    action_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    notice_id UUID NOT NULL REFERENCES notices(notice_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(user_id),
    action VARCHAR(50) NOT NULL,                   -- 'open_fix', 'acknowledge', 'assign', 'does_not_apply', 'fixed'
    assigned_to_user_id UUID REFERENCES users(user_id),
    comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);


## 2. RESTful API Endpoint Architecture (FastAPI)

The API layer converts static HTML reports into real-time microservices.

## A. Asset Inventory & Ingestion API
* **`POST /api/v1/inventory/sync`**  
  *Ingests asset lists from ServiceNow, Tenable, Qualys, or CSV payloads.*
  * **Payload:** List of assets containing vendor, product, version, environment, exposure, and ownership IDs.
  * **Behavior:** Validates structure, syncs records to `assets` table, updates inventory health metrics.
* **`GET /api/v1/assets`**  
  *Retrieves assets filtered by environment, exposure, or owner.*

## B. Advisory Matching & SSVC Decision Engine
* **`POST /api/v1/advisories/evaluate`**  
  *Triggers the evaluation funnel (`patchowner/engine.py`) when CISA KEV or vendor advisories update.*
  * **Behavior:** Matches advisories against active inventory, applies the CMDM SSVC 2.0 deployer tree, calculates vector strings and 1-sentence explanations, sets SLA deadlines, and records dispatches in `notices`.

## C. Role-Based Action Paths & Audit Logging
* **`GET /api/v1/notices`**  
  *Retrieves actionable notices formatted for specific recipient roles.*
  * **Query Params:** `role` (`fixer`, `accountable`), `urgency` (`Act now`, `Update soon`).
  * **Response:** Fixers receive actionable notices with vendor links; Accountable executives receive a calm 1-line status summary.
* **`POST /api/v1/notices/{notice_id}/act`**  
  *Executes one of the 5 direct action paths.*
  * **Payload:** `{ "action": "acknowledge" | "assign" | "does_not_apply" | "fixed", "comment": "string", "assigned_to": "uuid" }`
  * **Behavior:** Appends record to `action_states` database table, clears escalation windows if fixed or non-applicable, and logs full history for auditors.

## D. Policy Management & Health Monitoring
* **`POST /api/v1/policies/simulate`**  
  *Runs a 90-day backtest of a proposed SSVC policy tree against historical advisories.*
  * **Response:** Total notice count, urgency distribution, suppressed alerts, and affected recipients.
* **`GET /api/v1/health`**  
  *Evaluates the 11 continuous platform health checks (`patchowner/health.py`).*
  * **Response:** Unassigned assets, stale feeds, unhandled urgent notices, and budget overruns.



## 3. Service Layer Refactoring Strategy

| Current Script Module | Production SaaS Microservice Component |
| :--- | :--- |
| `patchowner/inventory.py` | `AssetService` + PostgreSQL `assets` table with CMDB API Webhooks. |
| `patchowner/kev.py` | Celery/Redis Scheduled Worker pulling CISA KEV & vendor JSON feeds every 6 hours. |
| `patchowner/ssvc.py` & `decide.py` | `EvaluationEngine` executing SSVC tree logic and assigning role-based notice payloads. |
| `patchowner/state.py` | `AuditService` writing action logs to `action_states` table. |
| `patchowner/health.py` | `HealthMonitor` running real-time database queries to verify 100% routing coverage. |



The **Security Control Center** UI is built around the core doctrine that *"the product speaks rarely, clearly, and only to the right person"*. Rather than presenting a noisy enterprise GRC dashboard, the UI is organized into five purpose-driven screens designed to move vulnerabilities from raw advisory signals to verified resolution.



### 1. Policies (Risk Appetite & Governance Engine)
* **Purpose & Persona:** Used by CISOs and Security Administrators to define organizational risk thresholds, notification rules, and SLA windows.
* **Core Components & Visual Layout:**
  * **Visual `WHEN / THEN` Builder:** A visual rule interface for configuring policy logic without complex Boolean code.
    * *WHEN:* `[CISA KEV: Yes] AND [Category: Edge/VPN/Identity] AND [Exposure: Internet-Facing] AND [Env: Production]`
    * *THEN:* `Set Urgency: Act Now` \\(\rightarrow\\) `Notify: Network Ops + Security On-Call` \\(\rightarrow\\) `SLAs: 2h Ack / 8h Plan / 24h Escalate`
  * **SSVC Decision Tree Canvas:** An interactive Carnegie Mellon SSVC 2.0 decision tree where admins click branches to customize deployer outcomes.
  * **SLA & Escalation Matrix:** Configures acknowledgment, mitigation, and escalation deadlines across urgency tiers (*Act now*, *Update soon*, *Plan update*, *Defer*).
  * **90-Day Policy Simulator:** An interactive sandbox allowing security leads to test proposed rules (*"Show me what this policy would have done over the last 90 days"*) to forecast alert volume, recipient distribution, and potential alert budget overruns before going live.



### 2. Technology Inventory (Asset Context & Ownership)
* **Purpose & Persona:** Used by Security Operations, IT Leads, and Asset Owners to maintain asset metadata and routing identities.
* **Core Components & Visual Layout:**
  * **Asset & CMDB Catalog:** A live catalog of tracked software and hardware (synced via ServiceNow or scanner integrations) displaying vendor, product, version, and environment tags (`production`, `staging`, `test`).
  * **Context Badges & Overrides:** Visual indicators for exposure (`internet_exposed`, `small`, `controlled`, `open`) and business criticality (`low`, `medium`, `high`, `critical`).
  * **Ownership Routing Block:** Direct assignment fields for every asset: **Fixer/Owner**, **Accountable Lead**, **On-Call Contact**, and **Escalation Target**.
  * **Exception & Lifecycle Management:** Active exception tracking showing review dates, temporary compensating controls, and retired asset filters.



### 3. Alerts (Actionable Triage & Fix Paths)
* **Purpose & Persona:** Used by Fixers (Engineers, System Admins) and Security Analysts to triage and resolve active vulnerability notices.
* **Core Components & Visual Layout:**
  * **Urgency-Categorized Cards:** Stacked notice views filtered by urgency (*Act now*, *Update soon*, *Plan update*, *Watch*).
  * **1-Sentence Plain-English Reason:** Every card opens with an unambiguous explanation (e.g., *"Act now, because it's reachable from the internet, the attack can run by itself, and it would hurt a lot"*).
  * **Match Confidence & Provenance Badges:** Highlights match confidence (*exact*, *likely*, *possible*) alongside primary source links (CISA KEV, official vendor advisories).
  * **5 Direct Action Buttons:** **Open Official Fix**, **Acknowledge**, **Assign**, **Does Not Apply**, and **Fixed**.
  * **"Why Was This Not Sent?" Panel:** An auditable list of suppressed alerts explaining why a notice stayed quiet (e.g., asset retired, active exception, policy deferral).



### 4. Routing (Directory Sync & Communication Channels)
* **Purpose & Persona:** Used by System Administrators and MSP Leads to manage team structures, directory integration, and executive status feeds.
* **Core Components & Visual Layout:**
  * **Directory & IdP Sync:** Integration settings for identity providers (Okta, Microsoft Entra ID) to import user roles, teams, and on-call schedules.
  * **Recipient Map & Role Rules:** Maps product categories or infrastructure tiers to communication channels (Slack, Teams, Email, PagerDuty, Jira).
  * **Executive Status Line Feed:** Shows exactly what executive recipients see—a calm 1-line status summary per asset with zero raw CVE numbers or technical clutter (e.g., *"Assigned to NetOps; patch scheduled for 10 PM tonight; no decision needed"*).
  * **MSP Multi-Tenant Management:** A master organization switcher allowing MSPs or entities like **CyberTrust Massachusetts** to oversee client routing from a single pane.


### 5. Health & Trust (System Integrity & Follow-Through Audit)
* **Purpose & Persona:** Used by CISOs, Auditors, and Compliance Leads to verify inventory coverage, feed freshness, and follow-through compliance.
* **Core Components & Visual Layout:**
  * **11 Continuous Health Monitors:** Diagnostic cards prioritizing system coverage gaps, worst-first:
    1. Unassigned asset ownership (missing owner, accountable lead, or on-call contact).
    2. Version confidence & unparsed inventory rows.
    3. Active vs. expiring exceptions (flags exceptions ending within 30 days).
    4. Advisory feed freshness (flags feeds older than 7 days).
    5. Follow-through cadence (verifies whether *Act now* and *Update soon* notices have been acted upon).
    6. Alert budget compliance (flags recipients exceeding weekly notice limits).
  * **Auditor Log:** A read-only audit log capturing every action taken, user comments, timestamps, and exact SSVC vector strings (`SSVCv2/A:Y/E:A/H:H/Se:O/`).


