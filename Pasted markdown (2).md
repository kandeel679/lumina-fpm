### **Project Guide: Proactive Firewall Policy Management & Threat Visualization Platform**

### 1. Project Title

Proactive Firewall Policy Management & Threat Visualization Platform

### 2. Project Vision & Overview

This project is a web-based dashboard designed to automate the acquisition, analysis, and visualization of firewall policies from multiple vendors. The system will provide a "single pane of glass" for network administrators to audit their firewall rules, detect policy anomalies (like shadowed or redundant rules), and visualize complex traffic flows.

Crucially, this platform will move beyond static policy analysis by integrating **Cyber Threat Intelligence (CTI)** feeds. It will correlate firewall rules with known malicious IPs and domains, allowing administrators to identify and prioritize risks based on active, real-world threats.

### 3. The Problem Statement (The "Why")

Firewall rulebases in any large organization grow organically over time, leading to thousands of rules. This creates significant, often hidden, risks:

- **Lack of Visibility:** It's impossible to get a clear picture of all allowed traffic.
- **Policy Anomalies:** "Shadowed," "redundant," and "overly permissive" rules create security holes and inefficiencies.
- **Manual Audits:** Auditing is a manual, error-prone, and time-consuming process that is often outdated as soon as it's finished.
- **Static vs. Dynamic Risk:** A rule that allows traffic to a "benign" IP address may become a critical vulnerability *tomorrow* when that IP is identified as a C2 server. Traditional tools do not bridge this gap.
- **Complex Inter-connectivity:** In a large network, it is extremely difficult to understand the "blast radius" of a compromised server or to map data flows for compliance.

### 4. Goals & Objectives (The "What")

- **Centralize:** To aggregate firewall policies from multiple, heterogeneous devices into a single, searchable database.
- **Analyze:** To automatically scan all policies and identify a range of configuration anomalies (e.g., `any-any-all`, shadowed rules).
- **Enrich:** To integrate external CTI feeds to flag policies that permit traffic to/from known-malicious indicators.
- **Visualize:** To present this complex data in two ways:
    1. A clean, filterable **table** for auditing.
    2. An interactive **graph** for intuitive topology and traffic-flow mapping.
- **Prioritize:** To provide administrators with a prioritized list of risks, based on both policy weakness and CTI data, so they know what to fix first.

### 5. Scope

| **In Scope (Features we WILL build)** | **Out of Scope (Features we will NOT build)** |
| --- | --- |
| **Read-only** analysis of firewall configurations. | **Making changes** or pushing new policies to firewalls. |
| Support for **Palo Alto Networks (Panorama & local)**. | Support for every vendor on the market (v1 will be focused). |
| Support for **Fortinet (FortiManager & local)**. | Deep packet inspection or live traffic flow (NetFlow) analysis. |
| A web-based dashboard for visualization. | A thick-client or desktop application. |
| Policy anomaly detection (shadowed, redundant, etc.). | User-identity-based policy analysis (e.g., Active Directory integration). |
| CTI feed integration (e.g., AlienVault OTX, AbuseIPDB). | Endpoint security (e.g., anti-virus, EDR). |
| Interactive graph/topology visualization of policies. | Vulnerability scanning or management. |

---

### 6. High-Level Architecture (The "How" - for the SDD)

The system will be designed using a four-layer architecture, as described in the FPM research.

1. **Acquisition Layer:** Responsible for connecting to firewalls (or their managers) and fetching the raw configuration data.
2. **Parsing Layer:** Responsible for taking the raw, vendor-specific data (e.g., XML, config text) and converting it into a single, standardized JSON format that the rest of the application can understand.
3. **Analysis Layer:** The "brain" of the project. This layer runs multiple modules against the standardized JSON data to find risks, anomalies, and CTI matches.
4. **Presentation Layer:** The user-facing web dashboard that displays the results from the Analysis Layer.

---

### 7. Detailed Feature Breakdown (For the SRS)

This section details the functional requirements for each layer.

### 7.1. Layer 1: Acquisition Layer ("The Collector")

- **FR-1.1: Multi-Device Polling Engine:** The system must be able to periodically poll multiple devices.
- **FR-1.2: Central Manager Integration:** The system must prioritize connecting to central managers (Palo Alto Panorama, FortiManager) to acquire policies for hundreds of firewalls with a single API call.
- **FR-1.3: Direct-to-Device Fallback:** For firewalls *not* managed by a central tool, the system must be able to connect to them directly via their REST API (e.g., a single Palo Alto or FortiGate).
- **FR-1.4: Vendor Connectors:** The system must have a modular "connector" architecture.
    - **FR-1.4.1: Palo Alto Connector:** Must use the REST/XML API. It must be able to perform `type=keygen` (for a key) and `type=config` (with an `xpath`) to get policies.
    - **FR-1.4.2: Fortinet Connector:** Must use the FortiGate/FortiManager REST API to fetch policy configurations.
- **FR-1.5: Secure Credential Management:** The system must provide a secure way to store the API keys and admin credentials for all managed devices (e.g., using an encrypted database or a tool like HashiCorp Vault).

### 7.2. Layer 2: Parsing Layer ("The Translator")

- **FR-2.1: Normalized Data Model:** The team must define a "Standardized Policy JSON" format. This is the single most important design task. This JSON object must be able to represent any rule from any vendor.
    - *Example:* `{"name": "Rule 1", "source": ["10.1.1.0/24", "ip_obj_webserver"], "destination": ["any"], "service": ["http", "https"], "action": "allow", "vendor": "PaloAlto", "raw_id": 5}`
- **FR-2.2: Vendor-Specific Parsers:**
    - **FR-2.2.1: Palo Alto Parser:** Must be able to parse the XML response from the Palo Alto API and convert every `<entry>` into the Standardized Policy JSON format.
    - **FR-2.2.2: Fortinet Parser:** Must be able to parse the JSON/config output from the Fortinet API and convert it into the Standardized Policy JSON format.

### 7.3. Layer 3: Analysis Layer ("The Brain")

- **FR-3.1: Policy Anomaly Module:** This module scans all standardized policies for common risks.
    - **FR-3.1.1: Overly Permissive Rules:** Flag rules where `Source`, `Destination`, or `Service` is `any` (or equivalent).
    - **FR-3.1.2: Shadowed Rule Detection:** Implement the algorithm to compare Rule A with Rule B and flag if Rule A is fully "shadowed" (will never be hit).
    - **FR-3.1.3: Redundant Rule Detection:** Flag rules that are identical to a preceding rule.
- **FR-3.2: CTI Enrichment Module:** This module provides dynamic threat context.
    - **FR-3.2.1: Indicator Extraction:** The module must scan all `Source` and `Destination` objects in the policies and extract all public IP addresses and FQDNs.
    - **FR-3.2.2: CTI API Integration:** The module must be able to take the extracted list of indicators and query third-party CTI APIs (e.g., AlienVault OTX, AbuseIPDB, VirusTotal).
    - **FR-3.2.3: Threat Correlation:** The module must correlate the CTI responses (e.g., "1.2.3.4 is malicious") back to the specific policy rules that reference them.
    - **FR-3.2.4: Threat Scoring:** The module must assign a risk score to rules based on CTI data (e.g., 🔴`Malicious`, 🟡`Suspicious`, 🟢`Clear`).

### 7.4. Layer 4: Presentation Layer ("The Dashboard")

This is the web application the user will interact with.

- **FR-4.1: Main Dashboard:** A summary page showing "at-a-glance" widgets:
    - Total Firewalls Managed
    - Total Policies Analyzed
    - Total Anomalies Found (e.g., 15 Shadowed Rules)
    - High-Risk Rules (widget for `any/any` rules)
    - Active Threats Found (widget for rules with CTI matches)
- **FR-4.2: Policy Explorer:** A filterable, searchable table of *all* aggregated rules. The user must be able to filter by `firewall`, `source`, `destination`, `service`, `action`, etc.
- **FR-4.3: Anomaly Report:** A dedicated page listing all rules flagged by the **Policy Anomaly Module (FR-3.1)**, grouped by anomaly type.
- **FR-4.4: CTI Threat Center:** A dedicated page listing all rules flagged by the **CTI Enrichment Module (FR-3.2)**, prioritized by severity. It should show the rule, the malicious indicator, and the CTI report (e.g., "Threat Type: C2 Server").
- **FR-4.5: Graph Visualization View:** This is the project's most powerful feature.
    - **FR-4.5.1:** The system must render the policies as an interactive, directed graph.
    - **FR-4.5.2:** **Nodes** in the graph will represent network objects, zones, and subnets (e.g., `trust-zone`, `web-server-subnet`, `1.2.3.4`).
    - **FR-4.5.3:** **Edges** (lines) between nodes will represent the policy rules that allow traffic between them.
    - **FR-4.5.4:** The graph must be interactive. Clicking a node (e.g., `web-server-subnet`) should highlight all traffic flows (edges) going to and from it.
    - **FR-4.5.5:** The graph must be linked to the CTI module. Any node representing a malicious IP should be colored **red**.

### 8. Recommended Technical Stack (For the SDD)

- **Backend:** Python (with **Flask** or **Django**) or **C# (.NET Core)**. Python is highly recommended due to its strong data science, automation, and `requests` libraries.
- **Database:** **PostgreSQL** (for storing structured policy data and credentials) and/or **MongoDB** (for flexibly storing the JSON policy documents).
- **Task/Polling Engine:** **Celery & Redis** (if using Python) or a .NET Worker Service to run the scheduled acquisition (FR-1.1) in the background.
- **Frontend (Web Dashboard):** **React.js** or **Vue.js**. These are modern, component-based frameworks ideal for building an interactive dashboard.
- **Graph Visualization Library:** **Cytoscape.js** or **Vis.js**. These are powerful JavaScript libraries designed specifically for network graph visualization.
- **API Clients:** **`requests`** (Python) or **`HttpClient`** (C#) for making API calls.
- **Parsers:** **`ElementTree`** (Python, for XML) or **`System.Text.Json`** / **`Newtonsoft.Json`** (C#, for JSON).

### 9. How Your Team Should Use This Guide

- **For the SRS (Software Requirements Specification):**
    - Focus on **Sections 3, 4, 5, and 7**.
    - These sections describe *what* the system must do, *who* it is for, and *what* features it must have.
    - Your SRS document should expand on every feature in **Section 7**, adding details about inputs, outputs, and acceptance criteria.
- **For the SDD (Software Design Document):**
    - Focus on **Sections 6 and 8**.
    - These sections describe *how* the system will be built.
    - Your SDD document should create detailed diagrams (UML, sequence, database schemas) based on the **4-Layer Architecture**. It should formally define the **"Standardized Policy JSON" (FR-2.1)** and detail the API endpoints for the frontend and backend.