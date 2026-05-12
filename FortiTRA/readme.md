# FortiTRA 🛡️
**Fortinet TAC Report Analysis**: *Automated Insights for FortiManager and FortiAnalyzer*

---

## 🚀 Overview
**FortiTRA** (TAC Report Analyzer) is a Python-based utility designed to ingest raw diagnostic output ('exe tac report') from **FortiManager (FMG)** and **FortiAnalyzer (FAZ)**. It automates the extraction of critical system metrics and compares them against recommended hardware or virtual machine thresholds to ensure optimal performance.

## ✨ Key Features
*   **Sizing Validation**: Evaluates if the current hardware or VM resources (CPU/RAM/Disk) are properly dimensioned for the current log ingestion rate and managed device count.
*   **Performance Monitoring**: Parses `diag sys top` and other system logs to identify high I/O wait times or memory exhaustion.
*   **Health Auditing**: Scans for "red flag" issues such as filesystem errors, crashes, or synchronization failures.
*   **ADOM Context Awareness**: Differentiates between `root` and `rootp` (Global) Administrative Domains to identify specific configuration states and bitmask flags.
*   **Automated Troubleshooting**: Converts thousands of lines of raw TAC report data into a prioritized summary of **Critical**, **Warning**, and **Info** alerts.
