# FortiGate Address Count Analyzer

A Python desktop tool for analyzing FortiGate configuration backups, logs, and TAC report files.

The tool counts firewall address objects and address groups by VDOM, identifies duplicate group members, detects address objects used in multiple groups, and allows filtering an address object to view its group memberships.

## Features

- Loads FortiGate configuration backups, logs, and TAC report files.
- Supports multi-VDOM FortiGate configurations.
- Counts explicit `firewall.address` objects by VDOM.
- Counts explicit `firewall.addrgrp` objects by VDOM.
- Shows the unique member count for every address group.
- Detects duplicate members within the same address group.
- Detects address objects used in multiple groups within the same VDOM.
- Filters by full or partial address-object name.
- Shows all address-group memberships for a filtered object.
- Supports compressed FortiGate support files.
- Displays results on screen only; no files are exported.

## Supported File Types

- `.conf`
- `.txt`
- `.log`
- `.out`
- `.gz`
- `.tar.gz`
- `.tgz`

## Requirements

- Python 3.10 or later
- Tkinter

Tkinter is normally included with Python on Windows.

On Ubuntu or Debian, install it with:

```bash
sudo apt update
sudo apt install python3-tk
```

## Download

Place the following script in the folder:

```text
fortigate_address_counter.py
```

## Run the Tool

```bash
python .\fortigate_address_counter.py
```

## Usage

1. Run the script.
2. Select **Load FortiGate File**.
3. Choose a FortiGate configuration, log, TAC report, or compressed support file.
4. Review the summary and address-group analysis.
5. Enter an address-object name, or part of a name, in the filter field.
6. Select **Filter** to display the object's VDOM and address-group memberships.
7. Select **Clear Filter** or **Show Full Report** to return to the complete results.

## Report Sections

### Summary by VDOM

Shows:

- Number of explicit firewall address objects
- Number of explicit firewall address groups

### Address Group Member Counts

Shows each address group with:

- Unique member count
- Number of duplicate member entries

The tool does not display the complete member list in the main report.

### Duplicate Members Within the Same Group

Shows any member repeated more than once in the same address group.

Example:

```text
VDOM: root
Group: Servers
  Server-01 — appears 2 times
```

### Objects Used in Multiple Groups

Shows address objects referenced by more than one address group in the same VDOM.

Example:

```text
VDOM: root
Object: Server-01
Group count: 3
Groups: Application-Servers, Production-Servers, Web-Servers
```

### Address Object Filter

The filter accepts a full or partial object name.

For every matching object, the tool shows:

- VDOM
- Object name
- Whether the object is explicitly defined under `config firewall address`
- Number of address groups using the object
- Address-group names

## FortiGate Configuration Sections Analyzed

The tool parses these FortiOS configuration sections:

```text
config firewall address
```

and:

```text
config firewall addrgrp
```

It reads group members from:

```text
set member
```

and:

```text
append member
```

## Important Notes

### Explicit Objects Only

The address count represents objects explicitly present in the selected file.

The live FortiGate GUI may show a higher count because built-in, default, or runtime-generated objects may not be included in a normal configuration backup.

### VDOM Scope

Address objects and address-group memberships are evaluated separately for each VDOM.

The same object name in two different VDOMs is treated as two separate objects.


### TAC Report Duplication

A TAC report may contain repeated configuration sections.

The tool attempts to prevent identical repeated sections from inflating object counts. If the same address group appears with different member lists in multiple parts of a TAC report, the available fragments may be combined for analysis.

### Group Membership Count

The membership count represents references inside address groups.

An object used in three different address groups contributes three memberships.

## Troubleshooting

### The tool only shows address counts

Confirm that the selected file contains:

```text
config firewall addrgrp
```

A configuration file without address-group sections cannot provide group membership information.

### No objects are found

Confirm that the selected file contains a FortiGate configuration or TAC output with:

```text
config firewall address
```

or:

```text
config firewall addrgrp
```

### The window does not open on Linux or WSL

Install Tkinter:

```bash
sudo apt install python3-tk
```

WSL also requires support for graphical Linux applications, such as WSLg on Windows 11.

### PowerShell runs an older version

Check the exact script path:

```powershell
Get-Item .\fortigate_address_group_analyzer_v3.py |
    Select-Object FullName, LastWriteTime, Length
```

Run the script using its complete path when necessary:

```powershell
python "C:\Path\To\fortigate_address_group_analyzer_v3.py"
```

## Security and Privacy

The tool analyzes files locally on the computer where it is run.

It does not:

- Upload FortiGate configurations
- Connect to a FortiGate
- Send data to an external service
- Modify the selected file
- Export analysis results

**FortiGate configuration and TAC files can contain sensitive information. Store and handle them according to your organization's security requirements.**
