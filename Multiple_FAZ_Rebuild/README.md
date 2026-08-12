# FortiAnalyzer Database Rebuild Script

A simple Python script to connect to multiple FortiAnalyzer devices over SSH and trigger a local SQL database rebuild.

## Files

```text
faz_rebuild.py
faz_hosts.txt
README.md
```

## Requirements

- Python 3
- Paramiko

Install Paramiko:

```powershell
py -m pip install paramiko
```

## Admin Account

The script uses a **single administrator account for all FortiAnalyzer devices** listed in `faz_hosts.txt`.

Set the administrator username on **line 5** of `faz_rebuild.py`:

```python
USERNAME = "admin"
```

Change `admin` if a different administrator username is used on the FortiAnalyzer devices.

The script prompts for the SSH password when it starts, and the same username/password is used to connect to each FAZ.

## Configure FAZ Devices

Add one FortiAnalyzer IP address or hostname per line in `faz_hosts.txt`:

```text
10.128.210.142
10.128.210.148
```

## Run the Script

From PowerShell:

```powershell
py .\faz_rebuild.py
```

The script will ask for the SSH password:

```text
SSH password:
```

## What the Script Does

For each FortiAnalyzer, the script:

1. Connects over SSH.
2. Runs:

```text
execute sql-local rebuild-db
```

3. Waits for the confirmation prompt.
4. Sends `y`.
5. Moves to the next FAZ.

Example output:

```text
[10.128.210.142] Connecting...
[10.128.210.142] Connected
Do you want to continue? (y/n)
[10.128.210.142] Starting DB rebuild...
[10.128.210.142] Rebuild triggered

Done.
```

## Important

`execute sql-local rebuild-db` rebuilds the FortiAnalyzer SQL database and can reboot the appliance.

Test the script on a lab or non-critical FortiAnalyzer before running it against multiple production devices.

It is recommended to process devices sequentially rather than rebuilding many FortiAnalyzers at the same time.

## Optional Verification

After a FortiAnalyzer comes back online, rebuild status can be checked with:

```text
diagnose sql status rebuild-db
```
