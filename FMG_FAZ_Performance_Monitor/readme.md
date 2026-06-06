# FortiManager/FortiAnalyzer Performance Monitor

A Python terminal monitor for FoetiManager/FortiAnalyzer system performance and log forwarding status.

## Features

- CPU usage
- Per-core CPU usage
- Memory usage
- Disk usage
- Disk I/O utilization
- Receive and insert lograte - FAZ Only
- Log forwarding connected/disconnected status - FAZ Only
- Auto-refresh every few seconds

## API Endpoints Used

```text
/fazsys/monitor/system/performance/status
/fazsys/monitor/logforward-status
/fazsys/monitor/logforward-status
/cli/global/system/performance
sys./status
```

## Usage

- On FMG/FAZ create an API Admin user with JSON-RPC permission set to at least 'Read'.
- Set trusted host subnet for the admin user.

### Install Requirements
```text
pip install -r requirements.txt
```
### Copy the example config
```text
cp config.example.ini config.ini
```
### Edit config.ini
- Set the FMG/FAZ IP or FQDN 
- Set the API KEY
- Set the "internal" in seconds - monitor refresh rate
```text
[config]
url = https://<FMG/FAZ_IP_or_FQDN>/jsonrpc
api_key = <API_KEY>
verify_ssl = false
interval = 5
```
### Run
```python
python perf_monitor.py
```
Run Once:
```python
python perf_monitor.py --once
```
Use a different config file:
```python
python perf_monitor.py --config /path/to/config.ini
```

Override refresh interval:
```python
python perf_monitor.py --interval 10
```


## ⚠️ Security

SSL verification is disabled by default (`verify=False`) to support self-signed
certificates. To enable verification, in the **config.ini** file:

#### If using the FQDN - make sure it matches the certificate, not just the IP:
```text
verify_ssl = true
```

#### OR
Set the path to FMG/FAZ Certificate
```text
verify_ssl = certs/ca.pem
```

replace with your
FMG/FAZ's CA certificate path:

```python
verify_ssl = "/path/to/ca-cert.pem"
```