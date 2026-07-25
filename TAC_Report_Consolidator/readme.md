# TAC Report Consolidator

`tac_merge.py` combines all `.log` files from a FortiManager or FortiAnalyzer GUI TAC report archive into one readable text file.

## Requirements

- Python 3
- No additional Python packages are required

## Download

Clone the repository:

```bash
git clone https://github.com/ilfarhanahmed/Fortinet_Tools.git
cd Fortinet_Tools/TAC_Report_Consolidator
```

## Usage

```bash
python3 tac_merge.py <TAC_REPORT_FILE>
```

Example:

```bash
python3 tac_merge.py FMG_TAC_Report.tar.gz
```

On Windows:

```powershell
py tac_merge.py "C:\TAC Reports\FMG_TAC_Report.tar.gz"
```

## Save the Output to a Specific Directory

Use `-o` or `--output_dir`:

```bash
python3 tac_merge.py FMG_TAC_Report.tar.gz -o merged_reports
```

The output directory is created automatically if it does not exist.

## Output

The script creates a timestamped text file:

```text
TAC_Report_Merged_YYYYMMDD_HHMMSS.txt
```

Example:

```text
TAC_Report_Merged_20260619_153000.txt
```

Each TAC report command is placed in its own section:

```text
### get_system_status

<command output>

### diagnose_system_top

<command output>
```


Only `.log` files inside the archive are added to the merged report.



## Important

TAC reports may contain sensitive information such as IP addresses, hostnames, usernames, serial numbers, and configuration details. Review the merged file before sharing it.
