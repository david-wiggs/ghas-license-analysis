# GitHub Advanced Security License Analysis

A Python utility for analyzing GitHub Advanced Security (GHAS) license usage and requirements across GitHub Enterprise organizations and repositories.

## Overview

This tool helps GitHub Enterprise administrators analyze their GHAS license utilization by:

1. Fetching active committers from repositories within specified organizations
2. Comparing these committers against existing GHAS license allocations
3. Identifying committers who are not currently covered by GHAS licenses
4. Generating comprehensive reports in both Markdown and CSV formats

## Features

- Analyzes GHAS license allocation and usage
- Identifies active repository committers from the last 90 days
- Compares existing GHAS license holders against active committers
- Identifies users who need GHAS licenses but don't have them
- Supports individual repositories or entire organizations
- Generates detailed reports in multiple formats

## Usage

```bash
python analysis.py --token YOUR_PAT --enterprise ENTERPRISE_NAME [OPTIONS]
```

### Required Arguments

- `--token` / `-t`: GitHub Personal Access Token with appropriate permissions
- `--enterprise` / `-e`: GitHub Enterprise name (required for GHAS analysis)

### Optional Arguments

- `--csv` / `-c`: Path to CSV file containing organizations (format: org)
- `--orgs` / `-g`: List of organizations to analyze (space-separated)
- `--output` / `-o`: Output file path (default: github_analysis_report.md)
- `--enterprise_server_hostname` / `-H`: GitHub Enterprise Server hostname
- `--debug` / `-d`: Enable debug logging

## Output

The script generates several reports in a dedicated reports folder:

1. Markdown summary report
2. CSV list of GHAS-licensed committers
3. CSV list of committers without GHAS licenses
4. Repository analysis with committer details
5. Repository summary with committer counts

## Example

```bash
python analysis.py -t ghp_YOUR_TOKEN -e your-enterprise -g org1 org2 org3
```

## Requirements

- Python 3.6+
- Required packages:
  - requests
  - argparse
  - csv