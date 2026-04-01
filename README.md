# OSINT-Tools

A Python-based toolkit for security investigations, file hashing, and VirusTotal enrichment.

## Overview

OSINT-Tools is a lightweight investigation toolkit built to support malware triage, file analysis, and threat enrichment workflows. It includes utilities for generating hashes, checking artifacts against VirusTotal, and running those workflows through either scripts or a simple GUI.

This project is useful for analysts, researchers, and defenders who want a fast way to enrich suspicious files or indicators during investigations.

## Features

- Generate file hashes for analysis and reputation checks
- Query VirusTotal for file or indicator enrichment
- Simple GUI workflow for easier analyst use
- Script-based execution for repeatable investigations
- Windows-friendly setup with batch installer support

## Project Structure

```text
OSINT-Tools/
├── data/
├── README.md
├── generate_hash.py
├── main.py
├── requirements.txt
├── setup.bat
├── virus_total_gui.py
└── virustotal_checker.py
```

