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

## File Descriptions
```
main.py
```
Main entry point for the toolkit. This can be used to launch the core workflow of the project.
```
generate_hash.py
```
Generates hashes for files, which can be used for reputation checking, malware analysis, and investigation correlation.
```
virustotal_checker.py
```
Handles VirusTotal lookups and enrichment logic.
```
virus_total_gui.py
```
Provides a GUI for performing VirusTotal checks and related investigative tasks.
```
setup.bat
```
Windows setup script to help install dependencies and prepare the environment.
```
requirements.txt
```
Contains the Python dependencies required for the project.

data/

Stores supporting files, investigation inputs, or output data used by the toolkit.

## Requirements
Python 3.10 or newer recommended
Internet access for VirusTotal lookups
A VirusTotal API key if required by the scripts
Windows recommended if using setup.bat
Installation
Option 1: Manual Setup

Clone the repository:
```
git clone <your-repo-url>
cd OSINT-Tools
```
Create a virtual environment:
```
python -m venv .venv
```
Activate the virtual environment:

## Windows
```
.venv\Scripts\activate
```
Install dependencies:
```
pip install -r requirements.txt
Option 2: Windows Setup Script
```
Run the batch setup script:
```
setup.bat
```
## Configuration

If the VirusTotal scripts require an API key, set it before running the tools.

# Windows PowerShell
```
$env:VT_API_KEY="your_api_key_here"
```
# Windows CMD
```
set VT_API_KEY=your_api_key_here
```
For permanent storage on Windows:
```
setx VT_API_KEY "your_api_key_here"
```
After using setx, reopen your terminal before running the scripts.

## Usage

* Run the main tool
python main.py

* Generate a file hash
python generate_hash.py

* Run the VirusTotal checker
python virustotal_checker.py

* Launch the GUI
python virus_total_gui.py

## Typical Use Cases
Hashing suspicious files before triage
Enriching malware samples with VirusTotal
Quickly checking artifacts through a simple GUI
Supporting OSINT and malware investigation workflows
Speeding up repetitive analyst enrichment steps

## Security Notes
Do not upload sensitive, proprietary, or customer-owned files to third-party services without approval
Be aware of API rate limits when using VirusTotal
Sanitize investigation artifacts before sharing externally
Use an isolated VM or lab environment when handling suspicious files

## Future Improvements
Add command-line arguments for more flexible execution
Support bulk IOC and hash input
Export results to CSV or JSON
Improve logging and error handling
Add config file support
Add screenshots for the GUI workflow
Add unit tests for core functions

## Contributing
Contributions, fixes, and improvements are welcome. Please open an issue or submit a pull request with a clear explanation of the change.

## License
Add your preferred license here.
