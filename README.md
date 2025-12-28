# Advanced Volatile Memory Forensics (AVMF) Dashboard

A Streamlit-based dashboard for volatile memory forensics analysis and incident response reporting.

## Features
- Upload / manage memory analysis outputs (CSV artifacts)
- Visual dashboard views (processes, network, persistence, etc.)
- Generates reports (Word export)
- Designed for demonstrating multiple attack scenarios (e.g., data exfil, credential theft, ransomware)
- Designed for integrating incident response playbooks

## Tech Stack
- Python
- Streamlit
- Volatility 3 (analysis)
- Magnet RAM Capture (acquisition)
- python-docx (report export)
- Miller (mlr) for CSV cleanup (optional)

## Prerequisites
- Python 3.10+ (recommended)
- Git

## Project Structure
```text
.
├─ forensics_dashboard.py        # Streamlit entry point
├─ requirements.txt              # Python dependencies (recommended)
├─ README.md
├─ data/                         # Input CSV artifacts 
├─ outputs/                      # Generated reports (optional)
└─ ...
```


Run Locally (Windows/PowerShell)
1) Clone the repo

```md
powershell

Copy the code
git clone https://github.com/M7md-202/Advanced-Volatile-Memory-Forensics-AVMF-.git
cd Advanced-Volatile-Memory-Forensics-AVMF-
```

2) Create & activate a virtual environment

```md
powershell

Copy the code
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```md
powershell

Copy the code
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

3) Install dependencies
If you have requirements.txt:

```md
powershell

Copy the code
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If you don't have requirements.txt yet:

```md
powershell

Copy the code
python -m pip install --upgrade pip
pip install streamlit pandas python-docx extra-streamlit-components
```

4) Run the app

  ```md 
powershell

Copy the code
python -m streamlit run forensics_dashboard.py
```

5) (Optional) Generaterequirements.txt
After installing everything you need:

```md 
powershell

Copy the code
pip freeze > requirements.txt
```
Commit and push it:

```md 
powershell

Copy the code
git add requirements.txt
git commit -m "Add requirements"
git push
```

