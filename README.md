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
```


## Documentation

---

## User Manual (Quick Guide)

This section explains how to use the AVMF dashboard step-by-step.  

---

### 1) Log in
Open the AVMF web app and log in using your assigned username and password use either Admin or an Employee account (Permissions will differ). 
<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/e74a33f1-9602-48dc-b3fb-49630e609aa4" />

(Optional) Enable **“Keep me logged in”** for demos/testing.

📸 **Screenshot to take:**  
**Login page** showing the AVMF header + Username/Password fields + “Keep me logged in” + Log in button.  
**Save as:** `docs/images/01_login.png`

---

### 2) Add a new scenario/image (memory case)
A “Scenario/Image” represents one investigation (example: `data_exfil.raw`).  
Go to **Settings → Add new scenario/image** and fill:
- **Memory dump filename/label (unique)** (example: `data_exfil.raw`)
- **Scenario name** (example: `HTTP Data Exfiltration`)
- **Operating OS** (example: `Windows 11`)
- **Acquired At** (date/time)
- **Pipeline** (example: `generic`)

Click **Add scenario**.

📸 **Screenshot to take:**  
**Settings page** showing the “Add new scenario/image” section with the form fields + the **Add scenario** button.  
**Save as:** `docs/images/02_add_scenario.png`

---

### 3) Edit or delete an existing scenario/image
Go to **Settings → Edit/delete existing scenario/image**:
- Select the scenario/image from the dropdown
- Update the metadata (rename label, OS, acquired time, pipeline)
- (Optional) Enable the checkbox to rename legacy scenario files (if your build supports it)
- Click **Save scenario changes**

To delete:
- Select scenario
- (Optional) enable “Also delete this image’s CSVs + YARA hits + scenario playbook”
- Click **Delete scenario**

📸 **Screenshot to take:**  
**Settings page** showing:
- the scenario dropdown (selected scenario visible)
- scenario metadata fields
- Save scenario changes + Delete scenario section/buttons  
**Save as:** `docs/images/03_edit_delete_scenario.png`

---

### 4) Configure dashboard tabs for the selected scenario
Each scenario can enable/disable which tabs appear in the dashboard.  
Go to **Settings → Dashboard Tabs for This Scenario**:
- Toggle tabs (Processes, Network, YARA Hits, Run Keys, RunOnce, Command Line, Sessions, Logon Events)
- (Optional) enable **Auto-hide empty tables/tabs**
- Click **Save scenario changes**

📸 **Screenshot to take:**  
**Settings page** showing the “Dashboard Tabs for This Scenario” section with checkboxes and Save scenario changes button.  
**Save as:** `docs/images/04_tabs_config.png`

---

### 5) Upload forensic artifacts (CSV files) for the scenario
Go to **Data Upload**.  
This page is where you upload per-scenario CSV outputs (ex: Volatility exports).  
For each table type (Processes, Network Connections, etc.):
1. Confirm the **current memory image** at the top is correct
2. Upload the matching CSV for that section
3. Confirm the page shows a message like **“Using uploaded CSV at: …”**
4. The preview table should populate (first rows)

📸 **Screenshot to take:**  
**Data Upload page** showing:
- “Current memory image: …”
- At least one upload section (Processes) with “Using uploaded CSV …”
- A preview table of rows  
**Save as:** `docs/images/05_data_upload.png`

---

### 6) Review findings in the Dashboard
Go to **Dashboard**.  
You’ll see an overview of the selected scenario:
- Image name, scenario name, OS, acquired time
- Counters (Processes, Network Connections, YARA hits, persistence, etc.)
- Tabs with data tables

Use filters where available (PID filter / process name filter) to focus on suspicious activity.

📸 **Screenshot to take:**  
**Dashboard page** showing:
- the top overview cards + counters
- at least one populated table (Processes and/or Network Connections)  
**Save as:** `docs/images/06_dashboard.png`

---

### 7) Generate a forensic report (TXT + optional Word)
Go to **Reports**:
- Review the report preview
- Click **Download as text (.txt)**
- For Word export, ensure `python-docx` is installed

If you see: **“Install python-docx to enable Word export.”**  
Install it:
```powershell
pip install python-docx
git push
```


