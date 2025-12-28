# Advanced Volatile Memory Forensics (AVMF) Dashboard

A Streamlit-based dashboard for volatile memory forensics analysis and incident response reporting.

## Features
- Upload / manage memory analysis outputs (CSV artifacts)
- Visual dashboard views (processes, network, persistence, etc.)
- Designed for demonstrating multiple attack scenarios (e.g., data exfil, credential theft, ransomware)
- Timeline reconstruction
- Network connections reconstruction
- Yara rules repository
- Dashboard which supports forensic results integration
- Automatic Forensic Reporting
- IR Playbook integration
- Secure RBAC Function

<img width="1207" height="609" alt="image" src="https://github.com/user-attachments/assets/d4452b3d-7dad-445d-a272-92c761d88493" />


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

<img width="1532" height="377" alt="image" src="https://github.com/user-attachments/assets/7a775f1b-11f3-446f-8f78-5d566fdf296f" />


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

  <img width="1508" height="519" alt="image" src="https://github.com/user-attachments/assets/bf538c73-6efb-4c42-962d-46cd13df559a" />


<img width="1557" height="513" alt="image" src="https://github.com/user-attachments/assets/b4eb2a10-a1b4-4dfc-8cae-33eddb519ad8" />


---

### 4) Configure dashboard tabs for the selected scenario
Each scenario can enable/disable which tabs appear in the dashboard.  
Go to **Settings → Dashboard Tabs for This Scenario**:
- Toggle tabs (Processes, Network, YARA Hits, Run Keys, RunOnce, Command Line, Sessions, Logon Events)
- (Optional) enable **Auto-hide empty tables/tabs**
- Click **Save scenario changes**

<img width="1507" height="564" alt="image" src="https://github.com/user-attachments/assets/edde517e-4980-4d8d-97d5-f10985d45376" />

---

### 5) Upload forensic artifacts (CSV files) for the scenario
Go to **Data Upload**.  
This page is where you upload per-scenario CSV outputs (ex: Volatility exports).  
For each table type (Processes, Network Connections, etc.):
1. Confirm the **current memory image** at the top is correct
2. Upload the matching CSV for that section
3. Confirm the page shows a message like **“Using uploaded CSV at: …”**
4. The preview table should populate (first rows)

<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/159d0e35-adec-41a4-8476-c22dba966c30" />

<img width="1919" height="1040" alt="image" src="https://github.com/user-attachments/assets/2f4d38ac-ed8b-493d-99a8-dd963b2be988" />


---

### 6) Review findings in the Dashboard
Go to **Dashboard**.  
You’ll see an overview of the selected scenario:
- Image name, scenario name, OS, acquired time
- Counters (Processes, Network Connections, YARA hits, persistence, etc.)
- Tabs with data tables

Use filters where available (PID filter / process name filter) to focus on suspicious activity.

<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/f4974147-710a-4600-86c8-77af29e2edd7" />

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
<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/b1627661-5721-448b-87c2-9e79911710bc" />


### 8) Download the Incident Response (IR) Playbook (DOCX)

Go to **IR Playbook**:
1. Select the **scenario/image**
2. Click **Download Active Playbook (.docx)**

If you see: **“python-docx is not installed. Install it to render playbooks.”**  
Install it:
```powershell
pip install python-docx
```

<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/76113f16-afb4-491d-873d-e17650764f41" />

<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/8d1a7a3c-65a8-4883-9952-fb8d013146d1" />

### 9) User Management (RBAC) (Admin only)

Admins can manage users and permissions.
Go to Settings → User Management (RBAC) :

View the RBAC table (users + permissions)

Add users (username + password + role)

Edit/remove users (select user, update role/permissions)

<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/717c7c95-6035-4b56-a3a0-16d9b60b9449" />

<img width="1492" height="288" alt="image" src="https://github.com/user-attachments/assets/9d6cc971-1538-44ae-8139-15a3633d86ac" />


### 10) Manage YARA Rules (Per Scenario)

Go to **YARA Rules**:
1. Confirm the correct **Memory image** is selected (shown at the top).
2. Use **Select a rule** to choose an existing YARA rule to view/edit.
3. (Optional) Expand **Preamble (imports / globals / comments)** if your rules use shared imports or globals.
4. Edit the **Rule text** in the editor.
5. Click **Save rule** to persist changes.
6. Use **Download .yar** to export the combined YARA rules file for the selected scenario.
7. (Optional) Use **Delete rule** to remove a rule.

<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/1ec0363b-0dec-4841-84fe-67e25841ff74" />
<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/d8e24f91-6426-4b17-aa73-246e9d2bd886" />
<img width="1872" height="955" alt="image" src="https://github.com/user-attachments/assets/0811cc39-25de-41fe-abdc-92944ff7b163" />
<img width="1874" height="952" alt="image" src="https://github.com/user-attachments/assets/5163b84e-3abb-4a18-b1a3-d48de393c176" />





