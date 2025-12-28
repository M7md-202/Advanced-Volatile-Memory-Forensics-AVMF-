// YARA rules for mem_creds.raw

rule Credtheft_Enumeration_Artifacts
{
  meta:
    author = 'Mohamed Mubarak"
    purpose = "Detect simulated credential enumeration/staging artifacts"
    scope = "process memory / strings"

  strings:
    $a1 = "cmdkey /list" ascii nocase
    $a2 = "cmdkey.exe" ascii nocase
    $b1 = "C:\\Lab\\cred_list.txt" ascii nocase
    $b2 = "C:\\Lab\\secrets.txt" ascii nocase
    $b3 = "C:\\Lab\\staged_creds.txt" ascii nocase
    $ps1 = "-NoP" ascii nocase
    $ps2 = "-W Hidden" ascii nocase
    $ps3 = "ExecutionPolicy Bypass" ascii nocase
    $ps4 = "Out-File" ascii nocase

  condition:
    any of them
}
