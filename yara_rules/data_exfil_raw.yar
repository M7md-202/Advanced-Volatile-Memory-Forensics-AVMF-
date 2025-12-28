// YARA rules for mem_beacon.raw

rule WIN_PowerShell_EncodedCommand_Suspicious
{
  meta:
    author = "Mohamed Mubarak"
    purpose = "Detect suspicious encoded PowerShell command usage (common in attacks)"
    confidence = "medium"
    scope = "process_memory_or_script"
  strings:
    // Common obfuscation / stealth switches
    $ps1 = "powershell" ascii nocase
    $sw1 = "-nop" ascii nocase
    $sw2 = "-w hidden" ascii nocase
    $sw3 = "-windowstyle hidden" ascii nocase
    $sw4 = "-ep bypass" ascii nocase
    $sw5 = "-executionpolicy bypass" ascii nocase
    $enc1 = " -enc " ascii nocase
    $enc2 = " -encodedcommand " ascii nocase

    // Often appears when decoding payloads
    $b64a = "FromBase64String" ascii nocase
    $iex  = "IEX" ascii nocase
    $iex2 = "Invoke-Expression" ascii nocase

  condition:
    $ps1 and
    (
      (1 of ($enc*)) and
      (2 of ($sw1,$sw2,$sw3,$sw4,$sw5)) and
      (any of ($b64a,$iex,$iex2))
    )
}
