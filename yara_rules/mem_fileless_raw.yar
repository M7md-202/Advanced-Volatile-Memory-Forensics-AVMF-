// YARA rules for mem_fileless.raw

rule DNS_Indicators {
    meta:
        description = "DNS indicators from memory dump"
        author = "Mohamed Mubarak"

    strings: 
	$dns001 = "aauxj.yt"
        $dns002 = "dlgofygprmqgdne.us"
	$dns003 = "fmojcylxlmeuf.ru"
	$dns004 = "fqxvhuyy.it"
        $dns005 = "ijdwcql.pw"
	$dns006 = "lyxsawiiitag.de"
        $dns007 = "yeompyokp.it"

     condition:
        any of them
}

rule Locky_Ransomware_2
{
    meta:
        description = "Detects Locky ransomware ransom-note strings in memory"
        author      = "Mohamed Mubarak"
        reference   = "Locky lab – ransom note / file extension strings"

    strings:
        // file extension used by Locky
        $a1 = ".locky" wide

        // parts of the ransom note file name
        $a2 = "_Locky" wide
        $a3 = "_recover" wide
        $a4 = "instructions" wide

        // common words from the ransom note body
        $a5 = "restore" wide nocase
        $a6 = "your files" wide nocase

        // typical extension of the ransom note file
        $a7 = ".txt" wide

    condition:
        $a1 and $a2 and $a3 and $a4 and 1 of ($a5, $a6, $a7)
}
