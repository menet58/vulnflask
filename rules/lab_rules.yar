rule Windows_Command_Strings {
    strings:
        $cmd = "cmd.exe" nocase
        $ps = "powershell" nocase
        $curl = "curl " nocase
        $wget = "wget " nocase
    condition:
        any of them
}

rule Suspicious_Script_Keywords {
    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $b64 = "base64" nocase
    condition:
        any of them
}
