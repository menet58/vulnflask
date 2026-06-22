rule Detecta_Texto_Test {
    strings:
        $a = "powershell"
    condition:
        $a
}
