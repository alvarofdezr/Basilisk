/* basilisk/rules/index.yar - Base de Firmas v1.0 */

rule EICAR_Test_File {
    meta:
        description = "Test File (EICAR Standard)"
        author = "basilisk EDR"
        severity = "CRITICAL"
    strings:
        // Detecta la cadena EICAR estándar ignorando mayúsculas/minúsculas
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii wide nocase
    condition:
        $s1
}

rule Suspicious_WebShell_PHP {
    meta:
        description = "Possible PHP Webshell"
        author = "basilisk EDR"
        severity = "CRITICAL"
    strings:
        $s1 = "shell_exec" nocase
        $s2 = "base64_decode" nocase
        $s3 = "$_POST" nocase
    condition:
        $s1 and $s2 and $s3
}

rule Mimikatz_Memory_Pattern {
    meta:
        description = "Mimikatz Credential Dumper Artifacts"
        author = "basilisk EDR"
        severity = "CRITICAL"
    strings:
        $s1 = "gentilkiwi" wide ascii nocase
        $s2 = "sekurlsa" wide ascii nocase
    condition:
        any of them
}