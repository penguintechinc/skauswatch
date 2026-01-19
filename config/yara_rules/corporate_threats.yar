/*
 * Corporate Threat Detection YARA Rules
 * Custom rules for detecting corporate-specific threats
 *
 * Add your organization's custom threat signatures here.
 * Rules should be tested before deployment.
 */

rule EICAR_Test_File {
    meta:
        description = "EICAR test file for antivirus testing"
        author = "SkausWatch"
        date = "2024-01-01"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Download {
    meta:
        description = "Detects PowerShell commands that download and execute content"
        author = "SkausWatch"
        date = "2024-01-01"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $download1 = "downloadstring" nocase
        $download2 = "downloadfile" nocase
        $download3 = "invoke-webrequest" nocase
        $download4 = "wget" nocase
        $exec1 = "iex" nocase
        $exec2 = "invoke-expression" nocase
        $exec3 = "-enc" nocase
        $exec4 = "-encodedcommand" nocase
    condition:
        $ps1 and (any of ($download*)) and (any of ($exec*))
}

rule Suspicious_Office_Macro {
    meta:
        description = "Detects suspicious macro indicators in Office documents"
        author = "SkausWatch"
        date = "2024-01-01"
        severity = "medium"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Auto_Open" nocase
        $auto3 = "Document_Open" nocase
        $auto4 = "Workbook_Open" nocase
        $shell1 = "WScript.Shell" nocase
        $shell2 = "Shell.Application" nocase
        $http1 = "XMLHTTP" nocase
        $http2 = "WinHttp" nocase
    condition:
        (any of ($auto*)) and ((any of ($shell*)) or (any of ($http*)))
}

rule Base64_Encoded_PE {
    meta:
        description = "Detects Base64-encoded PE files"
        author = "SkausWatch"
        date = "2024-01-01"
        severity = "high"
    strings:
        $b64_mz1 = "TVqQAAMAAAA" // MZ header base64
        $b64_mz2 = "TVpQAAIAAAA"
        $b64_mz3 = "TVroAAAAAAA"
    condition:
        any of ($b64_mz*)
}

rule Cryptocurrency_Miner_Strings {
    meta:
        description = "Detects cryptocurrency mining software strings"
        author = "SkausWatch"
        date = "2024-01-01"
        severity = "medium"
    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $miner1 = "xmrig" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "minerd" nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ // Bitcoin address pattern
        $monero = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ // Monero address pattern
    condition:
        (any of ($pool*)) or (2 of ($miner*)) or ($wallet and any of ($miner*)) or ($monero and any of ($miner*))
}
