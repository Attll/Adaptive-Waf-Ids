Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-StatusProbe([string]$Uri) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing $Uri -TimeoutSec 30
        return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Server = $response.Headers["Server"]; Body = $response.Content }
    }
    catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            $reader = [System.IO.StreamReader]::new($response.GetResponseStream())
            return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Server = $response.Headers["Server"]; Body = $reader.ReadToEnd() }
        }
        throw
    }
}

$benign = Invoke-StatusProbe "http://127.0.0.1:8090/backend/public/hello"
$attack = Invoke-StatusProbe "http://127.0.0.1:8090/backend/search?q=%27%20OR%201%3D1--"

if ($benign.StatusCode -ne 200 -or $benign.Body -notmatch 'backend_reached') {
    throw "Expected benign request to reach the backend, got HTTP $($benign.StatusCode)."
}
if ($attack.StatusCode -ne 403 -or $attack.Server -notmatch 'nginx') {
    throw "Expected CRS to block the SQL injection with nginx HTTP 403, got HTTP $($attack.StatusCode)."
}

[pscustomobject]@{
    benign_status = $benign.StatusCode
    attack_status = $attack.StatusCode
    attack_server = $attack.Server
    result = "passed"
} | ConvertTo-Json
