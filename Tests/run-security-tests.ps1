Write-Host "=== Starting Docker Prod Test Suite ==="
Write-Host ""

# ==========================
# SSL CHECK (PostgreSQL)
# ==========================

Write-Host "=== Checking PostgreSQL SSL Status ==="

try {
    $ssl = docker exec postgresql-client-server-main-db-1 `
        psql "postgresql://app_user:AppPass456!@localhost:5432/postgres?sslmode=require" -tAc "SHOW ssl;"

    $ssl = $ssl.Trim()

    if ($ssl -eq "on") {
        Write-Host "SSL is ENABLED on the database"
    } elseif ($ssl -eq "off") {
        Write-Host "SSL is DISABLED on the database"
    } else {
        Write-Host "Could not determine SSL status"
        Write-Host "Raw output: $ssl"
    }
} catch {
    Write-Host "SSL check failed. SSL is likely OFF, credentials wrong, or connection refused."
}

# ==========================
# INJECTION TEST
# ==========================

Write-Host "=== Injection Test (API) ==="

try {
    $result = Invoke-RestMethod `
        -Uri "http://localhost:3000/api/user/accounts?id=1 OR 1=1" `
        -Method GET -ErrorAction Stop

    Write-Host "Unexpected behavior: Injection might be possible"
    Write-Host $result
} catch {
    Write-Host "Server rejected the injection attempt (GOOD)"
    Write-Host $_.Exception.Message
}

Write-Host ""

# ==========================
# PORT SCAN
# ==========================

Write-Host "=== Port Scan (Localhost) ==="

$ports = @(80, 443, 3000, 5432, 8080, 135, 445)

foreach ($port in $ports) {
    $connection = Test-NetConnection -ComputerName "localhost" -Port $port -WarningAction SilentlyContinue
    if ($connection.TcpTestSucceeded) {
        Write-Host "Port $port open"
    } else {
        Write-Host "Port $port closed"
    }
}

Write-Host ""
Write-Host "=== Test Suite Completed ==="
