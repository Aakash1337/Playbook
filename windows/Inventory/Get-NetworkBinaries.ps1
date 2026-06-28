param(
  [switch]$IncludeSignatureAndHash,
  [string]$OutCsv = ".\network_binaries.csv"
)

function Get-ProcInfo {
  param([int]$ProcessId)

  $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  if (-not $p) { return $null }

  $path = $null
  try { $path = $p.Path } catch { $path = $null }

  $company = $null
  $desc = $null

  try {
    if ($path -and (Test-Path -LiteralPath $path)) {
      $vi = (Get-Item -LiteralPath $path).VersionInfo
      $company = $vi.CompanyName
      $desc = $vi.FileDescription
    }
  } catch {}

  $obj = [ordered]@{
    ProcessName = $p.ProcessName
    PID         = $ProcessId
    ImagePath   = $path
    Company     = $company
    Description = $desc
  }

  if ($IncludeSignatureAndHash -and $path -and (Test-Path -LiteralPath $path)) {
    try {
      $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
      $obj.SignerCertificateSubject = $sig.SignerCertificate.Subject
      $obj.SignatureStatus          = $sig.Status
    } catch {
      $obj.SignerCertificateSubject = $null
      $obj.SignatureStatus          = "Unknown"
    }

    try {
      $obj.SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path -ErrorAction Stop).Hash
    } catch {
      $obj.SHA256 = $null
    }
  } else {
    $obj.SignerCertificateSubject = $null
    $obj.SignatureStatus          = $null
    $obj.SHA256                   = $null
  }

  # Map PID to service(s), if any
  try {
    $svcs = Get-CimInstance Win32_Service -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty Name
    $obj.Services = ($svcs -join ",")
  } catch {
    $obj.Services = $null
  }

  return [PSCustomObject]$obj
}

$results = @()

# TCP
Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
  $pi = Get-ProcInfo -ProcessId $_.OwningProcess

  $results += [PSCustomObject]@{
    Proto           = "TCP"
    ProcessName     = $pi.ProcessName
    PID             = $_.OwningProcess
    ImagePath       = $pi.ImagePath
    Services        = $pi.Services
    Company         = $pi.Company
    Description     = $pi.Description
    LocalIP         = $_.LocalAddress
    LocalPort       = $_.LocalPort
    RemoteIP        = $_.RemoteAddress
    RemotePort      = $_.RemotePort
    State           = $_.State
    SignatureStatus = $pi.SignatureStatus
    Signer          = $pi.SignerCertificateSubject
    SHA256          = $pi.SHA256
  }
}

# UDP
Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
  $pi = Get-ProcInfo -ProcessId $_.OwningProcess

  $results += [PSCustomObject]@{
    Proto           = "UDP"
    ProcessName     = $pi.ProcessName
    PID             = $_.OwningProcess
    ImagePath       = $pi.ImagePath
    Services        = $pi.Services
    Company         = $pi.Company
    Description     = $pi.Description
    LocalIP         = $_.LocalAddress
    LocalPort       = $_.LocalPort
    RemoteIP        = $null
    RemotePort      = $null
    State           = $null
    SignatureStatus = $pi.SignatureStatus
    Signer          = $pi.SignerCertificateSubject
    SHA256          = $pi.SHA256
  }
}

$results =
  $results |
  Sort-Object Proto,PID,LocalIP,LocalPort,RemoteIP,RemotePort |
  Select-Object Proto,ProcessName,PID,ImagePath,Services,Company,Description,LocalIP,LocalPort,RemoteIP,RemotePort,State,SignatureStatus,Signer,SHA256

# Display
$results | Format-Table -AutoSize

# Export evidence
$results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
Write-Host "`nWrote: $OutCsv"
