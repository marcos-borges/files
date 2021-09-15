<#
    .SYNOPSIS
  
        Uninstall and re-install the Falcon Sensor to the same or different CIDs, and Clouds, using RTR or
    by standard PowerShell with privileged execution.
    PS v3 or higher required
    TLS 1.2 required
    .NOTES
        Version:        3.0
        Authors:        Marcos Ferreira
        Last Updater:   Marcos Ferreira
        Creation Date:  2021-03-20
        Update Date:    2021-05-10
        Purpose/Change: Initial version
        Usage:      Use at your own risk. While all efforts have been made to ensure this script works as expected, you should test
            in your own environment. This script uses security details that could allow bypass of sensor security controls, and
            availability should be controlled.
    Reference: To create the API client and secrets required please follow the below support article.
    https://supportportal.crowdstrike.com/s/article/How-to-Retrieve-an-Uninstall-Token-When-a-Host-Has-Aged-Out-of-the-Falcon-Console
    Requirements:
    Falcon Administrator role required for Created API access
    PowerShell v3 or higher
    TLS 1.2 minimum
    Sign the script, or execute with bypass
  
  
    .DESCRIPTION
        Uninstall and re-install the Falcon Sensor using RTR or PowerShell via an automation process.
    Privileged escalation of powershell required. One way to do this is:
    powershell -ep Bypass .\ReplaceFalcon.ps1
        Uninstallation token is obtained via reveal-uninstall-token API call to the source cloud.
        Installatin package will be downloaded via download-installer API call to the destination cloud.
  
    .PARAMETER SourceId
        OAuth2 API Client Id from the source tenant.
  
    .PARAMETER SourceSecret
        OAuth2 API Client Secret from the source tenant.
  
    .PARAMETER DestinationId
        OAuth2 API Client Id from the destination tenant.
  
    .PARAMETER DestinationSecret
        OAuth2 API Client Secret from the destination tenant.
  
    .PARAMETER FromCloud
        Specifies the source Cloud.
    'EU' = https://api.eu-1.crowdstrike.com
        'US' = https://api.crowdstrike.com
        'US-2' = https://api.us-2.crowdstrike.com
        'USFed' = https://api.laggar.gcw.crowdstrike.com
  
    .PARAMETER ToCloud
        Specifies the destination Cloud.
    See list above
  
    .PARAMETER InstallerPath
        Specifies installation file package path. Change to match your environment. If file not present, it will download from the cloud.
  
    .PARAMETER InstallArgs
        Specifies installation arguments. Use Recommended options.
  
    .PARAMETER CID
        Specifies destination CID with checksum. Obtained on sensor download page.
      
    .PARAMETER Hash
        Specifies the installation package hash (SHA256) of the Sensor version you wish to install. Obtained on sensor download page.
  
    .PARAMETER AuditMessage
        Add a custom message for audit records in the Falcon UI.
#>
<# -------------------      Begin Editable Region. -------------- #>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]
    $SourceId = '',
 
    [Parameter(Mandatory = $false)]
    [string]
    $SourceSecret = '',
 
    [Parameter(Mandatory = $false)]
    [string]
    $DestinationId = '',
 
    [Parameter(Mandatory = $false)]
    [string]
    $DestinationSecret = '',
 
    [ValidateSet('EU', 'US', 'US-2', 'USFed')]
    [string]
    $FromCloud = 'US',
 
    [ValidateSet('EU', 'US', 'US-2', 'USFed')]
    [string]
    $ToCloud = 'US',
 
    [Parameter(Mandatory = $false)]
    [string]
    $InstallerPath = 'C:\WindowsSensor.exe',
 
    [Parameter(Mandatory = $false)]
    [string]
    $InstallArgs = '/install /quiet /noreboot ProvNoWait=1',
 
    [Parameter(Mandatory = $false)]
    [string]
    $CID = '',
 
    [Parameter(Mandatory = $false)]
    [string]
    $Hash = '',
 
    [Parameter(Mandatory = $false)]
    [string]
    $AuditMessage = 'ReplaceFalcon Real-Time Response script',
 
    [Parameter(Mandatory = $false)]
    [string]
    $Proxy = ''
)
<# ----------------      END Editable Region. ----------------- #>
begin {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    switch ($FromCloud) {
        'EU' { $SrcHostname = 'https://api.eu-1.crowdstrike.com' }
        'US' { $SrcHostname = 'https://api.crowdstrike.com' }
        'US-2' { $SrcHostname = 'https://api.us-2.crowdstrike.com' }
        'USFed' { $SrcHostname = 'https://api.laggar.gcw.crowdstrike.com' }
    }
 
    switch ($ToCloud) {
        'EU' { $DstHostname = 'https://api.eu-1.crowdstrike.com' }
        'US' { $DstHostname = 'https://api.crowdstrike.com' }
        'US-2' { $DstHostname = 'https://api.us-2.crowdstrike.com' }
        'USFed' { $DstHostname = 'https://api.laggar.gcw.crowdstrike.com' }
    }
 
    # Check for necessary cmdlets
    $cmds = @(
        "ConvertFrom-Json",
        "ConvertTo-Json",
        "Get-ChildItem",
        "Get-FileHash",
        "Get-Process",
        "Get-Service",
        "Invoke-WebRequest",
        "Remove-Item",
        "Start-Process",
        "Test-Path",
        "Write-Output"
    )
     
    foreach ($cmd in $cmds) {
        if (-not (Get-Command $cmd -errorAction SilentlyContinue)) {
            throw "The term '$($cmd)' is not recognized as the name of a cmdlet."
        } 
    }
 
    if ($Proxy) {
        $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
        $PSDefaultParameterValues = @{
            'Invoke-WebRequest:Proxy' = $Proxy
        }
    }
 
    # Registry paths for uninstall information
    $UninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    # HostId value from registry
    $HostId = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\" +
    "{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}" +
    "\Default") -Name AG).AG)).ToLower() -replace '-','')
}
 
process {
    # Validate if API credentials have been set.
    if ((-not $SourceId) -or (-not $SourceSecret) -or (-not $DestinationId) -or (-not $DestinationSecret)) {
        throw "API credentials not configured properly"
    }
 
    $Param = @{
        Uri = "$($SrcHostname)/oauth2/token"
        Method = 'post'
        Headers = @{
            accept = 'application/json'
            'content-type' = 'application/x-www-form-urlencoded'
        }
        Body = @{
            'client_id' = $SourceId
            'client_secret' = $SourceSecret
        }
    }
 
    # Get API Token
    $SrcToken = try {
        (Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json
    }
     
    catch {
        if ($_.ErrorDetails) {
            $_.ErrorDetails | ConvertFrom-Json
        }
        else {
            $_.Exception
        }
    }
 
    if (-not $SrcToken.access_token) {
        if ($SrcToken.GetType().Name -eq "WebException") {
            throw "Unable to request token from source cloud $($FromCloud) using client id $($SourceId). Return was: $($SrcToken)"
        } else {           
            throw "Unable to request token from source cloud $($FromCloud) using client id $($SourceId). Return error code: $($SrcToken.errors.code). Return error message: $($SrcToken.errors.message)"
        }
    }
 
    $Param = @{
        Uri = "$($DstHostname)/oauth2/token"
        Method = 'post'
        Headers = @{
            accept = 'application/json'
            'content-type' = 'application/x-www-form-urlencoded'
        }
        Body = @{
            'client_id' = $DestinationId
            'client_secret' = $DestinationSecret
        }
    }
 
    # Get API Token
    $DstToken = try {
        (Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json
    }
     
    catch {
        if ($_.ErrorDetails) {
            $_.ErrorDetails | ConvertFrom-Json
        }
        else {
            $_.Exception
        }
    }
 
    if (-not $DstToken.access_token) {
        if ($DstToken.GetType().Name -eq "WebException") {
            throw "Unable to request token from source cloud $($ToCloud) using client id $($DestinationId). Return was: $($DstToken)"
        } else {           
            throw "Unable to request token from source cloud $($ToCloud) using client id $($DestinationId). Return error code: $($DstToken.errors.code). Return error message: $($DstToken.errors.message)"
        }
    }
 
    if ((-not $CID) -Or ($CID -NotMatch '[A-z0-9]{32}-[A-z0-9]{2}')) {
        $Param = @{
            Uri = "$($DstHostname)/sensors/queries/installers/ccid/v1"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($DstToken.token_type) $($DstToken.access_token)"
            }
        }
         
        # Get destination CID
        $CID = try {
            ((Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json).resources[0]
        }
 
        catch {
            if ($_.ErrorDetails) {
                $_.ErrorDetails | ConvertFrom-Json
            }
            else {
                $_.Exception
            }
        }
         
        if ((-not $CID) -Or ($CID -NotMatch  '[A-z0-9]{32}-[A-z0-9]{2}')) {
            throw "Unable to determine CID used in this process. Please use -CID or define `$CID default value in this script."
        }
    }
 
    $InstallArgs += " CID=$CID"
     
    if (-not $Hash) {
        $Param = @{
            Uri = "$($DstHostname)/policy/combined/sensor-update/v1?filter=platform_name%3A%20%27Windows%27%2Bname%3A%20%27platform_default%27"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($DstToken.token_type) $($DstToken.access_token)"
            }
        }
         
        # Find sensor build from default policy
        $SensorBuild = try {
            (((Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json).resources[0].settings.build) -replace '\D+',''
        }
 
        catch {
            if ($_.ErrorDetails) {
                $_.ErrorDetails | ConvertFrom-Json
            }
            else {
                $_.Exception
            }
        }
 
        $Param = @{
            Uri = "$($DstHostname)/sensors/combined/installers/v1?filter=platform%3A%27windows%27"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($DstToken.token_type) $($DstToken.access_token)"
            }
        }
         
        $Installers = Invoke-WebRequest @Param -UseBasicParsing | ConvertFrom-Json
         
        foreach ($findBuild in $Installers.resources) {
            if (($findBuild.version -replace '.*\.') -eq $SensorBuild) {
                $Hash = $findBuild.sha256
                break
            }
        }
        if (-not $Hash) {
            throw "Unable to determine installation package hash to be used in this process. Please use -hash or define `$Hash default value in this script."
        }
    }
         
    if (Test-Path $InstallerPath) {
        if ((Get-FileHash $InstallerPath).Hash.ToUpper() -ne $Hash.ToUpper()) {
            Remove-Item $InstallerPath
        }
    }
 
    if ((Test-Path $InstallerPath) -eq $false) {
        if (-not $Hash) {
            throw "Hash not configured in script"
        }
        $Param = @{
            Uri = "$($DstHostname)/sensors/entities/download-installer/v1?id=" + $Hash
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($DstToken.token_type) $($DstToken.access_token)"
            }
            OutFile = $InstallerPath
        }
        $Request = try {
            Invoke-WebRequest @Param -UseBasicParsing
        }
 
        catch {
            if ($_.ErrorDetails) {
                $_.ErrorDetails | ConvertFrom-Json
            }
            else {
                $_.Exception
            }
        }
 
        if ((Test-Path $InstallerPath) -eq $false) {
            throw "Unable to locate $($InstallerPath)"
        }
        if ((Get-FileHash $InstallerPath).Hash.ToUpper() -ne $Hash.ToUpper()) {
            throw "$($InstallerPath) hash differs. File looks like corrupted."
        }
    }
     
    if (-not $InstallArgs) {
        throw "No installation arguments configured in script"
    }
 
    if (-not $HostId) {
        throw "Unable to retrieve host identifier"
    }
 
    foreach ($Key in (Get-ChildItem $UninstallKeys)) {
        if ($Key.GetValue("DisplayName") -like "*CrowdStrike Windows Sensor*") {
            # Create uninstall string
            $Uninstall = "/c $($Key.GetValue("QuietUninstallString"))"
        }
    }
 
    if (-not $Uninstall) {
        throw "QuietUninstallString not found for CrowdStrike Windows Sensor"
    }
 
    $Param = @{
        Uri = "$($SrcHostname)/policy/combined/reveal-uninstall-token/v1"
        Method = 'post'
        Headers = @{
            accept = 'application/json'
            'content-type' = 'application/json'
            authorization = "$($SrcToken.token_type) $($SrcToken.access_token)"
        }
        Body = @{
            audit_message = $AuditMessage
            device_id = $HostId
        } | ConvertTo-Json
    }
 
    # Get sensor uninstall token
    $Request = try {
        Invoke-WebRequest @Param -UseBasicParsing | ConvertFrom-Json
    }
 
    catch {
        if ($_.ErrorDetails) {
            $_.ErrorDetails | ConvertFrom-Json
        }
        else {
            $_.Exception
        }
    }
 
    if (-not $Request.resources) {
        throw "Unable to retrieve uninstall token"
    }
    $Uninstall += " MAINTENANCE_TOKEN=$($Request.resources.uninstall_token)"
     
    Start-Process -FilePath cmd.exe -ArgumentList $Uninstall -PassThru | ForEach-Object {
        Write-Output "[$($_.Id)] '$($_.ProcessName)' beginning removal; sensor will become unresponsive..."
        $WaitInstall = ("-WindowStyle Hidden -Command &{ Wait-Process -Id $($_.Id); do { Start-Sleep -Seconds 5 } until ((Get-Service" +
        " -Name CSFalconService -ErrorAction SilentlyContinue) -eq `$null -And @(Get-Process -ErrorAction" +
        " SilentlyContinue msiexec).count -le 1); Start-Process -FilePath" +
        " $InstallerPath -ArgumentList '$InstallArgs' }")
        Start-Process -FilePath powershell.exe -ArgumentList $WaitInstall
    }
}
