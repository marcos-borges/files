<#
    .SYNOPSIS
   
        Uninstall and re-install the Falcon Sensor to the same or different CIDs, and Clouds, recover borken installs (best effort),
        uninstall sensor using RTR or by standard PowerShell with privileged execution.
        PS v3 or higher required
        TLS 1.2 required
    .NOTES
        Version:        4.2
        Authors:        Marcos Ferreira
        Last Updater:   Marcos Ferreira
        Creation Date:  2021-03-20
        Update Date:    2022-11-18
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
 
    .PARAMETER Action
        Define action to be used. Valid options: 'Migrate','Recover','Uninstall'
   
    .PARAMETER SourceId
        OAuth2 API Client Id from the source tenant.
   
    .PARAMETER SourceSecret
        OAuth2 API Client Secret from the source tenant.
   
    .PARAMETER DestinationId
        OAuth2 API Client Id from the destination tenant.
   
    .PARAMETER DestinationSecret
        OAuth2 API Client Secret from the destination tenant.
   
    .PARAMETER FromCloud
        Specifies the source Cloud. If you don't specify the script will try to autodiscover.
        'eu-1' = https://api.eu-1.crowdstrike.com
        'us-1' = https://api.crowdstrike.com
        'us-2' = https://api.us-2.crowdstrike.com
        'us-gov-1' = https://api.laggar.gcw.crowdstrike.com
   
    .PARAMETER ToCloud
        Specifies the destination Cloud.
    See list above
   
    .PARAMETER InstallerPath
        Specifies installation file package path. Change to match your environment. If file not present, it will download from the cloud.
   
    .PARAMETER InstallArgs
        Specifies installation arguments. Use Recommended options.
 
    .PARAMETER SensorProxyCheck
        Check if the current installation have proxy configuration and if the InstallArgs have it as well.
 
    .PARAMETER KeepSensorConfiguration
        Keep sensor configuration such as PROXY, TAG, modules.
 
    .PARAMETER BulkToken
        Specifies maitenance token to be used.
   
    .PARAMETER CID
        Specifies destination CID with checksum. Obtained on sensor download page.
       
    .PARAMETER Hash
        Specifies the installation package hash (SHA256) of the Sensor version you wish to install. Obtained on sensor download page.
   
    .PARAMETER AuditMessage
        Add a custom message for audit records in the Falcon UI.
 
    .PARAMETER Proxy
        Set proxy to be used by this script.
#>
<# -------------------      Begin Editable Region. -------------- #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Migrate','Recover','Uninstall',IgnoreCase=$false)]
    [string]
    $Action = 'Migrate',
 
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
  
    [ValidateSet('eu-1', 'us-1', 'us-2', 'us-gov-1')]
    [string]
    $FromCloud = '',
  
    [ValidateSet('eu-1', 'us-1', 'us-2', 'us-gov-1')]
    [string]
    $ToCloud = '',
  
    [Parameter(Mandatory = $false)]
    [string]
    $InstallerPath = 'C:\WindowsSensor.exe',
  
    [Parameter(Mandatory = $false)]
    [string]
    $InstallArgs = '/install /quiet /norestart ProvNoWait=1',
 
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet($false,$true)]
    $SensorProxyCheck = $true,
  
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet($false,$true)]
    $KeepSensorConfiguration = $true,
  
    [Parameter(Mandatory = $false)]
    [string]
    $BulkToken = '',
  
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
    if ($PSVersionTable.PSVersion -lt '3.0')
       { throw "This script requires a miniumum PowerShell 3.0" }
    if (!([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')) {
        if (([enum]::GetNames([Net.SecurityProtocolType]) -contains [Net.SecurityProtocolType]::Tls12)) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } else {
            throw "Unable to use Tls12. Please review .NET and PowerShell requirenments."
        }
    }
 
    # Proxy value from registry
    if ((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name CsProxyHostname -ErrorAction SilentlyContinue) -or (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name CsProxyHostname -ErrorAction SilentlyContinue)) {
        if ($KeepSensorConfiguration) {
            if (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name CsProxyHostname -ErrorAction SilentlyContinue) {
                $csproxyname = (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name CsProxyHostname -ErrorAction SilentlyContinue  | Select -ExpandProperty CsProxyHostname) -join ','
                $csproxyname = ($csproxyname.Split(",",[System.StringSplitOptions]::RemoveEmptyEntries) | ?{$_ -gt '0'} | ForEach{[char][int]"$($_)"}) -join ''
            } elseif (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name CsProxyHostname -ErrorAction SilentlyContinue) {
                $csproxyname = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default' -ErrorAction Stop).CsProxyHostname
            }
            if ($InstallArgs -match 'APP_PROXYNAME=(\w|\.)+($|\s)') {
                $InstallArgs = $InstallArgs -replace 'APP_PROXYNAME=(?<hostname>(\w|\.)+)',"APP_PROXYNAME=$csproxyname"
            } else {
                $InstallArgs += " APP_PROXYNAME=$csproxyname"
            }
        }
        if ($SensorProxyCheck -and !($InstallArgs -match 'APP_PROXYNAME=(\w|\.)+($|\s)')) {
             throw "Please review APP_PROXYNAME declaration from your `$InstallArgs."
        }
    }
    if ((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name CsProxyPort -ErrorAction SilentlyContinue) -or (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name CsProxyPort -ErrorAction SilentlyContinue)) {
        if ($KeepSensorConfiguration) {
            if (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name CsProxyPort -ErrorAction SilentlyContinue) {
                $csproxyport = [bitconverter]::ToInt16((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name CsProxyPort -ErrorAction SilentlyContinue | Select -ExpandProperty CsProxyPort),0)
            } elseif (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name CsProxyPort -ErrorAction SilentlyContinue) {
                $csproxyport = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default' -ErrorAction Stop).CsProxyPort
            }
            if ($InstallArgs -match 'APP_PROXYPORT=(\w|\.)+($|\s)') {
                $InstallArgs = $InstallArgs -replace 'APP_PROXYPORT=(?<port>\d+)',"APP_PROXYPORT=$csproxyport"
            } else {
                $InstallArgs += " APP_PROXYPORT=$csproxyport"
            }
        }
        if ($SensorProxyCheck -and !($InstallArgs -match 'APP_PROXYPORT=(?<port>\d+)($|\s)')) {
            throw "Please review APP_PROXYPORT declaration from your `$InstallArgs."
        }
    }
 
    if ($KeepSensorConfiguration) {
        # Check group tagging
        if (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name GroupingTags -ErrorAction SilentlyContinue) {
            $cstags = (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name GroupingTags -ErrorAction SilentlyContinue  | Select -ExpandProperty GroupingTags) -join ','
            $cstags = ($cstags.Split(",",[System.StringSplitOptions]::RemoveEmptyEntries) | ?{$_ -gt '0'} | ForEach{[char][int]"$($_)"}) -join ''
        } elseif (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name GroupingTags -ErrorAction SilentlyContinue) {
            $cstags = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default' -ErrorAction Stop).GroupingTags
        }
        if ($InstallArgs -match 'GROUPING_TAGS=\"(?<tag>(\S)+)\"($|\s)') {
            $InstallArgs = $InstallArgs -replace 'GROUPING_TAGS=\"(?<tag>(\S)+)\"',"GROUPING_TAGS=""$cstags"""
        } else {
                $InstallArgs += " GROUPING_TAGS=""$cstags"""
        }
    }
 
    if (-not $FromCloud) { $FromCloud = 'us-1' }
    switch ($FromCloud) {
        'eu-1' { $SrcHostname = 'https://api.eu-1.crowdstrike.com' }
        'us-1' { $SrcHostname = 'https://api.crowdstrike.com' }
        'us-2' { $SrcHostname = 'https://api.us-2.crowdstrike.com' }
        'us-gov-1' { $SrcHostname = 'https://api.laggar.gcw.crowdstrike.com' }
    }
  
    if (-not $ToCloud) { $ToCloud = 'us-1' }
    switch ($ToCloud) {
        'eu-1' { $DstHostname = 'https://api.eu-1.crowdstrike.com' }
        'us-1' { $DstHostname = 'https://api.crowdstrike.com' }
        'us-2' { $DstHostname = 'https://api.us-2.crowdstrike.com' }
        'us-gov-1' { $DstHostname = 'https://api.laggar.gcw.crowdstrike.com' }
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
        "Measure-Object",
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
    # CID value from registry
    $CurrentCID = ''
    if (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name CU -ErrorAction SilentlyContinue) {
        $CurrentCID = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\" +
                    "{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}" +
                    "\Default") -Name CU -ErrorAction SilentlyContinue).CU)).ToLower() -replace '-','')
    } elseif (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name AG -ErrorAction SilentlyContinue) {
        $CurrentCID = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services" +
                    "\CSAgent\Sim") -Name CU -ErrorAction SilentlyContinue).CU)).ToLower() -replace '-','')
    }
    # HostId value from registry
    $HostId = ''
    if (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name AG -ErrorAction SilentlyContinue) {
        $HostId = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\" +
                    "{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}" +
                    "\Default") -Name AG -ErrorAction SilentlyContinue).AG)).ToLower() -replace '-','')
    } elseif (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name AG -ErrorAction SilentlyContinue) {
        $HostId = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services" +
                    "\CSAgent\Sim") -Name AG -ErrorAction SilentlyContinue).AG)).ToLower() -replace '-','')
    }
}
  
process {
    # Validate if API credentials have been set.
    if ($Action -eq 'Migrate') {
        if ((-not $SourceId) -or (-not $SourceSecret) -or (-not $DestinationId) -or (-not $DestinationSecret)) {
            throw "API credentials not configured properly"
        }
    } else {
        if ((-not $SourceId) -or (-not $SourceSecret)) {
            throw "API credentials not configured properly"
        } else {
            $DestinationId = $SourceId
            $DestinationSecret = $SourceSecret
        }
    }
    $Retries=0
    do {
        switch ($FromCloud) {
            'eu-1' { $SrcHostname = 'https://api.eu-1.crowdstrike.com' }
            'us-1' { $SrcHostname = 'https://api.crowdstrike.com' }
            'us-2' { $SrcHostname = 'https://api.us-2.crowdstrike.com' }
            'us-gov-1' { $SrcHostname = 'https://api.laggar.gcw.crowdstrike.com' }
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
        $SrcToken = try {(Invoke-WebRequest @Param -UseBasicParsing -MaximumRedirection 0)
                    } catch {
                        if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                            Write-Output $_.ErrorDetails.Length
                            $_.ErrorDetails | ConvertFrom-Json
                        } elseif ($_.Exception.Response) {
                            if ($_.Exception.Response.StatusCode -eq 403) {
                                throw "Unable to request token from source cloud $($FromCloud) using client id $($SourceId) due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review source API credentials."
                            }
                        } else {
                            $_.Exception
                        }
                    }
 
        if ($SrcToken.StatusCode -ne 201) {
            if (!$SrcToken.Headers) {
                Write-Host "Unable to request token. Please check API credentials or connectivity. Current response is:`n$($SrcToken)"
                break
            } else {
                $FromCloud=$SrcToken.Headers.'X-Cs-Region'
            }
        }
        $Retries++
    } while ($SrcToken.StatusCode -ne 201 -and $Retries -le 4)
 
    $SrcToken = ($SrcToken | ConvertFrom-Json)
  
    if (-not $SrcToken.access_token) {
        throw "Unable to request token from source cloud $($FromCloud) using client id $($SourceId). Return was: $($SrcToken)"
    }
 
    $Retries=0
    do {
        switch ($ToCloud) {
            'eu-1' { $DstHostname = 'https://api.eu-1.crowdstrike.com' }
            'us-1' { $DstHostname = 'https://api.crowdstrike.com' }
            'us-2' { $DstHostname = 'https://api.us-2.crowdstrike.com' }
            'us-gov-1' { $DstHostname = 'https://api.laggar.gcw.crowdstrike.com' }
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
        $DstToken = try {(Invoke-WebRequest @Param -UseBasicParsing -MaximumRedirection 0)
                    } catch {
                        if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                            Write-Output $_.ErrorDetails.Length
                            $_.ErrorDetails | ConvertFrom-Json
                        } elseif ($_.Exception.Response) {
                            if ($_.Exception.Response.StatusCode -eq 403) {
                                throw "Unable to request token from destination cloud $($ToCloud) using client id $($DestinationId) due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review destination API credentials."
                            }
                        } else {
                            $_.Exception
                        }
                    }
 
        if ($DstToken.StatusCode -ne 201) {
            if (!$DstToken.Headers) {
                Write-Host "Unable to request token. Please check API credentials or connectivity. Current response is:`n$($DstToken)"
                break
            } else {
                $ToCloud=$DstToken.Headers.'X-Cs-Region'
            }
        }
        $Retries++
    } while ($DstToken.StatusCode -ne 201 -and $Retries -le 4)
 
    $DstToken = ($DstToken | ConvertFrom-Json)
      
    if (-not $DstToken.access_token) {
        throw "Unable to request token from destination cloud $($ToCloud) using client id $($DestinationId). Return was: $($DstToken)"
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
        $CID = try {((Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json).resources[0]
        } catch {
            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                Write-Output $_.ErrorDetails.Length
                $_.ErrorDetails | ConvertFrom-Json
            } elseif ($_.Exception.Response) {
                if ($_.Exception.Response.StatusCode -eq 403) {
                    throw "Unable to determine CID due to $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor Download scope for client id $($DestinationId) or set destination CID manually."
                }
            } else {
                $_.Exception
            }
        }
          
        if ((-not $CID) -Or ($CID -NotMatch  '[A-z0-9]{32}-[A-z0-9]{2}')) {
            throw "Unable to determine CID used in this process. Please use -CID or define `$CID default value in this script."
        }
    }
 
    if ($Action -eq 'Migrate' -and ($CID.SubString(0,32).ToLower() -eq $CurrentCID)) {
        throw "Current sensor CID is equal to destination CID. Consider changing the action. Nothing to do here."
    } elseif ($Action -eq 'Recover' -and !($CID.SubString(0,32).ToLower() -eq $CurrentCID) -and !($CurrentCID.Length -eq 0)) {
        throw "Unable to try to recover when using API keys from different CID. Make sure to use API keys from CID $($CurrentCID)"
    }
  
    $InstallArgs += " CID=$CID"
      
    if (-not $Hash -and !($Action -eq 'Uninstall')) {
        $Param = @{
            Uri = "$($DstHostname)/policy/combined/sensor-update/v2?filter=platform_name%3A%20%27Windows%27%2Bname%3A%20%27platform_default%27"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($DstToken.token_type) $($DstToken.access_token)"
            }
        }
 
        # Find sensor build from default policy
        $SensorVersion = try {
            (((Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json).resources[0].settings.sensor_version)
        }
 
        catch {
            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                Write-Output $_.ErrorDetails.Length
                $_.ErrorDetails | ConvertFrom-Json
            } elseif ($_.Exception.Response) {
                if ($_.Exception.Response.StatusCode -eq 403) {
                    throw "Unable to determine hash to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor update policies scope for client id $($DestinationId) with read permission or set sensor hash manually."
                }
            } else {
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
 
        $Installers = try {
            (Invoke-WebRequest @Param -UseBasicParsing | ConvertFrom-Json)
        } catch {
            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                Write-Output $_.ErrorDetails.Length
                $_.ErrorDetails | ConvertFrom-Json
            } elseif ($_.Exception.Response) {
                if ($_.Exception.Response.StatusCode -eq 403) {
                    throw "Unable to determine hash to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor Download scope for client id $($DestinationId) or set sensor hash manually."
                }
            } else {
                $_.Exception
            }
        }
 
        foreach ($findBuild in $Installers.resources) {
            if ($findBuild.version -eq $SensorVersion) {
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
  
    if ((Test-Path $InstallerPath) -eq $false -and !($Action -eq 'Uninstall')) {
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
            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                Write-Output $_.ErrorDetails.Length
                $_.ErrorDetails | ConvertFrom-Json
            } elseif ($_.Exception.Response) {
                if ($_.Exception.Response.StatusCode -eq 403) {
                    throw "Unable to download sensor file to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor Download scope for client id $($DestinationId) or upload sensor file manually at $($InstallerPath)."
                }
            } else {
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
 
    if (-not $InstallArgs -and !($Action -eq 'Uninstall')) {
        throw "No installation arguments configured in script"
    }
  
    if (-not $HostId -and (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name PW -ErrorAction SilentlyContinue)) {
        throw "Unable to retrieve host identifier"
    }
 
    if ($FixInstall) {
        Clean-FalconInstall -Action $FixInstallAction -Backup $FixInstallBackup -Force $FixInstallForce | Out-Null
    }
 
    $UninstallKey=@()
    foreach ($Key in (Get-ChildItem $UninstallKeys)) {
        if ($Key.GetValue("DisplayName") -like "*CrowdStrike Windows Sensor*") {
            $Output = "" | Select KeyPath,Version,Uninstall
            $Output.KeyPath = $Key.PSPath
            $Output.Version = $($Key.GetValue("DisplayVersion"))
            $Output.Uninstall = "/min /c set __COMPAT_LAYER=RUNASINVOKER && $($Key.GetValue("QuietUninstallString"))"
            $UninstallKey += $Output
        }
    }
  
    # Create uninstall string
    if ($UninstallKey.count -gt 1) {
        Write-Output "Multiple uninstall key found in registry. Please review this host. Script will continue."
    }
    $UninstallKey.ForEach{
        if($_.Version -eq (Get-Item 'C:\Program Files\CrowdStrike\CSFalconService.exe').VersionInfo.FileVersion){
            $Uninstall = $_.Uninstall
        }
    }
 
    if (-not $Uninstall) {
        throw "QuietUninstallString not found for CrowdStrike Windows Sensor"
    }
 
    if (-not $BulkToken -and ((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name PW -ErrorAction SilentlyContinue) -or (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name PW -ErrorAction SilentlyContinue))) {
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
        $Request = try {Invoke-WebRequest @Param -UseBasicParsing | ConvertFrom-Json
        } catch {
            if ($_.ErrorDetails) {
                $_.ErrorDetails | ConvertFrom-Json
            }
            else {
                $_.Exception
            }
        }
        if (-not $Request.resources) {
            throw "Unable to retrieve uninstall token from source cloud $($FromCloud) using client id $($SourceId). Return was: $($Request)"
        }
        $Uninstall += " MAINTENANCE_TOKEN=$($Request.resources.uninstall_token)"
    } elseif ($BulkToken) {
        $Uninstall += " MAINTENANCE_TOKEN=$($BulkToken)"
    }
 
    if ($Action -eq 'Migrate') {
        Start-Process -FilePath cmd.exe -ArgumentList $Uninstall -PassThru | ForEach-Object {
            Write-Output "[$($_.Id)] '$($_.ProcessName)' beginning removal; sensor will become unresponsive..."
            $WaitInstall = ("-WindowStyle Hidden -Command &{ Wait-Process -Id $($_.Id); do { Start-Sleep -Seconds 5 } until ((Get-Service" +
            " -Name CSFalconService -ErrorAction SilentlyContinue) -eq `$null -And @(Get-Process -ErrorAction" +
            " SilentlyContinue msiexec).count -le 1); set __COMPAT_LAYER=RUNASINVOKER ; Start-Process -FilePath" +
            " $InstallerPath -ArgumentList '$InstallArgs'}")
            Start-Process -FilePath powershell.exe -ArgumentList $WaitInstall
        }
    } elseif ($Action -eq 'Recover') {
        $InstallArgs += " MAINTENANCE_TOKEN=$($Request.resources.uninstall_token)"
        set __COMPAT_LAYER=RUNASINVOKER ; Start-Process -FilePath $InstallerPath -ArgumentList '$InstallArgs' -PassThru | ForEach-Object {
            Write-Output "[$($_.Id)] '$($_.ProcessName)' beginning recover; sensor will become unresponsive..."
            Write-Output "[$($_.Id)] Beginning recover using the following arguments: '$($InstallArgs)' ..."
        }
    } elseif ($Action -eq 'Uninstall') {
        Start-Process -FilePath cmd.exe -ArgumentList $Uninstall -PassThru | ForEach-Object {
            Write-Output "[$($_.Id)] '$($_.ProcessName)' beginning removal; sensor will become unresponsive..."
        }
    }
}
