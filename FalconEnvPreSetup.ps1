<#
    .SYNOPSIS

        This script is intend to pre-setup Falcon Platform on new POV. Current policy setup allows you to
        deploy sensor on environment in a detection only mode, without need to remove any solution.
	
    .NOTES
    	Version:            1.0
    	Authors:            Marcos Ferreira
    	Last Updater:       Marcos Ferreira
    	Creation Date:      2021-09-04
    	Update Date:        2021-10-03
    	Purpose/Change:     2021-10-03 - Public version
                            2021-09-25 - added policy order configuration.
                            2021-09-22 - added default policy configuration on sensor update and prevention.
                            2021-09-04 - Initial version.
    	Usage:	            Use at your own risk. Use this script to configure update and prevention policies.
        Host Requirements:  PowerShell v3 or higher. TLS 1.2 minimum. .Net 3.5 SP1 and Higher.

    .PARAMETER ClientId
        Falcon OAuth2 API Client Id.

    .PARAMETER ClientSecret
        Falcon OAuth2 API Client Secret.

    .PARAMETER FalconCloud
        Specifies your Falcon Cloud.
	    'EU' = https://api.eu-1.crowdstrike.com
        'US' = https://api.crowdstrike.com
        'US-2' = https://api.us-2.crowdstrike.com
        'USFed' = https://api.laggar.gcw.crowdstrike.com

    .PARAMETER DefaultPolicy
        When true default policies will be adjusted as well.
#>
<# -------------------      Begin Editable Region. -------------- #>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]
    $ClientId = '',

    [Parameter(Mandatory = $false)]
    [string]
    $ClientSecret = '',

    [ValidateSet('EU', 'US', 'US-2', 'USFed')]
    [string]
    $FalconCloud = 'US',

    [Parameter(Mandatory = $false)]
    [boolean]
    $DefaultPolicy = $true
)
<# ----------------      END Editable Region. ----------------- #>
begin {
    switch ($FalconCloud) {
        'EU' { $FalconURL = 'https://api.eu-1.crowdstrike.com' }
        'US' { $FalconURL = 'https://api.crowdstrike.com' }
        'US-2' { $FalconURL = 'https://api.us-2.crowdstrike.com' }
        'USFed' { $FalconURL = 'https://api.laggar.gcw.crowdstrike.com' }
    }

    $FalconGroups = @{'Non-Critical'='Group to be used as first wave of sensor upgrade after QA. Please does not include any critical machine on this group. This group should have something between 30-40% of the hosts.'
                      'QA'='For QA purposes, this group should reflect a good sample of the environment to receive the latest GA version of Falcon sensor and also allow the evaluation of new features from prevention policy. For sampling please use from 5-10% as a good margin and at least 1 sample of each operation system flavor/version. Considering 1 sample from each BU of the company can result in a better QA process.'
                      'Troubleshooting'='Troubleshooting group will be used for specific scenarios in order to facilitate field troubleshooting. Hosts added into this group should not be removed from other groups and stay only during the diagnose process, and must be removed after troubleshooting is done.'}

    $FalconUpdatePolicyPayload = @(
                                   @{'description' = 'Sensor update policy for troubleshooting usage.'
                                   'name' = 'Troubleshooting'
                                   'platform_name' = 'Windows'
                                   'settings' = @{'uninstall_protection' = 'DISABLED'}},
                                   @{'description' = 'Sensor update policy for troubleshooting usage.'
                                   'name' = 'Troubleshooting'
                                   'platform_name' = 'Mac'
                                   'settings' = @{'uninstall_protection' = 'DISABLED'}},
                                   @{'description' = 'Sensor update policy for troubleshooting usage.'
                                   'name' = 'Troubleshooting'
                                   'platform_name' = 'Linux'},
                                   @{'description' = 'First wave of sensor update. QA.'
                                   'name' = 'QA'
                                   'platform_name' = 'Windows'
                                   'settings' = @{'build' = ($FalconSensor.windows.resources | Where-Object {$_.build -match '.*auto' }).build}},
                                   @{'description' = 'First wave of sensor update. QA.'
                                   'name' = 'QA'
                                   'platform_name' = 'Mac'
                                   'settings' = @{'build' = ($FalconSensor.mac.resources | Where-Object {$_.build -match '.*auto' }).build}},
                                   @{'description' = 'First wave of sensor update. QA.'
                                   'name' = 'QA'
                                   'platform_name' = 'Linux'
                                   'settings' = @{'build' = ($FalconSensor.linux.resources | Where-Object {$_.build -match '.*auto' }).build}},
                                   @{'description' = 'Second wave of sensor update. N-1'
                                   'name' = 'Non-Critical'
                                   'platform_name' = 'Windows'
                                   'settings' = @{'build' = ($FalconSensor.windows.resources | Where-Object {$_.build -match '.*n-1.*' }).build}},
                                   @{'description' = 'Second wave of sensor update. N-1'
                                   'name' = 'Non-Critical'
                                   'platform_name' = 'Mac'
                                   'settings' = @{'build' = ($FalconSensor.mac.resources | Where-Object {$_.build -match '.*n-1.*' }).build}},
                                   @{'description' = 'Second wave of sensor update. N-1'
                                   'name' = 'Non-Critical'
                                   'platform_name' = 'Linux'
                                   'settings' = @{'build' = ($FalconSensor.linux.resources | Where-Object {$_.build -match '.*n-1.*' }).build}}
                                  )

    $FalconPreventionPolicyPayload = @(
                                   @{'description' = 'Sensor prevention policy for troubleshooting usage.'
                                   'name' = 'Troubleshooting'
                                   'platform_name' = 'Windows'},
                                   @{'description' = 'Sensor prevention policy for troubleshooting usage.'
                                   'name' = 'Troubleshooting'
                                   'platform_name' = 'Mac'},
                                   @{'description' = 'Sensor prevention policy for troubleshooting usage.'
                                   'name' = 'Troubleshooting'
                                   'platform_name' = 'Linux'},
                                   @{'description' = 'Sensor prevention policy for QA. When new features are deployed it is disable by default. Use this policy to evaluate new features on QA hosts before enabling it on large scale.'
                                   'name' = 'QA'
                                   'platform_name' = 'Windows'
                                   'settings' = @(@{id='EndUserNotifications';value=@{enabled = $true}},
                                                  @{id='UnknownDetectionRelatedExecutables';value=@{enabled=$true}},
                                                  @{id='UnknownExecutables';value=@{enabled=$true}},
                                                  @{id='SensorTamperingProtection';value=@{enabled=$true}},
                                                  @{id='AdditionalUserModeData'; value=@{enabled=$true}},
                                                  @{id='InterpreterProtection'; value=@{enabled=$true}},
                                                  @{id='EngineProtectionV2'; value=@{enabled=$true}},
                                                  @{id='ScriptBasedExecutionMonitoring'; value=@{enabled=$true}},
                                                  @{id='HTTPDetections'; value=@{enabled=$true}},
                                                  @{id='RedactHTTPDetectionDetails'; value=@{enabled=$false}},
                                                  @{id='HardwareEnhancedExploitDetection'; value=@{enabled=$true}},
                                                  @{id='FirmwareAnalysisExtraction'; value=@{enabled=$true}},
                                                  @{id='CloudAntiMalware'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='AdwarePUP'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='OnSensorMLSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='DetectOnWrite'; value=@{enabled=$true}},
                                                  @{id='QuarantineOnWrite'; value=@{enabled=$true}},
                                                  @{id='NextGenAV'; value=@{enabled=$true}},
                                                  @{id='CustomBlacklisting'; value=@{enabled=$true}},
                                                  @{id='PreventSuspiciousProcesses'; value=@{enabled=$true}},
                                                  @{id='SuspiciousRegistryOperations'; value=@{enabled=$true}},
                                                  @{id='MaliciousPowershell'; value=@{enabled=$true}},
                                                  @{id='IntelPrevention'; value=@{enabled=$true}},
                                                  @{id='SuspiciousKernelDrivers'; value=@{enabled=$true}},
                                                  @{id='ForceASLR'; value=@{enabled=$true}},
                                                  @{id='ForceDEP'; value=@{enabled=$true}},
                                                  @{id='HeapSprayPreallocation'; value=@{enabled=$true}},
                                                  @{id='NullPageAllocation'; value=@{enabled=$true}},
                                                  @{id='SEHOverwriteProtection'; value=@{enabled=$true}},
                                                  @{id='BackupDeletion'; value=@{enabled=$true}},
                                                  @{id='Cryptowall'; value=@{enabled=$true}},
                                                  @{id='FileEncryption'; value=@{enabled=$true}},
                                                  @{id='Locky'; value=@{enabled=$true}},
                                                  @{id='FileSystemAccess'; value=@{enabled=$true}},
                                                  @{id='VolumeShadowCopyAudit'; value=@{enabled=$true}},
                                                  @{id='VolumeShadowCopyProtect'; value=@{enabled=$true}},
                                                  @{id='ApplicationExploitationActivity'; value=@{enabled=$true}},
                                                  @{id='ChopperWebshell'; value=@{enabled=$true}},
                                                  @{id='DriveByDownload'; value=@{enabled=$true}},
                                                  @{id='ProcessHollowing'; value=@{enabled=$true}},
                                                  @{id='JavaScriptViaRundll32'; value=@{enabled=$true}},
                                                  @{id='WindowsLogonBypassStickyKeys'; value=@{enabled=$true}},
                                                  @{id='CredentialDumping'; value=@{enabled=$true}},
                                                  @{id='AutomatedRemediation'; value=@{enabled=$true}}
                                                 )},
                                   @{'description' = 'Sensor prevention policy for QA. When new features are deployed it is disable by default. Use this policy to evaluate new features on QA hosts before enabling it on large scale.'
                                   'name' = 'QA'
                                   'platform_name' = 'Mac'
                                   'settings' = @(@{id='EndUserNotifications';value=@{enabled = $true}},
                                                  @{id='UnknownDetectionRelatedExecutables';value=@{enabled=$true}},
                                                  @{id='UnknownExecutables';value=@{enabled=$true}},
                                                  @{id='ScriptBasedExecutionMonitoring'; value=@{enabled=$true}},
                                                  @{id='FirmwareStandardVisibility'; value=@{enabled=$true}},
                                                  @{id='FirmwareDeepVisibility'; value=@{enabled=$true}},
                                                  @{id='CloudAntiMalware'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='AdwarePUP'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='OnSensorMLSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='OnSensorMLAdwarePUPSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='NextGenAV'; value=@{enabled=$true}},
                                                  @{id='CustomBlacklisting'; value=@{enabled=$true}},
                                                  @{id='PreventSuspiciousProcesses'; value=@{enabled=$true}},
                                                  @{id='IntelPrevention'; value=@{enabled=$true}},
                                                  @{id='XPCOMShell'; value=@{enabled=$true}},
                                                  @{id='ChopperWebshell'; value=@{enabled=$true}},
                                                  @{id='EmpyreBackdoor'; value=@{enabled=$true}},
                                                  @{id='KcPasswordDecoded'; value=@{enabled=$true}},
                                                  @{id='HashCollector'; value=@{enabled=$true}}
                                                 )},
                                   @{'description' = 'Sensor prevention policy for QA. When new features are deployed it is disable by default. Use this policy to evaluate new features on QA hosts before enabling it on large scale.'
                                   'name' = 'QA'
                                   'platform_name' = 'Linux'
                                   'settings' = @(@{id='CloudAntiMalware'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='OnSensorMLSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='EXTRA_AGGRESSIVE'}},
                                                  @{id='CustomBlacklisting'; value=@{enabled=$true}},
                                                  @{id='PreventSuspiciousProcesses'; value=@{enabled=$true}}
                                                 )}
                                   )

    $FalconPreventionDefaultPayload = @{'Windows' = @(@{id='EndUserNotifications';value=@{enabled = $false}},
                                                      @{id='UnknownDetectionRelatedExecutables';value=@{enabled=$true}},
                                                      @{id='UnknownExecutables';value=@{enabled=$true}},
                                                      @{id='SensorTamperingProtection';value=@{enabled=$true}},
                                                      @{id='AdditionalUserModeData'; value=@{enabled=$true}},
                                                      @{id='InterpreterProtection'; value=@{enabled=$true}},
                                                      @{id='EngineProtectionV2'; value=@{enabled=$true}},
                                                      @{id='ScriptBasedExecutionMonitoring'; value=@{enabled=$true}},
                                                      @{id='HTTPDetections'; value=@{enabled=$true}},
                                                      @{id='RedactHTTPDetectionDetails'; value=@{enabled=$false}},
                                                      @{id='HardwareEnhancedExploitDetection'; value=@{enabled=$true}},
                                                      @{id='FirmwareAnalysisExtraction'; value=@{enabled=$true}},
                                                      @{id='CloudAntiMalware'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='AdwarePUP'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='OnSensorMLSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='DetectOnWrite'; value=@{enabled=$false}},
                                                      @{id='QuarantineOnWrite'; value=@{enabled=$false}},
                                                      @{id='NextGenAV'; value=@{enabled=$false}},
                                                      @{id='CustomBlacklisting'; value=@{enabled=$true}},
                                                      @{id='PreventSuspiciousProcesses'; value=@{enabled=$false}},
                                                      @{id='SuspiciousRegistryOperations'; value=@{enabled=$false}},
                                                      @{id='MaliciousPowershell'; value=@{enabled=$false}},
                                                      @{id='IntelPrevention'; value=@{enabled=$false}},
                                                      @{id='SuspiciousKernelDrivers'; value=@{enabled=$false}},
                                                      @{id='ForceASLR'; value=@{enabled=$false}},
                                                      @{id='ForceDEP'; value=@{enabled=$false}},
                                                      @{id='HeapSprayPreallocation'; value=@{enabled=$false}},
                                                      @{id='NullPageAllocation'; value=@{enabled=$false}},
                                                      @{id='SEHOverwriteProtection'; value=@{enabled=$false}},
                                                      @{id='BackupDeletion'; value=@{enabled=$false}},
                                                      @{id='Cryptowall'; value=@{enabled=$false}},
                                                      @{id='FileEncryption'; value=@{enabled=$false}},
                                                      @{id='Locky'; value=@{enabled=$false}},
                                                      @{id='FileSystemAccess'; value=@{enabled=$false}},
                                                      @{id='VolumeShadowCopyAudit'; value=@{enabled=$false}},
                                                      @{id='VolumeShadowCopyProtect'; value=@{enabled=$false}},
                                                      @{id='ApplicationExploitationActivity'; value=@{enabled=$false}},
                                                      @{id='ChopperWebshell'; value=@{enabled=$false}},
                                                      @{id='DriveByDownload'; value=@{enabled=$false}},
                                                      @{id='ProcessHollowing'; value=@{enabled=$false}},
                                                      @{id='JavaScriptViaRundll32'; value=@{enabled=$false}},
                                                      @{id='WindowsLogonBypassStickyKeys'; value=@{enabled=$false}},
                                                      @{id='CredentialDumping'; value=@{enabled=$false}},
                                                      @{id='AutomatedRemediation'; value=@{enabled=$false}}
                                                     )
                                        'Mac' =     @(@{id='EndUserNotifications';value=@{enabled = $false}},
                                                      @{id='UnknownDetectionRelatedExecutables';value=@{enabled=$true}},
                                                      @{id='UnknownExecutables';value=@{enabled=$true}},
                                                      @{id='ScriptBasedExecutionMonitoring'; value=@{enabled=$true}},
                                                      @{id='FirmwareStandardVisibility'; value=@{enabled=$true}},
                                                      @{id='FirmwareDeepVisibility'; value=@{enabled=$true}},
                                                      @{id='CloudAntiMalware'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='AdwarePUP'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='OnSensorMLSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='OnSensorMLAdwarePUPSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='NextGenAV'; value=@{enabled=$false}},
                                                      @{id='CustomBlacklisting'; value=@{enabled=$true}},
                                                      @{id='PreventSuspiciousProcesses'; value=@{enabled=$false}},
                                                      @{id='IntelPrevention'; value=@{enabled=$false}},
                                                      @{id='XPCOMShell'; value=@{enabled=$false}},
                                                      @{id='ChopperWebshell'; value=@{enabled=$false}},
                                                      @{id='EmpyreBackdoor'; value=@{enabled=$false}},
                                                      @{id='KcPasswordDecoded'; value=@{enabled=$false}},
                                                      @{id='HashCollector'; value=@{enabled=$false}}
                                                     )
                                        'Linux' =   @(@{id='CloudAntiMalware'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='OnSensorMLSlider'; value=@{detection='EXTRA_AGGRESSIVE'; prevention='DISABLED'}},
                                                      @{id='CustomBlacklisting'; value=@{enabled=$true}},
                                                      @{id='PreventSuspiciousProcesses'; value=@{enabled=$false}}
                                                     )
                                        }
}
process {
    # Validate if API credentials have been set.
    if ((-not $ClientId) -or (-not $ClientSecret)) {
        throw "API credentials not configured properly"
    }

    # Get API Token
    Write-Host "`nConnecting to Falcon... " -noNewLine
    $Param = @{
        Uri = "$($FalconURL)/oauth2/token"
        Method = 'post'
        Headers = @{
            accept = 'application/json'
            'content-type' = 'application/x-www-form-urlencoded'
        }
        Body = @{
            'client_id' = $ClientId
            'client_secret' = $ClientSecret
        }
    }

    $FalconAPIToken = try {
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

    if ($FalconAPIToken.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        $FalconAPIToken | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconAPIToken.errors.code
    }

    if ($FalconAPIToken.StatusCode -ne 201) {
        if ($FalconAPIToken.StatusCode -eq $null) {
            Write-Host "$($FalconAPIToken.Status): $($FalconAPIToken.Message)" -ForegroundColor Red
            throw "$($FalconAPIToken.Status): $($FalconAPIToken.Message)"
        } else {
            Write-Host "$($FalconAPIToken.StatusCode): $($FalconAPIToken.errors.message)" -ForegroundColor Red
            throw "$($FalconAPIToken.errors.code): $($FalconAPIToken.errors.message)"
        }
    } else {
        Write-Host "$($FalconAPIToken.StatusCode): connected" -ForegroundColor Green
        $FalconAPIToken = $FalconAPIToken.Content | ConvertFrom-Json
    }

    $FalconGroupCreation = @{}
    foreach($type in 'dynamic', 'static') {
        foreach($FalconGroup in $FalconGroups.GetEnumerator()) {
            if(-not ($type -eq 'dynamic' -and $FalconGroup.Name -eq 'Troubleshooting')) {
                # Groups creation
                $FalconGroupName = $FalconGroup.Name
                if($type -eq 'dynamic') {
                    $FalconGroupName = "$($FalconGroup.Name) - $($type)"
                }
                Write-Host "`nCreating host groups Falcon... " -noNewLine
                $Param = @{
                    Uri = "$($FalconURL)/devices/entities/host-groups/v1"
                    Method = 'post'
                    Headers = @{
                        accept = 'application/json'
                        'content-type' = 'application/json'
                        authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
                    }
                    Body = @{
                        'resources' = @(@{
                            'description' = $falconGroup.Value
                            'group_type' = $type
                            'name' = $FalconGroupName
                        })
                    } | ConvertTo-Json
                }

                $FalconGroupCreate = try {
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

                if ($FalconGroupCreate.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
                    $FalconGroupCreate | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconGroupCreate.errors.code
                }

                if ($FalconGroupCreate.StatusCode -ne 201) {
                    Write-Host "$($FalconGroupCreate.StatusCode): $($FalconGroupCreate.errors.message)" -ForegroundColor Red
                    if ($FalconGroupCreate.StatusCode -ne 409) {
                        throw "$($FalconGroupCreate.errors.code): $($FalconGroupCreate.errors.message)"
                    }
                } else {
                    $FalconGroupCreation.Add(($FalconGroupCreate.Content | ConvertFrom-Json).resources.name,($FalconGroupCreate.Content | ConvertFrom-Json).resources.id)
                    Write-Host "$($FalconGroupCreate.StatusCode): group $($FalconGroupName) created " -ForegroundColor Green
                }

            }
        }
    }

    # Get a list of available sensor versions
    $FalconSensor = @{}
    foreach($platform in 'windows', 'mac', 'linux') {
        Write-Host "`nListing available sensor versions for $platform ... " -noNewLine
        $Param = @{
            Uri = "$($FalconURL)/policy/combined/sensor-update-builds/v1?platform=$($platform)"
            Method = 'get'
            Headers = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
            }
        }

        $FalconSensorVersions = try {
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
        if ($FalconSensorVersions.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
            $FalconSensorVersions | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconSensorVersions.errors.code
        }

        if ($FalconSensorVersions.StatusCode -ne 200) {
            Write-Host "$($FalconSensorVersions.StatusCode): $($FalconSensorVersions.errors.message)" -ForegroundColor Red
            throw "$($FalconSensorVersions.errors.code): $($FalconSensorVersions.errors.message)"
        } else {
            $FalconSensor.Add($platform,($FalconSensorVersions.Content | ConvertFrom-Json))
            Write-Host "$($FalconSensorVersions.StatusCode): got $($platform) sensor versions " -ForegroundColor Green
        }
    }

    # Create a sensor update policy
    Write-Host "`nCreating sensor update policies... " -noNewLine
    $Param = @{
        Uri = "$($FalconURL)/policy/entities/sensor-update/v2"
        Method = 'post'
        Headers = @{
            accept = 'application/json'
            'content-type' = 'application/json'
            authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
        }
        Body = @{
            'resources' = $FalconUpdatePolicyPayload
        } | ConvertTo-Json -Depth 10
    }

    $FalconPolicyCreate = try {
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
    if ($FalconPolicyCreate.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        $FalconPolicyCreate | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyCreate.errors.code
    }

    if ($FalconPolicyCreate.StatusCode -ne 201) {
        Write-Host "$($FalconPolicyCreate.StatusCode): $($FalconPolicyCreate.errors.message)" -ForegroundColor Red
        if ($FalconPolicyCreate.StatusCode -ne 409) {
            throw "$($FalconPolicyCreate.errors.code): $($FalconPolicyCreate.errors.message)"
        }
    } else {
        Write-Host "$($FalconPolicyCreate.StatusCode): sensor update policies created." -ForegroundColor Green
    }
    
    # Assign host groups to the policy and enable
    ($FalconPolicyCreate.Content | ConvertFrom-Json).resources | ForEach-Object {
        $current = $_
        foreach($FalconGroup in $FalconGroups.GetEnumerator()) {
            Remove-Variable jsonBase -ErrorAction SilentlyContinue
            if ($current.name -eq $FalconGroup.Key) {
                $jsonBase = @{}
                $action_parameters = New-Object System.Collections.ArrayList

                foreach ($key in $FalconGroupCreation.Keys) {
                    if($key -match $FalconGroup.key) {
                        $action_parameters.Add(@{'name'='group_id';'value'=$FalconGroupCreation[$key];}) | Out-Null
                    }
                }
                $jsonBase.Add('action_parameters',$action_parameters)
                $jsonBase.Add('ids',@($current.id))
            }
            if ($jsonBase -ne $null) {
                Write-Host "`nAssigning host groups to policy... " -noNewLine
                $Param = @{
                    Uri = "$($FalconURL)/policy/entities/sensor-update-actions/v1?action_name=add-host-group"
                    Method = 'post'
                    Headers = @{
                        accept = 'application/json'
                        'content-type' = 'application/json'
                        authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
                    }
                    Body = $jsonBase | ConvertTo-Json -Depth 10

                }

                $FalconPolicyAssign = try {
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
                if ($FalconPolicyAssign.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
                    $FalconPolicyAssign | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyAssign.errors.code
                }

                if ($FalconPolicyAssign.StatusCode -ne 200) {
                    Write-Host "$($FalconPolicyAssign.StatusCode): $($FalconPolicyAssign.errors.message)" -ForegroundColor Red
                } else {
                    Write-Host "$($FalconPolicyAssign.StatusCode): host group assigned to the policy $($current.name) on $($current.platform_name)." -ForegroundColor Green
                }
            }
        }
        Write-Host "`nEnabling sensor update policy... " -noNewLine
        $Param = @{
            Uri = "$($FalconURL)/policy/entities/sensor-update-actions/v1?action_name=enable"
            Method = 'post'
            Headers = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
            }
            Body = @{'ids' = @($current.id)
            } | ConvertTo-Json

        }

        $FalconPolicyEnable = try {
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
        if ($FalconPolicyEnable.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
            $FalconPolicyEnable | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyEnable.errors.code
        }

        if ($FalconPolicyEnable.StatusCode -ne 200) {
            Write-Host "$($FalconPolicyEnable.StatusCode): $($FalconPolicyEnable.errors.message)" -ForegroundColor Red
        } else {
            Write-Host "$($FalconPolicyEnable.StatusCode):enabling policy $($current.name) on $($current.platform_name)." -ForegroundColor Green
        }

    }


    # Set sensor update policy precedence
    foreach($platform in 'Windows', 'Mac', 'Linux') {
        Write-Host "`nAdjusting sensor update policy precedences... " -noNewLine
        $Param = @{
            Uri = "$($FalconURL)/policy/combined/sensor-update/v2?filter=platform_name:""$($platform)""%2Bname:!""platform_default"""
            Method = 'get'
            Headers = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
            }
        }

        $FalconPolicyList = try {
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

        $FalconPolicyList = ($FalconPolicyList.Content | ConvertFrom-Json).resources.id
        $FalconUpdateIds = @()
        ($FalconPolicyCreate.Content | ConvertFrom-Json).resources | ForEach-Object {
            if($_.platform_name -eq $platform) {
                $FalconUpdateIds += $_.id
            }
        }
        $FalconPolicyList | ForEach-Object {
            if($_ -notin $FalconUpdateIds){
                $FalconUpdateIds += $_
            }
        }

        $Param = @{
            Uri = "$($FalconURL)/policy/entities/sensor-update-precedence/v1"
            Method = 'post'
            Headers = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
            }
            Body = @{'ids' = $FalconUpdateIds
                     'platform_name' = $platform
            } | ConvertTo-Json
        }

        $FalconPolicyOrder = try {
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
        if ($FalconPolicyOrder.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
            $FalconPolicyOrder | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyOrder.errors.code
        }

        if ($FalconPolicyOrder.StatusCode -ne 200) {
            Write-Host "$($FalconPolicyOrder.StatusCode): $($FalconPolicyOrder.errors.message)" -ForegroundColor Red
        } else {
            Write-Host "$($FalconPolicyOrder.StatusCode): adjusted $($platform) sensor update policy order." -ForegroundColor Green
        }

    }

    # Adjust default sensor update policy
    if ($DefaultPolicy) {
        foreach($platform in 'Windows', 'Mac', 'Linux') {
            Write-Host "`nAdjusting default sensor update policy... " -noNewLine
            $Param = @{
                Uri = "$($FalconURL)/policy/combined/sensor-update/v2?filter=platform_name:""$($platform)""%2Bname:""platform_default"""
                Method = 'get'
                Headers = @{
                    accept = 'application/json'
                    'content-type' = 'application/json'
                    authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
                }
            }

            $FalconPolicyDefault = try {
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

            $FalconPolicyDefault = ($FalconPolicyDefault.Content | ConvertFrom-Json).resources.id


            $Param = @{
                Uri = "$($FalconURL)/policy/entities/sensor-update/v2"
                Method = 'patch'
                Headers = @{
                    accept = 'application/json'
                    'content-type' = 'application/json'
                    authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
                }
                Body = @{
                    'resources' = @(
                                    @{'id' = $FalconPolicyDefault
							          'settings' = @{'build' = ($FalconSensor.$platform.resources | Where-Object {$_.build -match '.*n-2.*' }).build}}
                    )
                } | ConvertTo-Json -Depth 10
            }

            $FalconPolicyUpdate = try {
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
            if ($FalconPolicyUpdate.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
                $FalconPolicyUpdate | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyUpdate.errors.code
            }

            if ($FalconPolicyUpdate.StatusCode -ne 200) {
                Write-Host "$($FalconPolicyUpdate.StatusCode): $($FalconPolicyUpdate.errors.message)" -ForegroundColor Red
                if ($FalconPolicyUpdate.StatusCode -ne 409) {
                    throw "$($FalconPolicyUpdate.errors.code): $($FalconPolicyUpdate.errors.message)"
                }
            } else {
                Write-Host "$($FalconPolicyUpdate.StatusCode): sensor update policies changed." -ForegroundColor Green
            }
        }
    }

    # Create a sensor preveention policy
    Write-Host "`nCreating sensor prevetion policies... " -noNewLine
    $Param = @{
        Uri = "$($FalconURL)/policy/entities/prevention/v1"
        Method = 'post'
        Headers = @{
            accept = 'application/json'
            'content-type' = 'application/json'
            authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
        }
        Body = @{
            'resources' = $FalconPreventionPolicyPayload
        } | ConvertTo-Json -Depth 10
    }

    $FalconPolicyCreate = try {
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
    if ($FalconPolicyCreate.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        $FalconPolicyCreate | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyCreate.errors.code
    }

    if ($FalconPolicyCreate.StatusCode -ne 201) {
        Write-Host "$($FalconPolicyCreate.StatusCode): $($FalconPolicyCreate.errors.message)" -ForegroundColor Red
        if ($FalconPolicyCreate.StatusCode -ne 409) {
            throw "$($FalconPolicyCreate.errors.code): $($FalconPolicyCreate.errors.message)"
        }
    } else {
        Write-Host "$($FalconPolicyCreate.StatusCode): sensor prevention policies created." -ForegroundColor Green
    }

    # Assign host groups to the policy and enable
    ($FalconPolicyCreate.Content | ConvertFrom-Json).resources | ForEach-Object {
        $current = $_
        foreach($FalconGroup in $FalconGroups.GetEnumerator()) {
            Remove-Variable jsonBase -ErrorAction SilentlyContinue
            if ($current.name -eq $FalconGroup.Key) {
                $jsonBase = @{}
                $action_parameters = New-Object System.Collections.ArrayList

                foreach ($key in $FalconGroupCreation.Keys) {
                    if($key -match $FalconGroup.key) {
                        $action_parameters.Add(@{'name'='group_id';'value'=$FalconGroupCreation[$key];}) | Out-Null
                    }
                }
                $jsonBase.Add('action_parameters',$action_parameters)
                $jsonBase.Add('ids',@($current.id))
            }
            if ($jsonBase -ne $null) {
                Write-Host "`nAssigning host groups to policy... " -noNewLine
                $Param = @{
                    Uri = "$($FalconURL)/policy/entities/prevention-actions/v1?action_name=add-host-group"
                    Method = 'post'
                    Headers = @{
                        accept = 'application/json'
                        'content-type' = 'application/json'
                        authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
                    }
                    Body = $jsonBase | ConvertTo-Json -Depth 10

                }

                $FalconPolicyAssign = try {
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
                if ($FalconPolicyAssign.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
                    $FalconPolicyAssign | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyAssign.errors.code
                }

                if ($FalconPolicyAssign.StatusCode -ne 200) {
                    Write-Host "$($FalconPolicyAssign.StatusCode): $($FalconPolicyAssign.errors.message)" -ForegroundColor Red
                } else {
                    Write-Host "$($FalconPolicyAssign.StatusCode): host group assigned to the policy $($current.name) on $($current.platform_name)." -ForegroundColor Green
                }
            }
        }
        Write-Host "`nEnabling sensor prevention policy... " -noNewLine
        $Param = @{
            Uri = "$($FalconURL)/policy/entities/prevention-actions/v1?action_name=enable"
            Method = 'post'
            Headers = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
            }
            Body = @{'ids' = @($current.id)
            } | ConvertTo-Json

        }

        $FalconPolicyEnable = try {
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
        if ($FalconPolicyEnable.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
            $FalconPolicyEnable | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyEnable.errors.code
        }

        if ($FalconPolicyEnable.StatusCode -ne 200) {
            Write-Host "$($FalconPolicyEnable.StatusCode): $($FalconPolicyEnable.errors.message)" -ForegroundColor Red
        } else {
            Write-Host "$($FalconPolicyEnable.StatusCode):enabling policy $($current.name) on $($current.platform_name)." -ForegroundColor Green
        }

    }

    # Set sensor prevention policy precedence
    foreach($platform in 'Windows', 'Mac', 'Linux') {
        Write-Host "`nAdjusting sensor prevention policy precedences... " -noNewLine
        $Param = @{
            Uri = "$($FalconURL)/policy/combined/prevention/v1?filter=platform_name:""$($platform)""%2Bname:!""platform_default"""
            Method = 'get'
            Headers = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
            }
        }

        $FalconPolicyList = try {
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

        $FalconPolicyList = ($FalconPolicyList.Content | ConvertFrom-Json).resources.id
        $FalconPreventionIds = @()
        ($FalconPolicyCreate.Content | ConvertFrom-Json).resources | ForEach-Object {
            if($_.platform_name -eq $platform) {
                $FalconPreventionIds += $_.id
            }
        }
        $FalconPolicyList | ForEach-Object {
            if($_ -notin $FalconPreventionIds){
                $FalconPreventionIds += $_
            }
        }

        $Param = @{
            Uri = "$($FalconURL)/policy/entities/prevention-precedence/v1"
            Method = 'post'
            Headers = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
            }
            Body = @{'ids' = $FalconPreventionIds
                     'platform_name' = $platform
            } | ConvertTo-Json
        }

        $FalconPolicyOrder = try {
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
        if ($FalconPolicyOrder.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
            $FalconPolicyOrder | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyOrder.errors.code
        }

        if ($FalconPolicyOrder.StatusCode -ne 200) {
            Write-Host "$($FalconPolicyOrder.StatusCode): $($FalconPolicyOrder.errors.message)" -ForegroundColor Red
        } else {
            Write-Host "$($FalconPolicyOrder.StatusCode): adjusted $($platform) sensor prevention policy order." -ForegroundColor Green
        }

    }
    
    # Adjust default sensor prevention policy
    if ($DefaultPolicy) {
        foreach($platform in 'Windows', 'Mac', 'Linux') {
            Write-Host "`nAdjusting default sensor prevention policy... " -noNewLine
            $Param = @{
                Uri = "$($FalconURL)/policy/combined/prevention/v1?filter=platform_name:""$($platform)""%2Bname:""platform_default"""
                Method = 'get'
                Headers = @{
                    accept = 'application/json'
                    'content-type' = 'application/json'
                    authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
                }
            }

            $FalconPolicyDefault = try {
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
            
            $FalconPolicyDefault = ($FalconPolicyDefault.Content | ConvertFrom-Json).resources.id


            $Param = @{
                Uri = "$($FalconURL)/policy/entities/prevention/v1"
                Method = 'patch'
                Headers = @{
                    accept = 'application/json'
                    'content-type' = 'application/json'
                    authorization = "$($FalconAPIToken.token_type) $($FalconAPIToken.access_token)"
                }
                Body = @{
                    'resources' = @(
                                    @{'id' = $FalconPolicyDefault
							          'settings' = $FalconPreventionDefaultPayload[$platform]}
                    )
                } | ConvertTo-Json -Depth 10
            }

            $FalconPolicyUpdate = try {
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
            if ($FalconPolicyUpdate.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
                $FalconPolicyUpdate | Add-Member -MemberType NoteProperty -Name 'StatusCode' -Value $FalconPolicyUpdate.errors.code
            }

            if ($FalconPolicyUpdate.StatusCode -ne 200) {
                Write-Host "$($FalconPolicyUpdate.StatusCode): $($FalconPolicyUpdate.errors.message)" -ForegroundColor Red
                if ($FalconPolicyUpdate.StatusCode -ne 409) {
                    throw "$($FalconPolicyUpdate.errors.code): $($FalconPolicyUpdate.errors.message)"
                }
            } else {
                Write-Host "$($FalconPolicyUpdate.StatusCode): $($platform) sensor default prevention policies changed." -ForegroundColor Green
            }
        }
    }
}