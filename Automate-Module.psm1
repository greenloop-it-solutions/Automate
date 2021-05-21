<#
.SYNOPSIS
    These PowerShell Functions will Install, Uninstall, and Confirm ConnectWise Automate installations.

.DESCRIPTION
    Functions Included:
        Confirm-Automate
        Uninstall-Automate
        Install-Automate

.LINK
    https://github.com/Braingears/PowerShell

.NOTES
    File Name      : Automate-Module.psm1
    Author         : Chuck Fowler (Chuck@Braingears.com)
    Version        : 1.0
    Creation Date  : 11/10/2019
    Purpose/Change : Initial script development
    Prerequisite   : PowerShell V2

    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check both to be considered for $Automate.Installed
                    It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.


.EXAMPLE
    Confirm-Automate [-Silent]

    Confirm-Automate [-Show]

.EXAMPLE
    Uninstall-Automate [-Silent]

.EXAMPLE
    Install-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 [-Show]

#>
Function Confirm-Automate {
<#
.SYNOPSIS
    This PowerShell Function will confirm if Automate is installed, services running, and checking-in.

.DESCRIPTION
    This function will automatically start the Automate services (if stopped). It will collect Automate information from the registry.

.PARAMETER Raw
    This will show the Automate registry entries

.PARAMETER Show
    This will display $Automate object

.PARAMETER Silent
    This will hide all output

.LINK
    https://github.com/Braingears/PowerShell

.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Creation Date  : 08/16/2019
    Purpose/Change : Initial script development

    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check both to be consdered for $Automate.Installed
                    It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.

    Version        : 1.2
    Date           : 04/02/2020
    Changes        : Add $Automate.Service -eq $null
                    If the service still exists, the installation is failing with Exit Code 1638.

.EXAMPLE
    Confirm-Automate [-Silent]

    Confirm-Automate [-Show]

    ServerAddress : https://yourserver.hostedrmm.com
    ComputerID    : 321
    ClientID      : 1
    LocationID    : 2
    Version       : 190.221
    Service       : Running
    Online        : True
    LastHeartbeat : 29
    LastStatus    : 36

    $Automate
    $Global:Automate
    This output will be saved to $Automate as an object to be used in other functions.

#>
[CmdletBinding()]
    Param (
        [switch]$Raw    = $False,
        [switch]$Show   = $False,
        [switch]$Silent = $False
    )
    $ErrorActionPreference = 'SilentlyContinue'
    if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus) {
        $Online = if ((Test-Path "HKLM:\SOFTWARE\LabTech\Service") -and ((Get-Service ltservice).status) -eq "Running") {((((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus)).TotalSeconds) -lt 600)} else {Write-Output $False}
    } else {$Online = $False}

    if (Test-Path "HKLM:\SOFTWARE\LabTech\Service") {
        $Global:Automate = New-Object -TypeName psobject
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerName -Value $env:ComputerName
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ServerAddress -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").'Server Address')
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").ID)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ClientID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").ClientID)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name LocationID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LocationID)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Version -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").Version)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstFolder -Value (Test-Path "$($env:windir)\ltsvc")
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstRegistry -Value $True
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Installed -Value (Test-Path "$($env:windir)\ltsvc")
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Service -Value ((Get-Service LTService).Status)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Online -Value $Online
        if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").HeartbeatLastSent) {
            $Global:Automate | Add-Member -MemberType NoteProperty -Name LastHeartbeat -Value ([int]((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").HeartbeatLastSent)).TotalSeconds)
        }
        if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus) {
            $Global:Automate | Add-Member -MemberType NoteProperty -Name LastStatus -Value    ([int]((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus)).TotalSeconds)
        }
        Write-Verbose $Global:Automate
        if ($Show) {
            $Global:Automate
        } else {
            if (!$Silent) {
                Write-Output "Server Address checking-in to    $($Global:Automate.ServerAddress)"
                Write-Output "ComputerID:                      $($Global:Automate.ComputerID)"
                Write-Output "The Automate Agent Online        $($Global:Automate.Online)"
                Write-Output "Last Successful Heartbeat        $($Global:Automate.LastHeartbeat) seconds"
                Write-Output "Last Successful Status Update    $($Global:Automate.LastStatus) seconds"
            } # End Not Silent
        } # End if
        if ($Raw -eq $True) {Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service"}
    } else {
        $Global:Automate = New-Object -TypeName psobject
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerName -Value $env:ComputerName
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstFolder -Value (Test-Path "$($env:windir)\ltsvc")
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstRegistry -Value $False
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Installed -Value ((Test-Path "$($env:windir)\ltsvc") -and (Test-Path "HKLM:\SOFTWARE\LabTech\Service"))
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Service -Value ((Get-Service ltservice ).status)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Online -Value $Online
        Write-Verbose $Global:Automate
    } #End if Registry Exists
    if (!$Global:Automate.InstFolder -and !$Global:Automate.InstRegistry -and ($Null -eq $Global:Automate.Service)) {if ($Silent -eq $False) {Write-Output "Automate is NOT Installed"}}
} #End Function Confirm-Automate
########################
Set-Alias -Name LTC -Value Confirm-Automate -Description 'Confirm if Automate is running properly'
########################
Function Uninstall-Automate {
<#
.SYNOPSIS
    This PowerShell Function Uninstalls Automate.

.DESCRIPTION
    This function will download the Automate Uninstaller from Connectwise and completely remove the Automate / LabTech Agent.

.PARAMETER Silent
    This will hide all output

.LINK
    https://github.com/Braingears/PowerShell

.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Website        : braingears.com
    Creation Date  : 8/2019
    Purpose        : Create initial function script

    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check both to be considered for $Automate.Installed
                    It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.
                    If the LTSVC Folder or Registry keys are found after the uninstaller runs, the script now performs a manual gutting via PowerShell.

    Version        : 1.2
    Date           : 04/02/2020
    Changes        : Add $Automate.Service -eq $null
                    If the service still exists, the installation is failing with Exit Code 1638.

.EXAMPLE
    Uninstall-Automate [-Silent]


#>
[CmdletBinding(SupportsShouldProcess=$True)]
    Param (
    [switch]$Force,
    [switch]$Raw,
    [switch]$Show,
    [switch]$Silent = $False
    )
$ErrorActionPreference = 'SilentlyContinue'
$Verbose = if ($PSBoundParameters.Verbose -eq $True) { $True } else { $False }
$DownloadPath = "https://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe"
if ((([Int][System.Environment]::OSVersion.Version.Build) -gt 6000) -and ((get-host).Version.ToString() -ge 3)) {
    $DownloadPath = "https://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe"
} else {
    $DownloadPath = "http://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe"
}
$SoftwarePath = "C:\Support\Automate"
$UninstallApps = @(
    "ConnectWise Automate Remote Agent"
    "LabTech® Software Remote Agent"
    )
Write-Debug "Checking if Automate Installed"
Confirm-Automate -Silent -Verbose:$Verbose
    if (($Global:Automate.InstFolder) -or ($Global:Automate.InstRegistry) -or (!($Null -eq $Global:Automate.Service)) -or ($Force)) {
    $Filename = [System.IO.Path]::GetFileName($DownloadPath)
    $SoftwareFullPath = "$($SoftwarePath)\$Filename"
    if (!(Test-Path $SoftwarePath)) {New-Item -ItemType Directory -Path $SoftwarePath | Out-Null}
    Set-Location $SoftwarePath
    if ((Test-Path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
    if (!$Silent) {Write-Host "Removing Existing Automate Agent..."}
    Write-Verbose "Closing Open Applications and Stopping Services"
    Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force
    Stop-Service ltservice,ltsvcmon -Force
    $UninstallExitCode = (Start-Process "cmd" -ArgumentList "/c $($SoftwareFullPath)" -NoNewWindow -Wait -PassThru).ExitCode
    if (!$Silent) {
        if ($UninstallExitCode -eq 0) {
            # Write-Host "The Automate Agent Uninstaller Executed Without Errors" -ForegroundColor Green
            Write-Verbose "The Automate Agent Uninstaller Executed Without Errors"
        } else {
            Write-Host "Automate Uninstall Exit Code: $($UninstallExitCode)" -ForegroundColor Red
            Write-Verbose "Automate Uninstall Exit Code: $($UninstallExitCode)"
        }
    }
    Write-Verbose "Checking For Removal - Loop 5X"
    While ($Counter -ne 6) {
        $Counter++
        Start-Sleep 10
        Confirm-Automate -Silent -Verbose:$Verbose
        if ((!$Global:Automate.InstFolder) -and (!$Global:Automate.InstRegistry) -and ($Null -eq $Global:Automate.Service)) {
            Write-Verbose "Automate Uninstaller Completed Successfully"
            Break
        }
    }# end While
    if (($Global:Automate.InstFolder) -or ($Global:Automate.InstRegistry) -or (!($Null -eq $Global:Automate.Service))) {
        Write-Verbose "Uninstaller Failed"
        Write-Verbose "Manually Gutting Automate..."
        if (!(($Null -eq $Global:Automate.Service) -or ($Global:Automate.Service -eq "Stopped"))) {
            Write-Verbose "LTService Service not Stopped. Disabling LTService Service"
            Set-Service ltservice -StartupType Disabled
            Stop-Service ltservice,ltsvcmon -Force
        }
        Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force
        Write-Verbose "Uninstalling LabTechAD Package"
        $UninstallApps2 = foreach ($App in $UninstallApps) {Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -like $App} | Select-Object -ExpandProperty "Name"}
        $UninstallAppsFound = $UninstallApps2 | Select-Object -Unique
        foreach ($App in $UninstallAppsFound) {
            $AppLocalPackage = Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -like $App} | Select-Object -ExpandProperty "LocalPackage"
            if ($null -eq $AppLocalPackage) {
                Write-Verbose "$($App) - Not Installed"
            } else {
                Write-Verbose "Uninstalling: $($App) - msiexec /x $($AppLocalPackage) /qn /norestart"
                msiexec /x $AppLocalPackage /qn /norestart
            }
        }
        Remove-Item "$($env:windir)\ltsvc" -Recurse -Force
        Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service" | Remove-Item -Recurse -Force
        REG Delete HKLM\SOFTWARE\LabTech\Service /f | Out-Null
        Start-Process "cmd" -ArgumentList "/c $($SoftwareFullPath)" -NoNewWindow -Wait -PassThru | Out-Null
        Confirm-Automate -Silent -Verbose:$Verbose
        if ($Global:Automate.InstFolder) {
            if (!$Silent) {
                Write-Host "Automate Uninstall Failed" -ForegroundColor Red
                Write-Host "$($env:windir)\ltsvc folder still exists" -ForegroundColor Red
            } else {
                Write-Verbose "Automate Uninstall Failed"
                Write-Verbose "$($env:windir)\ltsvc folder still exists"
            }
        }
        if ($Global:Automate.InstRegistry) {
            if (!$Silent) {
                Write-Host "Automate Uninstall Failed" -ForegroundColor Red
                Write-Host "HKLM:\SOFTWARE\LabTech\Service Registry keys still exists" -ForegroundColor Red
            } else {
                Write-Verbose "Automate Uninstall Failed"
                Write-Verbose "HKLM:\SOFTWARE\LabTech\Service Registry keys still exists"
            }
        }
        if (!($Null -eq $Global:Automate.Service)) {
            if (!$Silent) {
                Write-Host "Automate Uninstall Failed" -ForegroundColor Red
                Write-Host "LTService Service still exists" -ForegroundColor Red
            } else {
                Write-Verbose "Automate Uninstall Failed"
                Write-Verbose "LTService Service still exists"
            }
        }
    } else {
        if (!$Silent) {Write-Host "The Automate Agent Uninstalled Successfully" -ForegroundColor Green}
        Write-Verbose "The Automate Agent Uninstalled Successfully"
    }
} # if Test Install
    Confirm-Automate -Silent:$Silent
} # End Function Uninstall-Automate
########################
Set-Alias -Name LTU -Value Uninstall-Automate -Description 'Uninstall Automate Agent'
########################
Function Install-Automate {
<#
.SYNOPSIS
    This PowerShell Function is for Automate Deployments

.DESCRIPTION
    Install the Automate Agent.

    This function will qualify if another Automate agent is already
    installed on the computer. If the existing agent belongs to a different
    Automate server, it will automatically "Rip & Replace" the existing
    agent. This comparison is based on the server's FQDN.

    This function will also verify if the existing Automate agent is
    checking-in. The Confirm-Automate Function will verify the Server
    address, LocationID, and Heartbeat/Check-in. If these entries are
    missing or not checking-in properly, this function will automatically
    attempt to restart the services and then "Rip & Replace" the agent to
    remediate the agent.

    $Automate
    $Global:Automate
    The output will be saved to $Automate as an object to be used in other functions.

    Example:
    Install-Automate -Server YOURSERVER.DOMAIN.COM -LocationID 2 -Transcript


    Tested OS:      Windows XP (with .Net 3.5.1 and PowerShell installed)
                    Windows Vista
                    Windows 7
                    Windows 8
                    Windows 10
                    Windows 2003R2
                    Windows 2008R2
                    Windows 2012R2
                    Windows 2016
                    Windows 2019

.PARAMETER Server
    This is the URL to your Automate server.

        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2

.PARAMETER LocationID
    Use LocationID to install the Automate Agent directly to the appropriate client's location / site.
    If parameter is not specified, it will automatically assign LocationID 1 (New Computers).

.PARAMETER Token
    Use Token to install the Automate Agent directly to the appropriate client's location / site.
    If parameter is not specified, it will automatically attempt to use direct unauthenticated downloads.
    This method is blocked after Automate v20.0.6.178 (Patch 6)

.PARAMETER Force
    This will force the Automate Uninstaller prior to installation.
    Essentually, this will be a fresh install and a fresh check-in to the Automate server.

        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Force

.PARAMETER Silent
    This will hide all output (except a failed installation when Exit Code -ne 0)
    The function will exit once the installer has completed.

        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Silent

.PARAMETER Transcript
    This parameter will save the entire transcript and response to:
    $($env:windir)\Temp\AutomateLogon.txt

        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Transcript -Verbose

.LINK
    https://github.com/Braingears/PowerShell

.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Creation Date  : 08/2019
    Purpose/Change : Initial script development

    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check both to be considered for $Automate.Installed
                    It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.
                    If the LTSVC Folder or Registry keys are found after the uninstaller runs, the script now performs a manual gutting via PowerShell.

    Version        : 1.2
    Date           : 02/17/2020
    Changes        : Add MSIEXEC Log Files to C:\Windows\Temp\Automate_Agent_(Date).log

    Version        : 1.3
    Date           : 05/26/2020
    Changes        : Look for and replace "Enter the server address here" with the actual Automate Server address.

    Version        : 1.4
    Date           : 06/29/2020
    Changes        : Added Token Parameter for Deployment

.EXAMPLE
    Install-Automate -Server 'automate.domain.com' -LocationID 42 -Token adb68881994ed93960346478303476f4
    This will install the LabTech agent using the provided Server URL, and LocationID.

#>
[CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=0)]
        [Alias("FQDN","Srv")]
        [string[]]$Server = $Null,
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=1)]
        [AllowNull()]
        [Alias('LID','Location')]
        [int]$LocationID = '1',
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=2)]
        [Alias("InstallerToken")]
        [string[]]$Token = $Null,
        [switch]$Force,
        [Parameter()]
        [AllowNull()]
        [switch]$Show = $False,
        [switch]$Silent,
        [Parameter()]
        [AllowNull()]
        [switch]$Transcript = $False
    )
    $ErrorActionPreference = 'SilentlyContinue'
    $Verbose = if ($PSBoundParameters.Verbose -eq $True) { $True } else { $False }
    $Error.Clear()
    if ($Transcript) {Start-Transcript -Path "$($env:windir)\Temp\Automate_Deploy.txt" -Force}
    $SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    $SoftwarePath = "C:\Support\Automate"
    $Filename = "Automate_Agent.msi"
    $SoftwareFullPath = "$SoftwarePath\$Filename"
    $AutomateURL = "https://$($Server)"

    Write-Verbose "Checking Operating System (WinXP and Older)"
    if ([int]((Get-WmiObject Win32_OperatingSystem).BuildNumber) -lt 6000) {
        $OS = ((Get-WmiObject Win32_OperatingSystem).Caption)
        Write-Host "This computer is running $($OS), and is no longer officially supported by ConnectWise Automate" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_Windows_XP_and_Server_2003_End_of_Life" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }

    Try {
        Write-Verbose "Enabling downloads to use SSL/TLS v1.2"
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    }
    Catch {
        Write-Verbose "Failed to enable SSL/TLS v1.2"
        Write-Host "This computer is not configured for SSL/TLS v1.2" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_TLS_1.0_and_1.1_Protocols_Unsupported" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }

    Try {
        $AutomateURLTest = "$($AutomateURL)/LabTech/"
        $TestURL = (New-Object Net.WebClient).DownloadString($AutomateURLTest)
        Write-Verbose "$AutomateURL is Active"
    }
    Catch {
        Write-Verbose "Could not download from $($AutomateURL). Switching to http://$($Server)"
        $AutomateURL = "http://$($Server)"
    }

    $DownloadPath = $null
    if ($null -ne $Token) {
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?InstallerToken=$Token"
        Write-Verbose "Downloading from: $($DownloadPath)"
    }
    else {
        Write-Verbose "A -Token <String[]> was not entered"
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?Probe=1&installType=msi&MSILocations=$($LocationID)"
        Write-Verbose "Downloading from (Old): $($DownloadPath)"
    }

    Confirm-Automate -Silent -Verbose:$Verbose
    Write-Verbose "if ServerAddress matches, the Automate Agent is currently Online, and Not forced to Rip & Replace then Automate is already installed."
    Write-Verbose (($Global:Automate.ServerAddress -like "*$($Server)*") -and ($Global:Automate.Online) -and !($Force))
    if (($Global:Automate.ServerAddress -like "*$($Server)*") -and $Global:Automate.Online -and !$Force) {
        if (!$Silent) {
            if ($Show) {
                $Global:Automate
            } else {
                Write-Host "The Automate Agent is already installed on $($Global:Automate.Computername) ($($Global:Automate.ComputerID)) and checked-in $($Global:Automate.LastStatus) seconds ago to $($Global:Automate.ServerAddress)" -ForegroundColor Green
            }
        }
    } else {
        if (!$Silent -and $Global:Automate.Online -and (!($Global:Automate.ServerAddress -like "*$($Server)*"))) {
            Write-Host "The Existing Automate Server Does Not Match The Target Automate Server." -ForegroundColor Red
            Write-Host "Current Automate Server: $($Global:Automate.ServerAddress)" -ForegroundColor Red
            Write-Host "New Automate Server:     $($AutomateURL)" -ForegroundColor Green
        } # if Different Server
        Write-Verbose "Downloading Automate Agent from $($AutomateURL)"
            if (!(Test-Path $SoftwarePath)) {mkdir $SoftwarePath | Out-Null}
            Set-Location $SoftwarePath
            if ((test-path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
            Try {
                Write-Verbose "Downloading from: $($DownloadPath)"
                Write-Verbose "Downloading to:   $($SoftwareFullPath)"
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
                Write-Verbose "Download Complete"
            }
            Catch {
                Write-Host "The Automate Server was inaccessible or the Token Parameters were not entered or valid. Failed to Download:" -ForegroundColor Red
                Write-Host $DownloadPath -ForegroundColor Red
                Write-Host "Help: Get-Help Install-Automate -Full"
                Write-Host "Exiting Installation..."
                Break
            }

            Write-Verbose "Removing Existing Automate Agent"
            Uninstall-Automate -Force:$Force -Silent:$Silent -Verbose:$Verbose
            if (!$Silent) {Write-Host "Installing Automate Agent to $AutomateURL"}
            Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force -PassThru
            $Date = (Get-Date -UFormat %Y-%m-%d_%H-%M-%S)
            $LogFullPath = "$env:windir\Temp\Automate_Agent_$Date.log"
            $Arguments = '-NoExit', '-Command', "Set-Location '$SoftwarePath'; msiexec.exe /i $($SoftwareFullPath) /qn /norestart LOCATION=$($LocationID) SERVERADDRESS=$($AutomateURL) /l*v $($LogFullPath)"
            $InstallExitCode = (Start-Process "powershell.exe" -ArgumentList $Arguments -Wait -PassThru).ExitCode
            Write-Verbose "MSIEXEC Log Files: $LogFullPath"
            if ($InstallExitCode -eq 0) {
                if (!$Silent) {Write-Verbose "The Automate Agent Installer Executed Without Errors"}
            } else {
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Red
                Write-Host "Automate Installer Logs: $LogFullPath" -ForegroundColor Red
                Write-Host "The Automate MSI failed. Waiting 15 Seconds..." -ForegroundColor Red
                Start-Sleep -Seconds 15
                Write-Host "Installer will execute twice (KI 12002617)" -ForegroundColor Yellow
                $Date = (Get-Date -UFormat %Y-%m-%d_%H-%M-%S)
                $LogFullPath = "$env:windir\Temp\Automate_Agent_$Date.log"
                $Arguments = '-NoExit', '-Command', "Set-Location '$SoftwarePath'; msiexec.exe /i $($SoftwareFullPath) /qn /norestart LOCATION=$($LocationID) SERVERADDRESS=$($AutomateURL) /l*v $($LogFullPath)"
                $InstallExitCode = (Start-Process "powershell.exe" -ArgumentList $Arguments -Wait -PassThru).ExitCode
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Yellow
                Write-Host "Automate Installer Logs: $LogFullPath" -ForegroundColor Yellow
            }# End else
        if ($InstallExitCode -eq 0) {
            While ($Counter -ne 30) {
                $Counter++
                Start-Sleep 10
                Confirm-Automate -Silent -Verbose:$Verbose
                if ($Global:Automate.Server -like "Enter the server address here*") {
                    Write-Verbose "The Automate Server Address was not written properly"
                    Write-Verbose "Manually overwriting the Server Address to: $($AutomateURL)"
                    Set-ItemProperty -Path HKLM:\SOFTWARE\LabTech\Service 'Server Address' -Value $AutomateURL –Force
                    Write-Verbose "Restarting LTService after correcting the Server Address"
                    Get-Service LTService | Where-Object {$_.Status -eq "Running"} | Restart-Service -Force
                    Confirm-Automate -Silent -Verbose:$Verbose
                }
                if ($Global:Automate.Online -and $Null -ne $Global:Automate.ComputerID) {
                    if (!$Silent) {
                        Write-Host "The Automate Agent Has Been Successfully Installed" -ForegroundColor Green
                        $Global:Automate
                    }#end if Silent
                    Break
                } # end if
            }# end While
        } else {
            While ($Counter -ne 3) {
                $Counter++
                Start-Sleep 10
                Confirm-Automate -Silent -Verbose:$Verbose
                if ($Global:Automate.Server -like "Enter the server address here*") {
                    Write-Verbose "The Automate Server Address was not written properly"
                    Write-Verbose "Manually overwriting the Server Address to: $($AutomateURL)"
                    Set-ItemProperty -Path HKLM:\SOFTWARE\LabTech\Service 'Server Address' -Value $AutomateURL –Force
                    Write-Verbose "Restarting LTService after correcting the Server Address"
                    Get-Service LTService | Where-Object {$_.Status -eq "Running"} | Restart-Service -Force
                    Confirm-Automate -Silent -Verbose:$Verbose
                }
                if ($Global:Automate.Online -and $Null -ne $Global:Automate.ComputerID) {
                    if (!$Silent) {
                        Write-Host "The Automate Agent Has Been Successfully Installed" -ForegroundColor Green
                        $Global:Automate
                    }#end if Silent
                    Break
                } # end if
            } # end While
        } # end if ExitCode 0
        Confirm-Automate -Silent -Verbose:$Verbose
        if (!($Global:Automate.Online -and $Null -ne $Global:Automate.ComputerID)) {
            if (!$Silent) {
                    Write-Host "The Automate Agent FAILED to Install" -ForegroundColor Red
                    $Global:Automate
            }# end if Silent
        } # end if Not Online
    } # End
    if ($Transcript) {Stop-Transcript}
} #End Function Install-Automate
########################
Set-Alias -Name LTI -Value Install-Automate -Description 'Install Automate Agent'
########################
