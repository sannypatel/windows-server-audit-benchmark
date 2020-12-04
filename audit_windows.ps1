<#
.SYNOPSIS
  The purpose of the script is to Audit Windows Server. You can change or update your test cases accordingly.
  Please free to update the code if you have a better way to test below test cases. (I know you will have)

.OUTPUTS
  Log file stored in C:\temp\audit__log_<yyyyMMddHHmmss>.log and it will store audit output in C:\temp\Windows_Audit_Result.csv and open port output on C:\temp\Open_Ports_Result.csv. 

.NOTES
  Version:        1.2
  Author:         Sanny Patel
  Creation Date:  1/12/2020
  Purpose/Change: Updated the section 3.1 (CheckAdminGroups Condition)
  
.EXAMPLE
  audit_windows.ps1

#>

## Variables
$env:Path += ";c:\windows\system32"
$LogTime = get-Date -Format "yyyyMMddHHmmss"
$LogName = "C:\temp\"+"audit_log_"+$LogTime
$LogFile = $LogName+".log"
$AuditCsv = "C:\temp\Windows_Audit_Result.csv"
$OpenPortCsv = "C:\temp\Open_Ports_Result.csv"

## Start TranScript
Start-Transcript -path $LogFile -append

Write-Output "Create LogFile $LogFile "

$script = {

    Write-Output "Section,Id,Description,Result" | Out-File $AuditCsv -Encoding UTF8

    function WriteResult {
        param (
            [Parameter()][string]$Result,
            [Parameter()][string]$Description,
            [Parameter()][string]$Id,
            [Parameter()][string]$Section
        )
        Write-Output "$Section,$Id,$Description,$Result" | Out-File -Append $AuditCsv -Encoding UTF8

    }

    function TestGPOs {
        $Description = "Check if necessary GPOs are applied"
        $Id = "5.4"
        $Section = "5"

        ## Add/Update your GPOs which should be applied on your windows server
        $Gpos = @("GPO_M_SEC_Servers","GPO_M_SEC_Servers_NLA","GPO_M_SEC_CSI_2016_MS  L1","GPO_M_SEC_CSI_2016_MS  L2", "Default Domain Policy", "CertificateInstaller", "WSUS Policy - Servers", "GPO_M_SEC_MGMT_Servers-Audit_Poilcy")
        $cmdout = gpresult /r /scope:computer
        $pattern = "Applied Group Policy Objects(.*?)The following GPOs were not applied because they were filtered out"
        $result = [regex]::match($cmdout, $pattern).Groups[1].Value
        $result = $result.replace("         ","`n")
        $result | out-file temp.txt
        $count = 0
        Foreach ($gpo in Get-Content .\temp.txt){
            if($Gpos.Contains($gpo)){
                $count = $count + 1
            }
        }
        if($count -ne 0)
        {  
            $Result = "Pass ($count applied)"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
        else
        {
            $Result = "Fail"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }

        Remove-Item .\temp.txt
        
    }
    function TestOU {
        
        $Description = "Check if the Servers' OU is correct."
        $Id = "5.3"
        $Section = "5"

        ## Update your OU details which you need to verify
        $OuResult = gpresult /r | Select-String -Pattern "(OU=SQL)|(OU=Application)|(OU=Build))"
        if ($null -ne $OuResult)
        {
            $Result = "Pass"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
        else
        {
            $Result = "Fail"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
    }
    function TestPath {
        param(
            [Parameter()][string]$Path,
            [Parameter()][string]$Id,
            [Parameter()][string]$Section,
            [Parameter()][string]$Description

        )

        if (Test-Path -Path $Path)
        {  
            $Result = "Pass"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
        else
        {
            $Result = "Fail"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }   
    }

    function CheckLicensing {
        $Description = "Check Windows License Status"
        $Id = "3.8"
        $Section = "3"
        $ExpectedOutput = "Windows(R), ServerStandard edition:    The machine is permanently activated."
        
        $WinVerAct = (cscript /Nologo "C:\Windows\System32\slmgr.vbs" /xpr) -join ''
        
        if ( $WinVerAct -eq $ExpectedOutput)
        {
            $Result = "Pass"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
        else {
            $Result = "Fail"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
    }

    function CheckDomainName {
        $Description = "Registering with the AD DNS registration"
        $Id = "3.2"
        $Section = "3"

        $AllDomain = @("example.com","example.local","example-test.com")
        $Domain = (Get-WmiObject win32_computersystem).Domain
        if($AllDomain.Contains($Domain))
        {   
            $Result = "Pass"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
        else {
            $Result = "Fail"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }

    }
    function CheckPortRange {
        if (Test-Path -Path $OpenPortCsv) {
            Clear-Content $OpenPortCsv
        }
        (Get-NetFirewallPortFilter -PolicyStore ActiveStore |Select-Object -Unique LocalPort).LocalPort | Out-File .\temp_ports.txt
        foreach ($port in Get-Content .\temp_ports.txt){
            try
            {
                if([int]$port -ge 1024){
                    Get-NetFirewallPortFilter -PolicyStore ActiveStore | Where-Object LocalPort -eq $port | Select-Object -Property LocalPort,InstanceID | Export-Csv -Append $OpenPortCsv -Encoding UTF8
                }
            }
            catch
            {
                Write-Debug "Not Applicable"
            }
        }
        Remove-Item .\temp_ports.txt
        
    }

    function CheckIsPortOpen {
        param (
            [Parameter()][string]$Port
        )

        $Description = "Registering Server to AD communication (Port test $Port)"
        $Id = "3.3"
        $Section = "3"

        $FirewallPort = Get-NetFirewallPortFilter -PolicyStore ActiveStore | Where-Object LocalPort -eq $Port |Select-Object -Property LocalPort
        if ($null -ne $FirewallPort)
        {   
            $Result = "Pass"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
        else {
            $Result = "Fail"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
    }

    function CheckAdminGroups {
        $Description = "Administrative access to Windows Virtual Servers"
        $Id = "3.1"
        $Section = "3"

        $Hostname = HOSTNAME.EXE
        #$ServerAdminGroup = Get-LocalGroupMember -Group "Administrators" | Select-String -Pattern "ADM-$Hostname-Administrators"
        $ServerAdminGroup = net localgroup administrators | Select-String -Pattern "ADM-$Hostname-Administrators"
        $ServerAdminGroupRDP = net localgroup administrators | Select-String -Pattern "ADM-$Hostname-Remote Desktop Users"
        if ($null -ne $ServerAdminGroup -And $null -ne $ServerAdminGroupRDP)
        {
            $Result = "Pass"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
        else {
            $Result = "Fail"
            WriteResult -Result $Result -Description $Description -Id $Id -Section $Section
        }
    }
    
    ## Start Testing
    ## Test Section 3.1 - Administrative access to Windows Virtual Servers
    CheckAdminGroups

    ## Test Section 3.2 - Registering with the AD DNS registration  
    CheckDomainName 

    ## test Section 3.3 - Registering Server to AD communication (Check if necessary ports are opened)
    $ADPorts = 53,88,135,139,389,445,464,593,636,3268,3269,49572,49573
    foreach ($port in $ADPorts) { 
        CheckIsPortOpen $port
    }
    ## test Section 3.3 - Registering Server to AD communication (Open Ports result)
    CheckPortRange

    ## Test Section 3.4 -  Mandotory Applications/Agents to be installed
    TestPath -Path "C:\Program Files\Qualys\QualysAgent\QualysAgent.exe" -Id "3.4.1" -Section "3" -Description "Ensure Qualys Agent is installed"
    TestPath -Path "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\Smc.exe" -Id "3.4.2" -Section "3" -Description "Ensure Symantec Agent is installed"
    TestPath -Path "C:\Program Files (x86)\BigFix Enterprise\BES Client\" -Id "3.4.3" -Section "3" -Description "Ensure Tivoli Agent is installed"
    TestPath -Path "C:\Program Files (x86)\BigFix Enterprise\BES Client\" -Id "3.4.4" -Section "3" -Description "Ensure TEM Agent is installed"
    TestPath -Path "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" -Id "3.4.5" -Section "3" -Description "Ensure Splunk Agent is installed"

    ## Test Section 3.8 - Licensing of Window Virtual Servers
    CheckLicensing

    ## Test Section 5.3 - All new Servers should go in correct OU while adding to AD or after added to AD. Default  Server goes  to “Computer” OU in AD Based on Server role , Server should move to one of following OU
    TestOU

    ## Test Section 5.4 - Process of applying these hardening Standards to Windows 2016 SOE  as well other versions of windows,GPO apply all necessary hardening based on the OU to which server is placed
    TestGPOs

    ## Print Output
    Import-Csv -Path $AuditCsv | Format-Table -AutoSize
    Write-Output " _______________________________________________________________________"
    Write-Output "|                    Open Ports B/W 1024-65535                         |"
    Write-Output "|______________________________________________________________________|"
    Import-Csv -Path $OpenPortCsv | Format-Table -AutoSize
}

## Run Script Block 
Invoke-Command -Scriptblock $script

## End TranScript
Stop-Transcript