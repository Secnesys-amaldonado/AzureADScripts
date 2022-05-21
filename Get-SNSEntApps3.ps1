
Import-Module AzureADPreview -Force

##
## First this script will check if the client computer has the correct version of Powershell to excecute
##
if (!(Get-Module AzureAD -ListAvailable | ? {($_.Version.Major -eq 2 -and $_.Version.Build -gt 0 -and $_.Version.Revision -gt 55) -or ($_.Version.Major -eq 2 -and $_.Version.Build -eq 1)})) { 
    Write-Host -BackgroundColor Red "This script requires a recent version of the AzureAD PowerShell module. Download it here: https://www.powershellgallery.com/packages/AzureAD/"; return
    }
##
## In this step, the script will check if previusly the current client console are already connected to Azure AD, otherwise will ask for user credentials to connect to Azure AD.
## The user credentials provider will have at least permissions to read the directory.
##
try { 
    Get-AzureADTenantDetail | Out-Null 
    }
catch { 
    Connect-AzureAD | Out-Null 
    }

Write-Host " "
Write-Host " "
Write-Host " "
Write-Host "Gathering information about Azure AD Enterprise applications..." -ForegroundColor Yellow

$entApps = Get-AzureADServicePrincipal -All $true    ##$entApp = $entApps[803] ##658 3 155 664    $entApp | FL *
$i = 0
$output = [System.Collections.Generic.List[Object]]::new() #output variable
$count = 1; $PercentComplete = 0;

foreach($entApp in $entApps){
    $ActivityMessage = "Gathering information about [[$($entApp.DisplayName)]] Enterprise Application. Please wait..."
    $StatusMessage = ("Processing {0} of {1}: {2}" -f $count, @($entApps).count, $entApp.AppId)
    $PercentComplete = ($count / @($entApps).count * 100)
    Write-Progress -Activity $ActivityMessage -Status $StatusMessage -PercentComplete $PercentComplete
    $count++

    $objPermissions = New-Object PSObject
    $i = $i +1
    
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Number" -Value $i
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "EntApp Name" -Value $entApp.DisplayName
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "EntApp Id" -Value $entApp.AppId
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Enabled" -Value $entApp.AccountEnabled
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Role Assignament Required" -Value $entApp.AppRoleAssignmentRequired
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Permissions" -Value $null   #Completar más adelante
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Owner" -Value $null   #Completar más adelante
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Users and Groups" -Value $null   #Completar más adelante
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Tags" -Value $null   #Completar más adelante
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Sign-ins" -Value $null   #Completar más adelante
    
    $spOAuth2PermissionsGrants = Get-AzureADOAuth2PermissionGrant -All $true| Where-Object { $_.clientId -eq $entApp.ObjectId }
    ## $spOAuth2PermissionsGrants = Get-AzureADOAuth2PermissionGrant -All $true| Where-Object { $entApp.clientId -eq $entApp.ObjectId }
    $newspOAuth2PermissionsGrant = [PSCustomObject]@{}
    $permsFinal = [String]$null
    $permPid = [PSCustomObject]@{}

    if($spOAuth2PermissionsGrants -eq $null){$permsFinal = "Ninguno"}else{
    foreach($spOAuth2PermissionsGrant in $spOAuth2PermissionsGrants){ ## $spOAuth2PermissionsGrant = $spOAuth2PermissionsGrants[0]
        $permPid = Get-AzureADUser -ObjectId $spOAuth2PermissionsGrant.PrincipalId -WarningAction SilentlyContinue
        $permPid.DisplayName 
        $permService = Get-AzureADServicePrincipal -All $true | Where-Object {$_.ObjectId -eq $spOAuth2PermissionsGrant.ResourceId}
        if($permService -eq $null){
        $permsFinal = "Ninguno"
        }else{
            $newspOAuth2PermissionsGrant = @{
                "API Name" = '['+$permService.DisplayName+']';
                "Claim value" = $spOAuth2PermissionsGrant.Scope
                "Consent Type" = $spOAuth2PermissionsGrant.ConsentType

            } 
            $permsFinal = $permsFinal + $newspOAuth2PermissionsGrant.'API Name'.ToString() + ', ' +  $newspOAuth2PermissionsGrant.'Claim value'.ToString() + ', ' + $newspOAuth2PermissionsGrant.'Consent Type' + ', ' + $permPid.DisplayName + "`n"
            }
        }
        }

    $objPermissions.Permissions = $permsFinal    
    $entAppOwner = Get-AzureADServicePrincipalOwner -ObjectId $entApp.ObjectId

    if($entAppOwner -eq $null){
        $entAppOwnName = "Ninguno"
        }else{
            $entAppOwnPreName = $entAppOwner.DisplayName
            [string]$entAppOwnName = $null
            for($j=0;$j -lt $entAppOwnPreName.Count;$j++){
                $entAppOwnName = $entAppOwnName + $entAppOwnPreName[$j]
                if($entAppOwnPreName.Count -gt $j+1){
                    [string]$entAppOwnName = $entAppOwnName + ','
                    }
                }
            }

    $objPermissions.Owner = $entAppOwnName
    $entAppUsrGrps = Get-AzureADServiceAppRoleAssignment -ObjectId $entApp.ObjectId

    if($entAppUsrGrps -eq $null){
        $entAppUsrGrpsName = "Ninguno"
        }else{
        $entAppUsrGrpspreName = @()
        [string]$entAppUsrGrpsName = $null
        for($j=0;$j -lt $entAppUsrGrps.Count;$j++){
            $entAppUsrGrpsName = $entAppUsrGrpsName + $entAppUsrGrps[$j].PrincipalDisplayName
            if($entAppUsrGrps.Count -gt $j+1){
                [string]$entAppUsrGrpsName = $entAppUsrGrpsName + ','
                }
            }  
        }

    $objPermissions.'Users and Groups' = $entAppUsrGrpsName
    [string]$entAppFinalTags = $null
    $entAppTags = $entApp.Tags

    if($entAppTags -eq $null){
       $entAppFinalTags = "Ninguno"
    }else{
        for($j=0;$j -lt $entAppTags.Count;$j++){
            $entAppFinalTags = $entAppFinalTags + $entAppTags[$j]
            if($entAppTags.Count -gt $j+1){
                [string]$entAppFinalTags = $entAppFinalTags + ','
                }
            }    
    }

    $entAppName = $entApp.DisplayName
    
    $entAppSignLogs = Get-AzureADAuditSignInLogs -Filter "appDisplayName eq '$entAppName'"


    [string]$entAppFinalSignIns = $null
    if($entAppSignLogs -eq $null){
        $entAppFinalSignIns = "Ninguno"
    }else{
        for($j=0;$j -lt $entAppSignLogs.Count;$j++){
            $entAppFinalSignIns = $entAppFinalSignIns + $entAppSignLogs[$j].CreatedDateTime + ", " + $entAppSignLogs[$j].IpAddress  + ", " + $entAppSignLogs[$j].UserPrincipalName + ", " + $entAppSignLogs[$j].Status.ErrorCode + "`n"
        }
    }

    $objPermissions.'Sign-ins' = $entAppFinalSignIns



    foreach($entAppSignLog in $entAppSignLogs){
        
        $entAppSignLog.CreatedDateTime + ", " + $entAppSignLog.IpAddress  + ", " + $entAppSignLog.UserPrincipalName + ", " + $entAppSignLog.Status.ErrorCode
        #$entAppSignUsrs = $entAppSignLog.UserPrincipalName + ", " + $entAppSignLog.CreatedDateTime
    }

    $objPermissions.'Tags' = $entAppFinalTags
    $output.Add($objPermissions)
}

$output | select * | Export-CSV -nti -Path "$((Get-Date).ToString('ddMMyyyy'))_NwPSEntAppsInventory.csv"