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

##
## From this point onwards the script start to gathering information about the Registered Applications.
##

Write-Host "Gathering information about Azure AD integrated applications..." -ForegroundColor Yellow

try { 
    $appRegs = Get-AzureADApplication ## Just to get the list of App Registrations 
    }
catch { 
    Write-Host "You must connect to Azure AD first!" -ForegroundColor Red -ErrorAction Stop 
    }

$output = [System.Collections.Generic.List[Object]]::new() #output variable
$i = 0
foreach ($appReg in $appRegs) {
    Write-Host "Gathering information about"$appReg.DisplayName -ForegroundColor DarkYellow
    $i++;
    $endReplURL = $null
    $objPermissions = New-Object PSObject
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Number" -Value $i
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Application Name" -Value $appReg.DisplayName
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "ApplicationId" -Value $appReg.AppId
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Available to other Tenants" -Value $appReg.AvailableToOtherTenants
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "OAuth2 Permissions" -Value $null
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Password Credentials" -Value $null
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Publicher Domain" -Value $appReg.PublisherDomain
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Public Client" -Value $appReg.PublicClient
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Homepage" -Value $appReg.Homepage
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Reply URLs" -Value $null
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "SignIn Audience" -Value $appReg.SignInAudience
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "App Permissions" -Value $null
    
   $resAppsIds = $appReg.RequiredResourceAccess
   $appPermissions = $null
    foreach($resAppsId in $resAppsIds){
        
        $AppId = $resAppsId.ResourceAppId
        $resourceAccess = $resAppsId.ResourceAccess
        foreach($Id in $AppId){
            
            foreach($resourceAcc in $resourceAccess){
                if($resourceAcc.Type -eq "Role"){
                    $sp = Get-AzureADServicePrincipal -All $true | Where-Object {$_.AppId -eq $AppId} ## Just to get the data of the Resource of the permission (Application)
                    $spRoles = $sp.AppRoles | Where-Object {$_.Id -eq $resourceAcc.Id}
                    $Content = [PSCustomObject]@{
                        "App API Name" = '['+$sp.DisplayName+']';
                        "App Permision Type" = $spRoles.AllowedMemberTypes[0];
                        "App Permission" = $spRoles.Value
                        }                        
                    }else{
                    $sp = Get-AzureADServicePrincipal -All $true | Where-Object {$_.AppId -eq $AppId} ## Just to get the data of the Resource of the permission (Delegated)
                    $spRoles = $sp.Oauth2Permissions | Where-Object {$_.Id -eq $resourceAcc.Id}
                    $Content = [PSCustomObject]@{
                        "App API Name" = '['+$sp.DisplayName+']';
                        "App Permision Type" = "Delegated";
                        "App Permission" = $spRoles.Value
                        }
                    }
                $appPermissions = $appPermissions + $Content.'App API Name'.ToString() + ', ' + $Content.'App Permision Type'.ToString() + ', ' + $Content.'App Permission'.ToString() + "; "
                }
        }
            
    }
    $objPermissions.'App Permissions' = $appPermissions

    $appReplURLs = $appReg.ReplyUrls

    foreach($appReplURL in $appReplURLs){
    
        $endReplURL = $endReplURL + $appReplURL + '; '
    }
    $objPermissions.'Reply URLs' = $endReplURL
    
    $pwdCreds = $appReg.PasswordCredentials
    $credLine = $null
    $allCreds = $null
    foreach($pwdCred in $pwdCreds){

        $credId = $pwdCred.KeyId
        $credSd = $pwdCred.StartDate.ToString("yyyy-MM-dd / hh:mm:ss")
        $credEd = $pwdCred.EndDate.ToString("yyyy-MM-dd / hh:mm:ss")
        $credLine = $credId + "; " + $credSd + "; " + $credEd
        $allCreds = $allCreds + $credLine + " | "
    }
    $objPermissions.'Password Credentials' = $allCreds
    
    $oauth2Perms = $appReg.Oauth2Permissions
    $preLine = $null

    foreach($oauth2Perm in $oauth2Perms){

        $oauth2PermDescr = $oauth2Perm.AdminConsentDescription
        $oauth2PermId = $oauth2Perm.Id
        $oauth2PermStatus = $oauth2Perm.IsEnabled
        $oauth2PermType = $oauth2Perm.Type
        $oauth2PermUsrConsDescr = $oauth2Perm.UserConsentDescription
        $oauth2PermUsrConsValue = $oauth2Perm.Value
        $preLine += $preLine + $oauth2PermId + "; " + $oauth2PermDescr + "; Status:" + $oauth2PermStatus + "; Type:" + $oauth2PermType + "; " + $oauth2PermUsrConsDescr + "; Value:" + $oauth2PermUsrConsValue + " | "
    }
    $objPermissions.'OAuth2 Permissions' = $preLine
    
    $output.Add($objPermissions)
}

#Export the result to CSV file
$output | select * | Export-CSV -nti -Path "$((Get-Date).ToString('ddMMyyyy'))_PSAppsInventory.csv"