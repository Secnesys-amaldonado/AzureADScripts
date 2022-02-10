#=================================================================================================
#  FUNTIONS
#=================================================================================================

function parse-AppPermissions {

    Param(
    #App role assignment object
    [Parameter(Mandatory=$true)]$appRoleAssignments)

    foreach ($appRoleAssignment in $appRoleAssignments) {
        $resID = $appRoleAssignment.ResourceDisplayName
        $roleID = (Get-ServicePrincipalRoleById $appRoleAssignment.resourceId).appRoles | ? {$_.id -eq $appRoleAssignment.appRoleId} | select -ExpandProperty Value
        $OAuthperm["[" + $resID + "]"] += $("," + $RoleId)
    }
}

function parse-DelegatePermissions {

    Param(
    #oauth2PermissionGrants object
    [Parameter(Mandatory=$true)]$oauth2PermissionGrants)
   
    foreach ($oauth2PermissionGrant in $oauth2PermissionGrants) {
        $resID = (Get-ServicePrincipalRoleById $oauth2PermissionGrant.ResourceId).appDisplayName
        if ($null -ne $oauth2PermissionGrant.PrincipalId) {
            $userId = "(" + (Get-UserUPNById -objectID $oauth2PermissionGrant.principalId) + ")"
        }
        else { $userId = $null }
        $OAuthperm["[" + $resID + $userId + "]"] += ($oauth2PermissionGrant.Scope.Split(" ") -join ",")
    }
}

function Get-ServicePrincipalRoleById {

    Param(
    #Service principal object
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$spID)

    #check if we've already collected this SP data
    #do we need anything other than AppRoles? add a $select statement...
    if (!$SPPerm[$spID]) {
        $res = Invoke-WebRequest -Method Get -Uri "https://graph.microsoft.com/beta/servicePrincipals/$spID" -Headers $authHeader -Verbose:$VerbosePreference
        $SPPerm[$spID] = ($res.Content | ConvertFrom-Json)
    }
    return $SPPerm[$spID]
}

function Get-UserUPNById {

    Param(
    #User objectID
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$objectID)

    #check if we've already collected this User's data
    #currently we store only UPN, store the entire object if needed
    if (!$SPusers[$objectID]) {
        $res = Invoke-WebRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/users/$($objectID)?`$select=UserPrincipalName" -Headers $authHeader -Verbose:$VerbosePreference
        $SPusers[$objectID] = ($res.Content | ConvertFrom-Json).UserPrincipalName
    }
    return $SPusers[$objectID]
}

function Get-AuthCode {
    Add-Type -AssemblyName System.Windows.Forms

    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
    $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=420;Height=600;Url=($url -f ($Scope -join "%20")) }

    $DocComp  = {
        $Global:uri = $web.Url.AbsoluteUri        
        if ($Global:uri -match "error=[^&]*|code=[^&]*") {$form.Close() }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null

    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
    $output = @{}
    foreach($key in $queryOutput.Keys){
        $output["$key"] = $queryOutput[$key]
    }
}
#=================================================================================================
# END OF FUNCTIONS
#=================================================================================================

#=================================================================================================
# MAIN SCRIPT STARTS HERE
#=================================================================================================

# The resource URI
$resource = "https://graph.microsoft.com"

##### CHANGE THIS VARIABLES
# Your Client ID, Client Secret and Redirect URI obainted when registering your WebApp
$clientid = ""
$clientSecret = ""
$redirectUri = ""
# Your tenant name *.onmicrosoft.com
$tenantId = ""
##### END OF CHANGED VARIABLES

$url = 'https://login.microsoftonline.com/' + $tenantId + '/oauth2/v2.0/token'

# UrlEncode the ClientID and ClientSecret and URL's for special characters 
Add-Type -AssemblyName System.Web
$clientIDEncoded = [System.Web.HttpUtility]::UrlEncode($clientid)
$clientSecretEncoded = [System.Web.HttpUtility]::UrlEncode($clientSecret)
$redirectUriEncoded =  [System.Web.HttpUtility]::UrlEncode($redirectUri)
$resourceEncoded = [System.Web.HttpUtility]::UrlEncode($resource)
$scopeEncoded = [System.Web.HttpUtility]::UrlEncode("https://outlook.office.com/user.readwrite.all")

# Get AuthCode
$url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri=$redirectUriEncoded&client_id=$clientID&resource=$resourceEncoded&prompt=admin_consent&scope=$scopeEncoded"
Get-AuthCode
# Extract Access token from the returned URI
$regex = '(?<=code=)(.*)(?=&)'
$authCode  = ($uri | Select-string -pattern $regex).Matches[0].Value

#get Access Token

$body = "grant_type=authorization_code&redirect_uri=$redirectUri&client_id=$clientId&client_secret=$clientSecretEncoded&code=$authCode&resource=$resource"

$tokenResponse = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token `
    -Method Post -ContentType "application/x-www-form-urlencoded" `
    -Body $body `
    -ErrorAction STOP

$token = $tokenResponse.access_token

$authHeader = @{
       'Authorization'="Bearer $token"
    }

#Get the list of Service principal objects within the tenant.
#Filter out any "built-in" service principals. Remove the filter if you want to include them.
#Only /beta returns publisherName currently

$SPs = @()

$uri = "https://graph.microsoft.com/beta/servicePrincipals?`$top=999&`$filter="
#using the list endpoint returns empty appRoles?!?! Do per-SP query later on...
do {
    $result = Invoke-WebRequest -Method Get -Uri $uri -Headers $authHeader -Verbose:$VerbosePreference
    $uri = ($result.Content | ConvertFrom-Json).'@odata.nextLink'

    #If we are getting multiple pages, best add some delay to avoid throttling
    Start-Sleep -Milliseconds 500
    $SPs += ($result.Content | ConvertFrom-Json).Value
} while ($uri)

#Get permissions

$SPperm = @{} #hash-table to store data for app roles and stuff
$SPusers = @{} #hash-table to store data for users assigned delegate permissions and stuff
$output = [System.Collections.Generic.List[Object]]::new() #output variable
$i=0; $count = 1; $PercentComplete = 0;

foreach ($SP in $SPs) {
    #Progress message
    $ActivityMessage = "Obteniendo los datos del Service Principal: $($SP.DisplayName). Por favor espere..."
    $StatusMessage = ("Procesando {0} of {1}: {2}" -f $count, @($SPs).count, $SP.id)
    $PercentComplete = ($count / @($SPs).count * 100)
    Write-Progress -Activity $ActivityMessage -Status $StatusMessage -PercentComplete $PercentComplete
    $count++

    #simple anti-throttling control
    Start-Sleep -Milliseconds 500
    Write-Verbose "Processing service principal $($SP.id)..."

    #Check for appRoleAssignments (application permissions)
    $appRoleAssignments = @()
    $res = Invoke-WebRequest -Method Get -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/appRoleAssignments" -Headers $authHeader -Verbose:$VerbosePreference
    $appRoleAssignments = ($res.Content | ConvertFrom-Json).Value

    $OAuthperm = @{};
    $assignedto = @();
    $resID = $null;
    $userId = $null;

    #prepare the output object
    $i++;$objPermissions = [PSCustomObject][ordered]@{
        "Number" = $i
        "Application Name" = $SP.appDisplayName
        "Tags" = [String]$SP.tags
        "ApplicationId" = $SP.AppId
        "Publisher" = (&{if ($SP.PublisherName) {$SP.PublisherName} else { $null }})
        "Verified" = (&{if ($SP.verifiedPublisher.verifiedPublisherId) {$SP.verifiedPublisher.displayName} else {"Not verified"}})
        "Homepage" = (&{if ($SP.Homepage) {$SP.Homepage} else { $null }})
        "Reply URL" = [String]$SP.replyUrls
        "SP name" = $SP.displayName
        "ObjectId" = $SP.id
        "Created on" = (&{if ($SP.createdDateTime) {(Get-Date($SP.createdDateTime) -format g)} else { $null }})
        "Enabled" = $SP.AccountEnabled      
        "Last modified" = $null
        "Audience" = $SP.signInAudience
        "Permissions (application)" = $null
        "Authorized By (application)" = $null
        "Permissions (delegate)" = $null
        "Valid until (delegate)" = $null
        "Authorized By (delegate)" = $null
    }

    #process application permissions entries
    if (!$appRoleAssignments) { Write-Verbose "No application permissions to report on for SP $($SP.id), skipping..." }
    else {
        $objPermissions.'Last modified' = (Get-Date($appRoleAssignments.CreationTimestamp | select -Unique | sort -Descending | select -First 1) -format g)
    
        parse-AppPermissions $appRoleAssignments
        $objPermissions.'Permissions (application)' = (($OAuthperm.GetEnumerator()  | % { "$($_.Name):$($_.Value.ToString().TrimStart(','))"}) -join ";")
        $objPermissions.'Authorized By (application)' = "An administrator (application permissions)"
    }
    
    #Check for oauth2PermissionGrants (delegate permissions)
    #Use /beta here, as /v1.0 does not return expiryTime
    $oauth2PermissionGrants = @()
    $res = Invoke-WebRequest -Method Get -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/oauth2PermissionGrants" -Headers $authHeader -Verbose:$VerbosePreference
    $oauth2PermissionGrants = ($res.Content | ConvertFrom-Json).Value
    $OAuthperm = @{};
    $assignedto = @();
    $resID = $null; 
    $userId = $null;

    #process delegate permissions entries
    if (!$oauth2PermissionGrants) { Write-Verbose "No delegate permissions to report on for SP $($SP.id), skipping..." }
    else {
        parse-DelegatePermissions $oauth2PermissionGrants
        $objPermissions.'Permissions (delegate)' = (($OAuthperm.GetEnumerator() | % { "$($_.Name):$($_.Value.ToString().TrimStart(','))"}) -join ";")
        $objPermissions.'Valid until (delegate)' = (Get-Date($oauth2PermissionGrants.ExpiryTime | select -Unique | sort -Descending | select -First 1) -format g)
        
        if (($oauth2PermissionGrants.ConsentType | select -Unique) -eq "AllPrincipals") { $assignedto += "All users (admin consent)" }
        $assignedto +=  @($OAuthperm.Keys) | % {if ($_ -match "\((.*@.*)\)") {$Matches[1]}}
        $objPermissions.'Authorized By (delegate)' = (($assignedto | select -Unique) -join ",")
    }

    $output.Add($objPermissions)
}

#Export the result to CSV file
$output | select * | Export-CSV -nti -Path "$((Get-Date).ToString('yyyyMMdd_HHmmss'))_GraphAppInventory.csv"