Param (
       [string]$organisation = "",
       [string]$key = ""
       )

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


$assettypeID = 172738

$ITGbaseURI = "https://api.itglue.com"

 
$headers = @{
    "x-api-key" = $key
}

Import-Module C:\temp\itglue\modules\itgluepowershell\ITGlueAPI.psd1 -Force
Add-ITGlueAPIKey -Api_Key $key
Add-ITGlueBaseURI -base_uri $ITGbaseURI

function BuildActiveDirectoryUserAsset ($tenantInfo) {
    
    $body = @{
        data = @{
            type       = "flexible-assets"
            attributes = @{
                "organization-id"        = $ITGlueOrganisation
                "flexible-asset-type-id" = $assettypeID
                traits                   = @{
                    "name"      = $tenantInfo.name
                    "username"        = $tenantInfo.username
                    "enabled"   = $tenantInfo.enabled
                    "group-membership" = $tenantInfo.groups | Sort-Object
                    "last-login-date"         = $tenantInfo.lastlogondate
                   
                }
            }
        }
    }
    
    $tenantAsset = $body | ConvertTo-Json -Depth 10
    return $tenantAsset
}

function GetAllITGItems ($Resource) {
    $array = @()
    
    $body = Invoke-RestMethod -Method get -Uri "$ITGbaseURI/$Resource" -Headers $headers -ContentType application/vnd.api+json
    $array += $body.data
    Write-Host "Retrieved $($array.Count) items"
        
    if ($body.links.next) {
        do {
            $body = Invoke-RestMethod -Method get -Uri $body.links.next -Headers $headers -ContentType application/vnd.api+json
            $array += $body.data
            Write-Host "Retrieved $($array.Count) items"
        } while ($body.links.next)
    }
    return $array
}

function CreateITGItem ($resource, $body) {
    $item = Invoke-RestMethod -Method POST -ContentType application/vnd.api+json -Uri $ITGbaseURI/$resource -Body $body -Headers $headers
    #return $item
}

function UpdateITGItem ($resource, $existingItem, $newBody) {
    $updatedItem = Invoke-RestMethod -Method Patch -Uri "$ITGbaseUri/$Resource/$($existingItem.id)" -Headers $headers -ContentType application/vnd.api+json -Body $newBody
    return $updatedItem
}

function Get-ITGlueID($ServerName){

(Get-ITGlueConfigurations -filter_name $ServerName).data.id 

}

Write-Host Attempting match of ITGlue Company using name $organisation -ForegroundColor Green

$attempted_match = Get-ITGlueOrganizations -filter_name "$organisation"

if($attempted_match.data[0].attributes.name -match $organisation) {
            Write-Host "Auto-match of ITGlue company successful." -ForegroundColor Green

            $ITGlueOrganisation = $attempted_match.data.id
}
            else {
            Write-Host "No auto-match was found. Please pass the exact name in ITGlue to -organization <string>" -ForegroundColor Red
            Exit
            }


    $Report = @()
    #Collect all users
    $Users = Get-ADUser -Filter * -Properties Name, GivenName, SurName, SamAccountName, UserPrincipalName, MemberOf, Enabled, LastLogonDate -ResultSetSize $Null
    # Use ForEach loop, as we need group membership for every account that is collected.
    # MemberOf property of User object has the list of groups and is available in DN format.
    Foreach($User in $users){
    $UserGroupCollection = $User.MemberOf
    #This Array will hold Group Names to which the user belongs.
    $UserGroupMembership = @()
    #To get the Group Names from DN format we will again use Foreach loop to query every DN and retrieve the Name property of Group.
    Foreach($UserGroup in $UserGroupCollection){
    $GroupDetails = Get-ADGroup -Identity $UserGroup
    #Here we will add each group Name to UserGroupMembership array
    $UserGroupMembership += $GroupDetails.Name
    }
    #As the UserGroupMembership is array we need to join element with ‘"<br/>"’ as the seperator
    $Groups = $UserGroupMembership -join "<br/>" | Sort-Object 
    $LogonDate = $User.LastLogonDate | Out-String
    #Creating custom objects
    $Out = New-Object PSObject
    $Out | Add-Member -MemberType noteproperty -Name Name -Value $User.Name
    $Out | Add-Member -MemberType noteproperty -Name Username -Value $User.SamAccountName
    $Out | Add-Member -MemberType noteproperty -Name Enabled -Value $User.Enabled
    $Out | Add-Member -MemberType noteproperty -Name Groups -Value $Groups
    $Out | Add-Member -MemberType noteproperty -Name LastLogonDate -Value $LogonDate 
    $Report += $Out
    }

ForEach ($UserItem in $Report){
    $existingAssets = @()
    $existingAssets += GetAllITGItems -Resource "flexible_assets?filter[organization_id]=$ITGlueOrganisation&filter[flexible_asset_type_id]=$assetTypeID"
    $matchingAsset = $existingAssets | Where-Object {$_.attributes.traits.'username' -contains $Useritem.Username}

    if ($matchingAsset) {
            Write-Output "Updating Active Directory User Flexible Asset"
            $UpdatedBody = BuildActiveDirectoryUserAsset -tenantInfo $Useritem
            $updatedItem = UpdateITGItem -resource flexible_assets -existingItem $matchingAsset -newBody $UpdatedBody
            Start-Sleep -Seconds 3
        }
        else {
            Write-Output "Creating Active Directory User Flexible Asset"
            $body = BuildActiveDirectoryUserAsset -tenantInfo $Useritem
            CreateITGItem -resource flexible_assets -body $body
            Start-Sleep -Seconds 3
            
        }
}
