Param(
    
    #Number of days worth of logs to search for
    [int]$days,
    [String]$ops,
    [String]$analyze,
    #If start_time and end_time are not provided, will default to 12:00 AM
    [String] $start_time,
    [String] $end_time
)

if(($days -eq 0) -or ($ops -eq "") -or ($analyze -eq "")){
    Write-Host "`nMissing required parameters.`r`nSample expected usage: .\CASUAL.ps1 -days [1-90] -ops [ADLogin|OD_Access|SP_Access|EXO_Access]  -analyze [AppID|IP].`r`n`nPlease refer to the README.md for explaination of what the parameters represent.`n"
    Exit
}


if(-not (Get-Module ExchangeOnlineManagement -ListAvailable)){
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}

$operation_record_maps =@{
    "ADLogin" = @("UserLoggedIn")
    "OD_Access" = @("FileAccessed", "FileAccessedExtended", "FilePreviewed", "FileUploaded", "FileDownloaded", "FileDeleted", "FileCopied", "FileCheckedIn", "FileCheckedOut", "FileMoved", "FileRenamed", "FileModified", "FileModifiedExtended", "FileDeletedFirstStageRecycleBin", "FileDeletedSecondStageRecycleBin", "FileRestored","FolderCreated", "FolderDeleted", "FolderMoved", "FolderCopied", "FolderRenamed", "FolderRestored", "FolderDeletedFirstStageRecycleBin", "FolderDeletedSecondStageRecycleBin","SharingSet", "AnonymousLinkUsed", "SharingRevoked", "AnonymousLinkCreated", "AnonymousLinkUpdated", "AnonymousLinkRemoved", "SecureLinkCreated", "SecureLinkUsed", "AddedToSecureLink", "AccessRequestCreated", "AccessRequestApproved", "AccessRequestRejected")
    "SP_Access" = @("PageViewed", "PageViewedExtended","SiteCollectionAdminAdded", "SiteCollectionAdminRemoved", "AddedToGroup", "RemovedFromGroup", "WebMembersCanShareModified", "WebRequestAccessModified", "GroupAdded", "ListItemRecycled", "GroupRemoved",,"ListCreated", "ListViewed", "ListUpdated", "ListDeleted", "ListItemCreated", "ListItemUpdated", "ListItemViewed", "ListItemRestored", "ListItemRecycled","SiteCollectionCreated", "SiteDeleted", "SharingPolicyChanged", "SiteCreationSettingChanged", "NetworkAccessPolicyChanged")
    "EXO_Access" = @("MailItemsAccessed", "Create",  "SoftDelete", "HardDelete", "MoveToDeletedItems", "AddFolderPermissions","UpdateInboxRules", "New-InboxRule", "Set-InboxRule","Set-MalwareFilterPolicy", "Add-MailboxPermission", "Disable-MalwareFilterRule", "Set-Mailbox", "New-MalwareFilterPolicy", "Set-AdminAuditLogConfig")
}

If (($days -gt 90) -or ($days -lt 1))
{
    Write-Host "Days must be less than 90"
    Exit
}

if (-not ($operation_record_maps.containsKey($ops))){
    Write-Host "Invalid operation type"
    Exit
}

if (-not ($analyze -eq "IP" -or $analyze -eq "AppID")){
    Write-Host "Invalid analyze type"
    Exit
}

$present_file_path = (Get-Location)

$full_helper_functions_path = Join-Path -Path $present_file_path -ChildPath "CASUAL_functions.ps1"
. $full_helper_functions_path

$StartDate = (Get-Date).AddDays(-$days)
$StartDate,$start_time,$full_start_date = get_utc_from_date_and_time_input $StartDate $start_time

$EndDate = (Get-Date).AddDays(1)
$EndDate,$end_time,$full_end_date = get_utc_from_date_and_time_input $EndDate $end_time

Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline

Write-Host "Searching for events between $StartDate and $EndDate"

$start_time_for_filepath = $start_time.replace(":", "")
$end_time_for_filepath = $start_time.replace(":", "")

$start_date_for_filepath = $StartDate.replace("/","")
$end_date_for_filepath = $EndDate.replace("/","")

$results_folder_path = Join-Path -Path $present_file_path -ChildPath "Results"

if(!(Test-Path $results_folder_path)){
    New-Item -ItemType Directory -Path $results_folder_path
}

$result_filename = "{0}_{1}-{2}_{3}_{4}_{5}_Results.json" -f $start_date_for_filepath,$start_time_for_filepath,$end_date_for_filepath,$end_time_for_filepath,$ops,$analyze
$result_full_path = Join-Path -Path $present_file_path -ChildPath "Results" | Join-Path -ChildPath $result_filename

$operation_type = $operation_record_maps[$ops]
$session_id = (Get-Date).ToString()

if ($analyze -eq "IP"){
    $IP_addr_count= @{}
    $IP_addr_to_country_hash = @{}
    
    $total_count = 0

    Write-Host "Searching Unified Audit Logs for $ops"
    while(1){
        #Paginated query.
        $Audit = Search-UnifiedAuditLog -StartDate $full_start_date -EndDate $full_end_date -ResultSize 5000 -Operations $operation_type -SessionId $session_id -SessionCommand "ReturnLargeSet"
        $total_count += $($Audit.Count)

        if ($Audit.Count -eq 0){
            Write-Host "No more logs available. Exiting polling loop"
            break
        }

        $ConvertAudit = $Audit | Select-Object -ExpandProperty AuditData | ConvertFrom-Json

        #$IP_addr_count and $IP_addr_to_country_hash are continually passed for each query to continually update both hash tables.
        #Memory should not be an issue given that the hash tables only store summary statistics, so should not be very large.
        $IP_addr_count,$IP_addr_to_country_hash = get_country_from_api $ConvertAudit $IP_addr_count $IP_addr_to_country_hash
    }
        
    Write-Host "Total number of logs returned: $total_count" 

    if ($total_count -ne 0){
        $json_result =$IP_addr_count|ConvertTo-Json -depth 100
        $json_result| Set-Content -Path $result_full_path  
    }
    else{
        Write-Host "No logs found. Analysis complete."
    }
}
else{
    $application_id_count = @{}

    $total_count = 0

    Write-Host "Searching Unified Audit Logs for $ops"
    while(1){
        #Paginated query
        $Audit = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations $operation_type -SessionId $session_id -SessionCommand "ReturnLargeSet"
        $total_count += $Audit.Count

        if ($Audit.Count -eq 0){
            Write-Host "No more logs available. Exiting polling loop"
            break
        }

        Write-Host "Number of logs returned: $($Audit.Count)"
        $ConvertAudit = $Audit | Select-Object -ExpandProperty AuditData | ConvertFrom-Json

        #$application_id_count are continually passed for each query to continually update the hash table.
        #Memory should not be an issue given that the hash table only store summary statistics, so should not be very large.
        $application_id_count = get_application_name_from_applicationId $ConvertAudit $application_id_count
    }
    
    Write-Host "Total number of logs returned: $total_count"
    
    if ($total_count -ne 0){
    $json_result =$application_id_count|ConvertTo-Json -depth 100
    $json_result| Set-Content -Path $result_full_path
    }
    else{
        Write-Host "No logs found. Analysis complete."
    }
        
}

Disconnect-ExchangeOnline -Confirm:$false
