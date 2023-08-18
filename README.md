# Cloud Audit Search through UnifiedAuditLogs (CASUAL)

| Info   | CASUAL is a Powershell script that performs data processing on the M365 logs returned from the [ Search-UnifiedAuditLog cmdlet ]( https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog?view=exchange-ps ) to return summary statistics. |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Author | Zhi Kang|

## Requirements

### ExchangeOnlineManagement

Install the _ExchangeOnlineManagement_ module
```
Install-Module ExchangeOnlineManagement
```

### Permissions needed to access the audit logs

<ol>
  <li>UnifiedAuditLog needs to be enabled.</li>

  <li>If the script is not being run as an administrator, the user needs to be in the _Audit Logs_ management role group. To do so, run with an admin account </li>

    New-ManagementRoleAssignment -Role "Audit Logs" -User "<non_admin_user@domain.com>"
    
  The non-admin user that is assigned to the role group should now be able to run the script successfully.
</ol>

## Usage

```bash
./src/CASUAL.ps1 -ops [ADLogin|OD_Access|SP_Access|EXO_Access] -analyze [AppID|IP] -days [1-90] -start_time <"8:00AM"> -end_time <"8:00AM">
```

### Parameters

* **ops**: Type of M365 logs to be pulled and processed

    1. ADLogin: Azure AD login logs
    2. OD_Access: OneDrive audit logs
    3. SP_Access: Sharepoint audit logs
    4. EXO_Access: Exchange Online audit logs

* **analyze**: Type of analysis to perform. The analysis results are on a user level, i.e. summary statistics per user.

    1. AppID: Analysis based on the ApplicationId field in the logs. Returns the human readable name of ApplicationId if available and count per application.
    2. IP: Analysis based on the ClientIP field in the logs. Returns the country of the IP address if available and count per IP address.

    [Additional information for the different fields](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#common-schema)

* **days**: Number of days from the current date to pull the logs from. Must be between 1 to 90

* **start_time**: The start time of the date range to pull the logs from. If none is provided, will default to 12:00AM

* **end_time**: The end time of the date range to pull the logs from. If none is provided, will default to 12:00AM

## Result

The analysis results will be stored as a JSON file in the Results folder. The results file will have name in this format:

```bash
<log_search_start_date>_<start_time_without_AM_or_PM>-<log_search_end_date>_<end_time_without_AM_or_PM>_<ops>_<analyze>_Results.json
```

## Sample Result

### IP Analysis

```json
{
    "user_a": {
    "Unique IP Count": 1,
    "Unique Countries Count": 1
    "IP Properties": {
      "209.142.68.29": {
        "Country": "United States",
        "Count": 18
      }
    }
  },
  "user_b@test_domain.com": {
    "Unique IP Count": 2,
    "Unique Countries Count": 1
    "IP Properties": {
      "69.162.81.155": {
        "Country": "United States",
        "Count": 5
      },
      "192.199.248.75": {
        "Country": "United States",
        "Count": 58
      }
    }
  },
  "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)": {
    "Unique Count": 0,
    "Unique Countries Count": 0
    "IP Properties": {
      "No IP": {
        "Country": "None",
        "Count": 20
      }
    }
  }
}
```

### AppID Analysis

```json
{
    "user_a": {
      "Unique Count": 3
     "AppID Properties": {
      "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": {
        "Name": "Azure Admin Web UI",
        "Count": 7
      },
      "fb78d390-0c51-40cd-8e17-fdbfab77341b": {
        "Name": "Microsoft Exchange REST API Based Powershell",
        "Count": 50
      },
      "2caeb7e8-ee9a-4f10-998f-2e7a329b6c49": {
        "Name": "Unknown",
        "Count": 7
      }
    }
  },
 "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)": {
    "Unique Count": 0
    "AppID Properties": {
      "No AppID": {
        "Name": "None",
        "Count": 20
      }
    }
  }
}
```
## Support/Feedback
For issues with, questions about, or feedback for CASUAL, please contact us at our [email](hello@insidersecurity.co).
