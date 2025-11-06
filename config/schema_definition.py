"""
Schema Definition
Defines the expected schema structure and data types for Sentinel Analytics Rules.
"""

# Required fields that must be present in every rule
REQUIRED_FIELDS = [
    'id',
    'name',
    'kind',
    'description',
    'severity',
    'enabled',
    'query',
    'queryFrequency',
    'queryPeriod',
    'triggerOperator',
    'triggerThreshold'
]

# Expected data types for fields
# Format: 'field.path': expected_type
EXPECTED_TYPES = {
    # Root level fields
    'id': str,
    'name': str,
    'displayName': str,
    'version': str,
    'lastModified': str,
    'kind': str,
    'description': str,
    'severity': str,
    'enabled': bool,
    'queryFrequency': str,
    'queryPeriod': str,
    'triggerOperator': str,
    'triggerThreshold': int,
    'query': str,
    'suppressionEnabled': bool,
    
    # Lists
    'tactics': list,
    'relevantTechniques': list,
    'entityMappings': list,
    'customDetails': dict,
    
    # Incident Configuration
    'incidentConfiguration.createIncident': bool,
    'incidentConfiguration.groupingConfiguration.enabled': bool,
    'incidentConfiguration.groupingConfiguration.reopenClosedIncident': bool,
    'incidentConfiguration.groupingConfiguration.lookbackDuration': str,
    'incidentConfiguration.groupingConfiguration.matchingMethod': str,
    'incidentConfiguration.groupingConfiguration.groupByEntities': list,
    'incidentConfiguration.groupingConfiguration.groupByAlertDetails': list,
    'incidentConfiguration.groupingConfiguration.groupByCustomDetails': list,
    
    # Event Grouping Settings
    'eventGroupingSettings.aggregationKind': str,
    
    # Alert Details Override
    'alertDetailsOverride.alertDisplayNameFormat': str,
    'alertDetailsOverride.alertDescriptionFormat': str,
    'alertDetailsOverride.alertTacticsColumnName': str,
    'alertDetailsOverride.alertSeverityColumnName': str
}

# Default Sentinel schema for KQL validation
# This is a basic schema - users should provide their own for complete validation
SENTINEL_SCHEMA = {
    "database": "SecurityInsights",
    "tables": {
        "SecurityEvent": {
            "columns": {
                "TimeGenerated": "datetime",
                "Computer": "string",
                "Account": "string",
                "EventID": "int",
                "CommandLine": "string",
                "ProcessName": "string",
                "WorkstationName": "string",
                "IpAddress": "string",
                "LogonType": "int"
            }
        },
        "SigninLogs": {
            "columns": {
                "TimeGenerated": "datetime",
                "UserPrincipalName": "string",
                "IPAddress": "string",
                "Location": "string",
                "AppDisplayName": "string",
                "ClientAppUsed": "string",
                "ConditionalAccessStatus": "string",
                "ResultType": "string",
                "ResultDescription": "string"
            }
        },
        "AuditLogs": {
            "columns": {
                "TimeGenerated": "datetime",
                "OperationName": "string",
                "Category": "string",
                "ResultType": "string",
                "InitiatedBy": "dynamic",
                "TargetResources": "dynamic"
            }
        },
        "CommonSecurityLog": {
            "columns": {
                "TimeGenerated": "datetime",
                "DeviceVendor": "string",
                "DeviceProduct": "string",
                "DeviceAction": "string",
                "SourceIP": "string",
                "DestinationIP": "string",
                "SourcePort": "int",
                "DestinationPort": "int",
                "Protocol": "string"
            }
        },
        "Syslog": {
            "columns": {
                "TimeGenerated": "datetime",
                "Computer": "string",
                "Facility": "string",
                "SeverityLevel": "string",
                "SyslogMessage": "string",
                "ProcessName": "string",
                "HostIP": "string"
            }
        }
    }
}
