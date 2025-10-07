"""
Entity Identifiers
Defines strong identifiers for each entity type in Microsoft Sentinel.
Reference: https://learn.microsoft.com/en-us/azure/sentinel/entities-reference
"""

ENTITY_STRONG_IDENTIFIERS = {
    "Account": [
        "Name",
        "FullName",
        "NTDomain",
        "DnsDomain",
        "UPNSuffix",
        "Sid",
        "AadUserId",
        "AadTenantId",
        "ObjectGuid",
        "PUID"
    ],
    
    "Host": [
        "FullName",
        "DnsDomain",
        "NTDomain",
        "HostName",
        "NetBiosName",
        "AzureID",
        "OMSAgentID",
        "OSFamily",
        "OSVersion"
    ],
    
    "IP": [
        "Address"
    ],
    
    "Malware": [
        "Name",
        "Category"
    ],
    
    "File": [
        "Name",
        "Directory",
        "FileHashType",
        "FileHashValue"
    ],
    
    "Process": [
        "ProcessId",
        "CommandLine",
        "ElevationToken",
        "CreationTimeUtc"
    ],
    
    "CloudApplication": [
        "AppId",
        "Name",
        "InstanceName"
    ],
    
    "DNS": [
        "DomainName"
    ],
    
    "AzureResource": [
        "ResourceId"
    ],
    
    "FileHash": [
        "Algorithm",
        "Value"
    ],
    
    "RegistryKey": [
        "Hive",
        "Key"
    ],
    
    "RegistryValue": [
        "Name",
        "Value",
        "ValueType"
    ],
    
    "SecurityGroup": [
        "DistinguishedName",
        "SID",
        "ObjectGuid"
    ],
    
    "URL": [
        "Url"
    ],
    
    "IoTDevice": [
        "DeviceId",
        "DeviceName",
        "Source",
        "IoTSecurityAgentId"
    ],
    
    "MailCluster": [
        "NetworkMessageIds",
        "CountByDeliveryStatus",
        "CountByThreatType",
        "CountByProtectionStatus",
        "Threats",
        "Query",
        "QueryTime",
        "MailCount",
        "Source"
    ],
    
    "MailMessage": [
        "NetworkMessageId",
        "Recipient",
        "Urls",
        "Threats",
        "Sender",
        "P1Sender",
        "P2Sender",
        "Subject",
        "BodyFingerprintBin1",
        "AntispamDirection",
        "DeliveryAction",
        "DeliveryLocation"
    ],
    
    "Mailbox": [
        "MailboxPrimaryAddress",
        "DisplayName",
        "Upn",
        "ExternalDirectoryObjectId"
    ],
    
    "SubmissionMail": [
        "SubmissionId",
        "Submitter",
        "NetworkMessageId",
        "Recipient",
        "Sender",
        "Subject"
    ]
}
