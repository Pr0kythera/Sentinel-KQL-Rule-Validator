"""
ASIM Field Names
Defines valid ASIM (Advanced Security Information Model) normalized field names
for entity mappings.
Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-common-fields
"""

# Valid ASIM field names for User/Account entities
# These fields can have prefixes: Actor, Target, Src, Dst
ASIM_USER_FIELDS = [
    "Username",
    "UserId",
    "UserIdType",
    "UserType",
    "OriginalUserType",
    "UserScope",
    "UserScopeId",
    "SessionId",
    "Upn",               # User Principal Name
    "Domain",
    "DomainType",
    "EmailAddress",
]

# Valid ASIM field names for Host/Device entities
# These fields can have prefixes: Src, Dst, Dvc
ASIM_HOST_FIELDS = [
    "Hostname",
    "Domain",
    "DomainType",
    "FQDN",
    "Description",
    "Id",
    "IdType",
    "MacAddr",
    "IpAddr",
    "Zone",
    "Os",
    "OsVersion",
    "Action",
    "OriginalAction",
    "Interface",
    "ScopeId",
    "Scope",
    "Type",
]

# Valid ASIM field names for Process entities
# These fields can have prefixes: Acting, Target, Parent
ASIM_PROCESS_FIELDS = [
    "ProcessName",
    "ProcessId",
    "ProcessGuid",
    "ProcessCommandLine",
    "ProcessCreationTime",
    "ProcessIntegrityLevel",
    "ProcessTokenElevation",
    "ProcessFileCompany",
    "ProcessFileDescription",
    "ProcessFileProduct",
    "ProcessFileVersion",
    "ProcessFileInternalName",
    "ProcessFileOriginalName",
    "ProcessFileMD5",
    "ProcessFileSHA1",
    "ProcessFileSHA256",
    "ProcessFileSHA512",
    "ProcessCurrentDirectory",
    "ProcessStartTime",
    "ProcessEndTime",
]

# Valid ASIM field names for File entities
# These fields can have prefixes: Target, Src
ASIM_FILE_FIELDS = [
    "FileName",
    "FilePath",
    "FilePathType",
    "FileDirectory",
    "FileExtension",
    "FileMimeType",
    "FileSize",
    "FileCreationTime",
    "FileContentType",
    "FileMD5",
    "FileSHA1",
    "FileSHA256",
    "FileSHA512",
    "FileHashType",
]

# Valid ASIM field names for Registry entities
ASIM_REGISTRY_FIELDS = [
    "RegistryKey",
    "RegistryValue",
    "RegistryValueType",
    "RegistryValueData",
    "RegistryPreviousKey",
    "RegistryPreviousValue",
    "RegistryPreviousValueType",
    "RegistryPreviousValueData",
]

# Valid ASIM field names for Application entities
# These fields can have prefixes: Acting, Target
ASIM_APPLICATION_FIELDS = [
    "AppName",
    "AppId",
    "AppType",
]

# Valid ASIM field names for URL entities
ASIM_URL_FIELDS = [
    "Url",
    "UrlOriginal",
    "UrlHostname",
    "UrlDomain",
    "UrlCategory",
]

# Valid ASIM field names for Email entities
ASIM_EMAIL_FIELDS = [
    "EmailSubject",
    "EmailSenderAddress",
    "EmailRecipient",
    "EmailDirection",
    "EmailSenderName",
    "EmailRecipientName",
]

# Valid ASIM field names for DNS entities
ASIM_DNS_FIELDS = [
    "DnsQuery",
    "DnsQueryType",
    "DnsQueryTypeName",
    "DnsQueryClass",
    "DnsQueryClassName",
    "DnsResponseCode",
    "DnsResponseCodeName",
    "DnsResponseName",
    "DnsFlagsAuthenticated",
    "DnsFlagsAuthoritative",
    "DnsFlagsCheckingDisabled",
    "DnsFlagsRecursionAvailable",
    "DnsFlagsRecursionDesired",
    "DnsFlagsTruncated",
]

# Valid ASIM field names for Network entities
# These use Src, Dst prefixes for directional fields
ASIM_NETWORK_FIELDS = [
    "PortNumber",        # with Src, Dst prefixes
    "Bytes",             # with Src, Dst prefixes
    "Packets",           # with Src, Dst prefixes
    "VlanId",            # with Src, Dst, Inner, Outer prefixes
    "NetworkApplicationProtocol",
    "NetworkProtocol",
    "NetworkDirection",
    "NetworkDuration",
    "NetworkIcmpType",
    "NetworkIcmpCode",
    "NetworkConnectionHistory",
    "NetworkProtocolVersion",
    "NetworkRuleName",
    "NetworkRuleNumber",
]

# Valid ASIM field names for GeoLocation entities
# These fields can have prefixes: Src, Dst
ASIM_GEOLOCATION_FIELDS = [
    "GeoCountry",
    "GeoRegion",
    "GeoCity",
    "GeoLatitude",
    "GeoLongitude",
]

# Valid ASIM field names for Malware/Threat entities
ASIM_THREAT_FIELDS = [
    "ThreatName",
    "ThreatCategory",
    "ThreatId",
    "ThreatRiskLevel",
    "ThreatOriginalRiskLevel",
    "ThreatIpAddr",
    "ThreatField",
    "ThreatConfidence",
    "ThreatOriginalConfidence",
    "ThreatIsActive",
    "ThreatFirstReportedTime",
    "ThreatLastReportedTime",
]

# Valid ASIM field names for CloudApplication entities
ASIM_CLOUDAPP_FIELDS = [
    "CloudAppName",
    "CloudAppId",
    "CloudAppOperation",
    "CloudAppRiskLevel",
]

# Common prefixes used in ASIM
ASIM_PREFIXES = [
    "Actor",      # User performing action
    "Target",     # Target of action
    "Src",        # Source system
    "Dst",        # Destination system
    "Dvc",        # Reporting device
    "Acting",     # Acting process/application
    "Parent",     # Parent process
    "Inner",      # Inner VLAN
    "Outer",      # Outer VLAN
    "Local",      # Local endpoint
    "Remote",     # Remote endpoint
]

# Build comprehensive list of valid ASIM field names by combining prefixes with base field names
def build_asim_field_list():
    """
    Build complete list of valid ASIM field names.
    Returns a set of all valid field names including prefixed versions.
    """
    valid_fields = set()
    
    # Add unprefixed field names
    valid_fields.update(ASIM_REGISTRY_FIELDS)
    valid_fields.update(ASIM_URL_FIELDS)
    valid_fields.update(ASIM_EMAIL_FIELDS)
    valid_fields.update(ASIM_DNS_FIELDS)
    valid_fields.update(ASIM_NETWORK_FIELDS)
    valid_fields.update(ASIM_THREAT_FIELDS)
    valid_fields.update(ASIM_CLOUDAPP_FIELDS)
    
    # Add User fields with common prefixes
    for prefix in ["Actor", "Target", "Src", "Dst"]:
        for field in ASIM_USER_FIELDS:
            valid_fields.add(f"{prefix}{field}")
    
    # Add Host/Device fields with common prefixes
    for prefix in ["Src", "Dst", "Dvc"]:
        for field in ASIM_HOST_FIELDS:
            valid_fields.add(f"{prefix}{field}")
    
    # Add Process fields with common prefixes
    for prefix in ["Acting", "Target", "Parent"]:
        for field in ASIM_PROCESS_FIELDS:
            valid_fields.add(f"{prefix}{field}")
    
    # Add File fields with common prefixes
    for prefix in ["Target", "Src"]:
        for field in ASIM_FILE_FIELDS:
            valid_fields.add(f"{prefix}{field}")
    
    # Add Application fields with common prefixes
    for prefix in ["Acting", "Target"]:
        for field in ASIM_APPLICATION_FIELDS:
            valid_fields.add(f"{prefix}{field}")
    
    # Add GeoLocation fields with common prefixes
    for prefix in ["Src", "Dst"]:
        for field in ASIM_GEOLOCATION_FIELDS:
            valid_fields.add(f"{prefix}{field}")
    
    # Add network fields with Src/Dst prefixes where applicable
    for prefix in ["Src", "Dst"]:
        valid_fields.add(f"{prefix}PortNumber")
        valid_fields.add(f"{prefix}Bytes")
        valid_fields.add(f"{prefix}Packets")
        valid_fields.add(f"{prefix}VlanId")
    
    # Add special VLAN fields
    valid_fields.add("InnerVlanId")
    valid_fields.add("OuterVlanId")
    
    # Add commonly used standalone fields
    valid_fields.update([
        # Common standalone fields
        "User",
        "Computer",
        "IpAddr",
        "Hostname",
        "Application",
        
        # Event fields
        "EventType",
        "EventResult",
        "EventResultDetails",
        "EventMessage",
        "EventOriginalType",
        "EventOriginalResultDetails",
        
        # HTTP/Web session fields
        "HttpStatusCode",
        "HttpRequestMethod",
        "HttpVersion",
        "HttpUserAgent",
        "HttpReferrer",
        "HttpContentType",
        "HttpContentFormat",
        
        # Common Windows fields that may be used
        "Account",
        "AccountType",
        "LogonType",
        "SubjectUserName",
        "SubjectUserSid",
        "SubjectDomainName",
        "TargetUserName",
        "TargetUserSid",
        "TargetDomainName",
        "WorkstationName",
        "ImpersonationLevel",
        "PrivilegeList",
        
        # Rule/Alert fields
        "RuleName",
        "RuleNumber",
        "AlertName",
        "AlertSeverity",
    ])
    
    return valid_fields


# Build the complete list on module import
VALID_ASIM_FIELD_NAMES = build_asim_field_list()


# Entity type to expected field patterns mapping
# This helps provide more specific guidance in error messages
ENTITY_TO_ASIM_PATTERNS = {
    "Account": {
        "prefixes": ["Actor", "Target", "Src", "Dst"],
        "base_fields": ASIM_USER_FIELDS,
        "examples": ["ActorUsername", "TargetUsername", "ActorUserId", "SrcUsername"]
    },
    "Host": {
        "prefixes": ["Src", "Dst", "Dvc"],
        "base_fields": ASIM_HOST_FIELDS,
        "examples": ["SrcHostname", "DstHostname", "DvcIpAddr", "SrcIpAddr"]
    },
    "IP": {
        "prefixes": ["Src", "Dst", "Dvc"],
        "base_fields": ["IpAddr"],
        "examples": ["SrcIpAddr", "DstIpAddr", "DvcIpAddr"]
    },
    "Process": {
        "prefixes": ["Acting", "Target", "Parent"],
        "base_fields": ASIM_PROCESS_FIELDS,
        "examples": ["ActingProcessName", "TargetProcessId", "ActingProcessCommandLine"]
    },
    "File": {
        "prefixes": ["Target", "Src"],
        "base_fields": ASIM_FILE_FIELDS,
        "examples": ["TargetFileName", "SrcFilePath", "TargetFileSHA256"]
    },
    "URL": {
        "prefixes": [],
        "base_fields": ASIM_URL_FIELDS,
        "examples": ["Url", "UrlHostname", "UrlCategory"]
    },
    "DNS": {
        "prefixes": [],
        "base_fields": ASIM_DNS_FIELDS,
        "examples": ["DnsQuery", "DnsQueryType", "DnsResponseCode"]
    },
    "RegistryKey": {
        "prefixes": [],
        "base_fields": ASIM_REGISTRY_FIELDS,
        "examples": ["RegistryKey", "RegistryValue", "RegistryValueType"]
    },
    "RegistryValue": {
        "prefixes": [],
        "base_fields": ASIM_REGISTRY_FIELDS,
        "examples": ["RegistryValue", "RegistryValueType", "RegistryValueData"]
    },
    "Malware": {
        "prefixes": [],
        "base_fields": ASIM_THREAT_FIELDS,
        "examples": ["ThreatName", "ThreatCategory", "ThreatRiskLevel"]
    },
    "CloudApplication": {
        "prefixes": [],
        "base_fields": ASIM_CLOUDAPP_FIELDS,
        "examples": ["CloudAppName", "CloudAppId", "CloudAppOperation"]
    },
}
