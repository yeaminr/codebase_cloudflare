"""
Map the Cloudflare API token permission required for each Terraform operation
"""

# Map of each operation to the Cloudflare API token permission required
operation_permissions_map = {
    "account": {
        "read": [
            {"name": "Account Rule Lists Read", "scope": "account"},
            {"name": "Access: Mutual TLS Certificates Read", "scope": "account"},
            {"name": "Access: Apps and Policies Read", "scope": "account"},
            {"name": "Workers Scripts Read", "scope": "account"}
        ],
        "write": [
            {"name": "Account Rule Lists Write", "scope": "account"},
            {"name": "Workers Scripts Write", "scope": "account"}
        ],
    },
    "zone": {
        "read": [
            {"name": "Zone Read", "scope": "zone"},
            {"name": "DNS Read", "scope": "zone"},
            {"name": "Managed headers Read", "scope": "zone"},
            {"name": "Cache Settings Read", "scope": "zone"},
            {"name": "Config Settings Read", "scope": "zone"},
            {"name": "Origin Read", "scope": "zone"},
            {"name": "Page Rules Read", "scope": "zone"},
            {"name": "Dynamic URL Redirects Read", "scope": "zone"},
            {"name": "Zone WAF Read", "scope": "zone"},
            {"name": "SSL and Certificates Read", "scope": "zone"},
            {"name": "Workers Routes Read", "scope": "zone"},
            {"name": "Zone Settings Read", "scope": "zone"},
        ],
        "write": [
            {"name": "Zone Write", "scope": "zone"},
            {"name": "Billing Write", "scope": "account"},
            {"name": "Workers Routes Write", "scope": "zone"},
            {"name": "Zone Settings Write", "scope": "zone"},
            {"name": "Notifications Write", "scope": "account"},
            {"name": "Logs Write", "scope": "zone"}
        ],
    },
    "cdn": {
        "read": [
            {"name": "Zone Read", "scope": "zone"},
            {"name": "DNS Read", "scope": "zone"},
            {"name": "Managed headers Read", "scope": "zone"},
            {"name": "Cache Settings Read", "scope": "zone"},
            {"name": "Config Settings Read", "scope": "zone"},
            {"name": "Origin Read", "scope": "zone"},
            {"name": "Page Rules Read", "scope": "zone"},
            {"name": "Dynamic URL Redirects Read", "scope": "zone"},
            {"name": "Zone Transform Rules Read", "scope": "zone"},
            {"name": "Sanitize Read", "scope": "zone"},
            {"name": "Zone WAF Read", "scope": "zone"},
            {"name": "Zone Settings Read", "scope": "zone"},
            {"name": "Custom Pages Read", "scope": "zone"},
            {"name": "Response Compression Read", "scope": "zone"},
        ],
        "write": [
            {"name": "Zone Read", "scope": "zone"},
            {"name": "DNS Write", "scope": "zone"},
            {"name": "Managed headers Write", "scope": "zone"},
            {"name": "Cache Settings Write", "scope": "zone"},
            {"name": "Config Settings Write", "scope": "zone"},
            {"name": "Origin Write", "scope": "zone"},
            {"name": "Page Rules Write", "scope": "zone"},
            {"name": "Dynamic URL Redirects Write", "scope": "zone"},
            {"name": "Zone Transform Rules Write", "scope": "zone"},
            {"name": "Sanitize Write", "scope": "zone"},
            {"name": "Zone WAF Write", "scope": "zone"},
            {"name": "Zone Settings Write", "scope": "zone"},
            {"name": "Custom Pages Write", "scope": "zone"},
            {"name": "Response Compression Write", "scope": "zone"},
        ],
    },
    "security": {
        "read": [
            {"name": "Account Rulesets Read", "scope": "account"},
            {"name": "Billing Read", "scope": "account"},
            {"name": "Account Settings Read", "scope": "account"},
            {"name": "Account Rule Lists Read", "scope": "account"},
            {"name": "Zone Read", "scope": "zone"},
            {"name": "Zone WAF Read", "scope": "zone"},
            {"name": "Bot Management Read", "scope": "zone"},
            {"name": "DNS Read", "scope": "zone"},
            {"name": "Logs Read", "scope": "zone"},
            {"name": "Logs Write", "scope": "zone"}, # Log write permission is required for read operation
        ],
        "write": [
            {"name": "Account Rulesets Write", "scope": "account"},
            {"name": "Billing Write", "scope": "account"},
            {"name": "Account Settings Write", "scope": "account"},
            {"name": "Account Rule Lists Write", "scope": "account"},
            {"name": "Zone Write", "scope": "zone"},
            {"name": "Zone WAF Write", "scope": "zone"},
            {"name": "Bot Management Write", "scope": "zone"},
            {"name": "DNS Write", "scope": "zone"},
            {"name": "Logs Write", "scope": "zone"},
        ],
    },
    "tls": {
        "read": [
            {"name": "Zone Read", "scope": "zone"},
            {"name": "SSL and Certificates Read", "scope": "zone"},
            {"name": "Zone Settings Read", "scope": "zone"},
        ],
        "write": [
            {"name": "Zone Read", "scope": "zone"},
            {"name": "SSL and Certificates Write", "scope": "zone"},
            {"name": "Zone Settings Write", "scope": "zone"},
        ],
    },
    "cert": {
        "read": [
            {"name": "Account: SSL and Certificates Read", "scope": "account"},  # Account level CSR
            {"name": "SSL and Certificates Read", "scope": "zone"},
            {"name": "Zone Read", "scope": "zone"},
        ],
        "write": [
            {"name": "Account: SSL and Certificates Write", "scope": "account"},  # Account level CSR
            {"name": "SSL and Certificates Write", "scope": "zone"},
            {"name": "Zone Read", "scope": "zone"},
        ],
    },
    "mtls": {
        "read": [
            {"name": "Access: Mutual TLS Certificates Read", "scope": "account"},
            {"name": "Access: Apps and Policies Read", "scope": "account"},
            {"name": "Zone Settings Read", "scope": "zone"},
            {"name": "SSL and Certificates Read", "scope": "zone"},
        ],
        "write": [
            {"name": "Access: Mutual TLS Certificates Write", "scope": "account"},
            {"name": "Access: Apps and Policies Write", "scope": "account"},
            {"name": "Zone Settings Write", "scope": "zone"},
            {"name": "SSL and Certificates Write", "scope": "zone"},
        ],
    },
    "workers": {
        "read": [
            {"name": "Workers Scripts Read", "scope": "account"},
            {"name": "Workers Routes Read", "scope": "zone"},
        ],
        "write": [
            {"name": "Workers Scripts Write", "scope": "account"},
            {"name": "Workers Routes Write", "scope": "zone"},
        ],
    },
    "app_list": {
        "read": [
            {"name": "Account Rule Lists Read", "scope": "account"},
            {"name": "Access: Mutual TLS Certificates Read", "scope": "account"},
            {"name": "Access: Apps and Policies Read", "scope": "account"}
        ],
        "write": [
            {"name": "Account Rule Lists Write", "scope": "account"}
        ],
    },
}


# Map of each operation and the level at which the operation is performed. Either account or zone
operation_level_map = {
    "account": "account",
    "zone": "account",
    "cdn": "zone",
    "security": "mixed",
    "tls": "zone",
    "cert": "account",  # Account level CSR
    "mtls": "account",
    "workers": "account",
    "app_list": "account",
}
