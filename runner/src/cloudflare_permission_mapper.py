"""
Map the Cloudflare API token permission required for each Terraform operation
"""

# Map of each operation to the Cloudflare API token permission required
operation_permissions_map = {
    "account": {
        "read": [
            "Account Rulesets Read",
        ],
        "write": [
            "Account Rulesets Write",
        ],
    },
    "zone": {
        "read": [
            "Zone Read",
        ],
        "write": [
            "Zone Write",
            "Billing Write",
        ],
    },
    "cdn": {
        "read": [
            "Zone Read",
            "DNS Read",
            "Managed headers Read",
            "Cache Settings Read",
            "Config Settings Read",
            "Origin Read",
            "Page Rules Read",
            "Dynamic URL Redirects Read",
        ],
        "write": [
            "Zone Read",
            "DNS Write",
            "Managed headers Write",
            "Cache Settings Write",
            "Config Settings Write",
            "Origin Write",
            "Page Rules Write",
            "Dynamic URL Redirects Write",
        ],
    },
    "security": {
        "read": [
            "Zone Read",
            "Zone WAF Read",
        ],
        "write": [
            "Zone Read",
            "Zone WAF Write",
        ],
    },
    "tls": {
        "read": [
            "Zone Read",
            "SSL and Certificates Read",
        ],
        "write": [
            "Zone Read",
            "SSL and Certificates Write",
        ],
    },
    "cert": {
        "read": [
            "Account: SSL and Certificates Read",  # Account level CSR
            "SSL and Certificates Read",
            "Zone Read",
        ],
        "write": [
            "Account: SSL and Certificates Write",  # Account level CSR
            "SSL and Certificates Write",
            "Zone Read",
        ],
    },
}


# Map of each operation and the level at which the operation is performed. Either account or zone
operation_level_map = {
    "account": "account",
    "zone": "account",
    "cdn": "zone",
    "security": "zone",
    "tls": "zone",
    "cert": "account",  # Account level CSR
}
