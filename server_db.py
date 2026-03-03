"""
server_db.py
============
Version database for server-side software: web servers, runtimes, CMS platforms.

Schema per entry:
    latest   : str       - current stable release
    min_safe : str       - oldest version considered safe
    cves     : list      - associated CVE identifiers (most critical first)
    header   : str|None  - HTTP response header where the version is exposed
                           (None = detected via page body / meta tags)
    pattern  : str|None  - regex to extract the version from the header value
                           (single capture group for the version string)

Detection flow in the scanner:
    - header-based entries -> matched against the relevant response header
    - header=None entries  -> matched against page body via SERVER_BODY_PATTERNS

To add a new server/CMS:
    1. Add an entry to SERVER_DB
    2. If header-based: set header + pattern
    3. If body-based:   set header=None/pattern=None, add regex to SERVER_BODY_PATTERNS
"""

# Header-detected servers and runtimes
SERVER_DB = {
    "nginx": {
        "latest":   "1.25.5",
        "min_safe": "1.24.0",
        "cves": [
            "CVE-2024-24989",
            "CVE-2022-41741",
            "CVE-2019-9511",
        ],
        "header":  "server",
        "pattern": r"nginx[/ ](\d+\.\d+[\.\d]*)",
    },
    "apache": {
        "latest":   "2.4.59",
        "min_safe": "2.4.51",
        "cves": [
            "CVE-2023-31122",
            "CVE-2021-41773",
            "CVE-2021-42013",
        ],
        "header":  "server",
        "pattern": r"Apache[/ ](\d+\.\d+[\.\d]*)",
    },
    "iis": {
        "latest":   "10.0",
        "min_safe": "10.0",
        "cves": [
            "CVE-2022-21907",
            "CVE-2021-31166",
        ],
        "header":  "server",
        "pattern": r"Microsoft-IIS[/ ](\d+\.\d+)",
    },
    "php": {
        "latest":   "8.3.6",
        "min_safe": "8.1.0",
        "cves": [
            "CVE-2024-4577",
            "CVE-2023-3824",
            "CVE-2022-31628",
        ],
        "header":  "x-powered-by",
        "pattern": r"PHP[/ ](\d+\.\d+[\.\d]*)",
    },
    "drupal": {
        "latest":   "10.2.5",
        "min_safe": "10.0.0",
        "cves": [
            "CVE-2023-31250",
            "CVE-2022-25275",
        ],
        "header":  "x-generator",
        "pattern": r"Drupal\s*(\d+[\.\d]*)",
    },
    "openssl": {
        "latest":   "3.3.0",
        "min_safe": "3.0.0",
        "cves": [
            "CVE-2024-0727",
            "CVE-2023-5363",
        ],
        "header":  "server",
        "pattern": r"OpenSSL[/ ](\d+\.\d+[\.\d]*\w*)",
    },
    "lighttpd": {
        "latest":   "1.4.76",
        "min_safe": "1.4.70",
        "cves": ["CVE-2022-37797"],
        "header":  "server",
        "pattern": r"lighttpd[/ ](\d+\.\d+[\.\d]*)",
    },
    "tomcat": {
        "latest":   "10.1.24",
        "min_safe": "9.0.85",
        "cves": [
            "CVE-2023-46589",
            "CVE-2023-42794",
        ],
        "header":  "server",
        "pattern": r"(?:Apache-Coyote|Tomcat)[/ ](\d+\.\d+[\.\d]*)",
    },
    "akka-http": {
        "latest":   "10.6.2",
        "min_safe": "10.4.0",
        "cves": [],
        "header":  "server",
        "pattern": r"akka-http[/ ](\d+\.\d+[\.\d]*)",
    },
    "sun-one-web-server": {
        "latest":   "7.0",
        "min_safe": "7.0",
        "cves": ["CVE-2010-0361"],
        "header":  "server",
        "pattern": r"Sun-ONE-Web-Server[/ ](\d+\.\d+)",
    },
    # Body-detected CMS (header=None)
    "wordpress": {
        "latest":   "6.5.3",
        "min_safe": "6.4.0",
        "cves": ["CVE-2024-6307"],
        "header":  None,
        "pattern": None,
    },
    "joomla": {
        "latest":   "5.1.2",
        "min_safe": "4.4.0",
        "cves": ["CVE-2023-23752"],
        "header":  None,
        "pattern": None,
    },
}


# Body/meta-tag detection patterns
# Each tuple: (regex_with_optional_version_group_1, component_key)
# Group 1 is optional; if absent version is reported as "unknown"
SERVER_BODY_PATTERNS = [
    (r'<meta name="generator" content="WordPress (\d+\.\d+[\.\d]*)"', "wordpress"),
    (r'/wp-content/',  "wordpress"),
    (r'wp-includes/',  "wordpress"),
    (r'<meta name="generator" content="Joomla![^"]*?(?: Version (\d+\.\d+[\.\d]*))?', "joomla"),
    (r'/media/jui/',   "joomla"),
]
