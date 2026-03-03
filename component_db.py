"""
component_db.py
===============
Version database for client-side JS libraries and frontend frameworks.

Schema per entry:
    latest   : str  — current stable release
    min_safe : str  — oldest version with no known exploitable CVEs
    cves     : list — associated CVE identifiers (most critical first)

To add a new component:
    1. Add a key (lowercase, must match the name used in patterns.py)
    2. Fill in latest, min_safe, and any CVEs
    3. Add corresponding regex(es) to patterns.py
"""

COMPONENT_DB = {
    # ── jQuery family ──────────────────────────────────────────────────────
    "jquery": {
        "latest":   "3.7.1",
        "min_safe": "3.5.0",
        "cves": [
            "CVE-2020-11023",
            "CVE-2020-11022",
            "CVE-2019-11358",
            "CVE-2015-9251",
        ],
    },
    "jquery-ui": {
        "latest":   "1.14.1",
        "min_safe": "1.13.2",
        "cves": [
            "CVE-2022-31160",
            "CVE-2021-41184",
            "CVE-2021-41183",
            "CVE-2021-41182",
        ],
    },
    "jquery migrate": {
        "latest":   "3.4.1",
        "min_safe": "3.4.0",
        "cves": [],
    },

    # ── CSS / UI frameworks ────────────────────────────────────────────────
    "bootstrap": {
        "latest":   "5.3.3",
        "min_safe": "4.6.2",
        "cves": [
            "CVE-2019-8331",
            "CVE-2018-14041",
            "CVE-2018-14040",
            "CVE-2018-14042",
            "CVE-2016-10735",
        ],
    },
    "font-awesome": {
        "latest":   "6.5.2",
        "min_safe": "5.15.4",
        "cves": [],
    },
    "popper": {
        "latest":   "2.11.8",
        "min_safe": "2.10.0",
        "cves": [],
    },

    # ── Date / utility ────────────────────────────────────────────────────
    "moment": {
        "latest":   "2.30.1",
        "min_safe": "2.29.4",
        "cves": [
            "CVE-2022-31129",
            "CVE-2022-24785",
        ],
    },
    "lodash": {
        "latest":   "4.17.21",
        "min_safe": "4.17.21",
        "cves": [
            "CVE-2021-23337",
            "CVE-2020-28500",
            "CVE-2019-10744",
        ],
    },
    "underscore": {
        "latest":   "1.13.6",
        "min_safe": "1.13.0",
        "cves": ["CVE-2021-23358"],
    },
    "core-js": {
        "latest":   "3.37.0",
        "min_safe": "3.23.0",
        "cves": ["CVE-2023-26115"],
    },
    "axios": {
        "latest":   "1.7.2",
        "min_safe": "1.6.0",
        "cves": ["CVE-2023-45857"],
    },

    # ── MV* / SPA frameworks ──────────────────────────────────────────────
    "angular": {
        "latest":   "17.3.0",
        "min_safe": "14.0.0",
        "cves": [
            "CVE-2023-26117",
            "CVE-2022-25844",
        ],
    },
    "angularjs": {
        "latest":   "1.8.3",
        "min_safe": "1.8.0",
        "cves": [
            "CVE-2023-26117",
            "CVE-2022-25844",
            "CVE-2019-14863",
        ],
    },
    "react": {
        "latest":   "18.3.1",
        "min_safe": "17.0.0",
        "cves": [],
    },
    "vue": {
        "latest":   "3.4.21",
        "min_safe": "2.7.16",
        "cves": ["CVE-2023-46999"],
    },
    "ember": {
        "latest":   "5.6.0",
        "min_safe": "4.12.0",
        "cves": ["CVE-2021-41127"],
    },
    "backbone": {
        "latest":   "1.5.0",
        "min_safe": "1.4.1",
        "cves": [],
    },
    "knockout": {
        "latest":   "3.5.1",
        "min_safe": "3.5.1",
        "cves": ["CVE-2019-14862"],
    },

    # ── Templating ────────────────────────────────────────────────────────
    "handlebars": {
        "latest":   "4.7.8",
        "min_safe": "4.7.7",
        "cves": [
            "CVE-2021-23369",
            "CVE-2021-23383",
            "CVE-2019-20922",
        ],
    },
    "mustache": {
        "latest":   "4.2.0",
        "min_safe": "4.0.0",
        "cves": [],
    },

    # ── Legacy ────────────────────────────────────────────────────────────
    "prototype": {
        "latest":   "1.7.3",
        "min_safe": "1.7.3",
        "cves": ["CVE-2008-7220"],
    },
    "mootools": {
        "latest":   "1.6.0",
        "min_safe": "1.6.0",
        "cves": [],
    },
    "modernizr": {
        "latest":   "3.12.0",
        "min_safe": "3.12.0",
        "cves": [],
    },

    # ── Data / visualisation ──────────────────────────────────────────────
    "d3": {
        "latest":   "7.9.0",
        "min_safe": "7.0.0",
        "cves": [],
    },
    "three": {
        "latest":   "0.163.0",
        "min_safe": "0.150.0",
        "cves": [],
    },
    "chart.js": {
        "latest":   "4.4.3",
        "min_safe": "3.9.0",
        "cves": [],
    },

    # ── UI widgets / plugins ──────────────────────────────────────────────
    "swiper": {
        "latest":   "11.1.1",
        "min_safe": "8.0.0",
        "cves": [],
    },
    "slick": {
        "latest":   "1.8.1",
        "min_safe": "1.8.1",
        "cves": [],
    },
    "datatables": {
        "latest":   "2.0.7",
        "min_safe": "1.13.0",
        "cves": [],
    },
    "select2": {
        "latest":   "4.1.0-rc.0",
        "min_safe": "4.0.13",
        "cves": [],
    },
    "highlight.js": {
        "latest":   "11.9.0",
        "min_safe": "11.6.0",
        "cves": ["CVE-2021-23358"],
    },

    # ── Security-sensitive libs ───────────────────────────────────────────
    "dompurify": {
        "latest":   "3.1.5",
        "min_safe": "3.0.0",
        "cves": ["CVE-2024-45801"],
    },

    # ── Rich-text editors ─────────────────────────────────────────────────
    "ckeditor": {
        "latest":   "41.4.2",
        "min_safe": "38.0.0",
        "cves": ["CVE-2024-34129"],
    },
    "tinymce": {
        "latest":   "7.1.2",
        "min_safe": "6.0.0",
        "cves": ["CVE-2022-23494"],
    },
}
