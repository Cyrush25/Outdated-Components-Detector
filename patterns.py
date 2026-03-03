"""
patterns.py - All regex patterns for JS library version detection in page source.

JS_PATTERNS: list of (regex, component_key) tuples.
  - regex         : pattern with one capture group for the version string
  - component_key : lowercase key matching an entry in component_db.COMPONENT_DB

The scanner runs every pattern against the full page body.
Per component, only the lowest detected version is kept (most security-relevant).

Adding detection for a new library:
  1. Add the library to component_db.COMPONENT_DB
  2. Add one or more (regex, "key") tuples here, grouped under a comment block
"""

JS_PATTERNS = [
    # jQuery core
    (r'jquery[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',             "jquery"),
    (r'[Jj][Qq]uery\s+v?(\d+\.\d+[\.\d]*)',                    "jquery"),
    (r'"jquery":\s*"(\d+\.\d+[\.\d]*)"',                       "jquery"),
    (r'jQuery\s+JavaScript\s+Library\s+v(\d+\.\d+[\.\d]*)',    "jquery"),
    (r'/*!.*?jQuery.*?v(\d+\.\d+[\.\d]*)',                      "jquery"),
    # jQuery UI
    (r'jquery[.-]ui[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',       "jquery-ui"),
    (r'jQuery UI - v(\d+\.\d+[\.\d]*)',                         "jquery-ui"),
    # jQuery Migrate
    (r'jquery[.-]migrate[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',  "jquery migrate"),
    (r'jQuery Migrate v(\d+\.\d+[\.\d]*)',                      "jquery migrate"),
    # Bootstrap
    (r'bootstrap[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.(?:js|css)',  "bootstrap"),
    (r'"bootstrap":\s*"(\d+\.\d+[\.\d]*)"',                    "bootstrap"),
    (r'Bootstrap\s+v(\d+\.\d+[\.\d]*)',                         "bootstrap"),
    # Moment.js
    (r'moment[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',             "moment"),
    (r'moment\.js\s+v?(\d+\.\d+[\.\d]*)',                       "moment"),
    (r'"moment":\s*"(\d+\.\d+[\.\d]*)"',                       "moment"),
    # Angular v2+
    (r'@angular/core.*?(\d+\.\d+[\.\d]*)',                      "angular"),
    (r'"@angular/core":\s*"[~^]?(\d+\.\d+[\.\d]*)"',           "angular"),
    # AngularJS 1.x
    (r'angular[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',            "angularjs"),
    (r'AngularJS\s+v(\d+\.\d+[\.\d]*)',                         "angularjs"),
    # React
    (r'react[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',              "react"),
    (r'"react":\s*"[~^]?(\d+\.\d+[\.\d]*)"',                   "react"),
    (r'React\.version\s*=\s*["\'](\d+\.\d+[\.\d]*)',           "react"),
    # Vue
    (r'vue[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',                "vue"),
    (r'"vue":\s*"[~^]?(\d+\.\d+[\.\d]*)"',                    "vue"),
    (r'Vue\.version\s*=\s*["\'](\d+\.\d+[\.\d]*)',             "vue"),
    # Lodash
    (r'lodash[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',             "lodash"),
    (r'Lodash\s+<https.*?>\s+(\d+\.\d+[\.\d]*)',               "lodash"),
    (r'"lodash":\s*"[~^]?(\d+\.\d+[\.\d]*)"',                 "lodash"),
    # Underscore
    (r'underscore[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',         "underscore"),
    (r'Underscore\.js\s+(\d+\.\d+[\.\d]*)',                    "underscore"),
    # Backbone
    (r'backbone[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',           "backbone"),
    # Handlebars
    (r'handlebars[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',         "handlebars"),
    (r'Handlebars\s+v(\d+\.\d+[\.\d]*)',                        "handlebars"),
    # Mustache
    (r'mustache[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',           "mustache"),
    # Modernizr
    (r'modernizr[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',          "modernizr"),
    # Core-JS
    (r'core-js[/-](\d+\.\d+[\.\d]*)',                           "core-js"),
    # Prototype.js
    (r'prototype[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',          "prototype"),
    # MooTools
    (r'mootools[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',           "mootools"),
    # Ember
    (r'ember[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',              "ember"),
    # D3
    (r'd3[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',                 "d3"),
    (r'"d3":\s*"[~^]?(\d+\.\d+[\.\d]*)"',                     "d3"),
    # Three.js
    (r'three[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',              "three"),
    # Knockout
    (r'knockout-(\d+\.\d+[\.\d]*)(?:\.min)?\.js',              "knockout"),
    # Swiper
    (r'swiper[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',             "swiper"),
    # Slick
    (r'slick[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',              "slick"),
    # DataTables
    (r'dataTables[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',         "datatables"),
    # Axios
    (r'axios[/-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',              "axios"),
    (r'"axios":\s*"[~^]?(\d+\.\d+[\.\d]*)"',                  "axios"),
    # Chart.js
    (r'chart[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',              "chart.js"),
    # Select2
    (r'select2[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',            "select2"),
    # Popper
    (r'popper[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',             "popper"),
    # Highlight.js
    (r'highlight[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',          "highlight.js"),
    # DOMPurify
    (r'DOMPurify[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',          "dompurify"),
    (r'purify[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',             "dompurify"),
    # CKEditor
    (r'ckeditor[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',           "ckeditor"),
    (r'CKEDITOR_VERSION\s*=\s*["\'](\d+\.\d+[\.\d]*)',         "ckeditor"),
    # TinyMCE
    (r'tinymce[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',            "tinymce"),
    (r'tinymce/(\d+\.\d+[\.\d]*)/',                            "tinymce"),
    # Font Awesome
    (r'font-awesome[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.css',      "font-awesome"),
    (r'fontawesome[.-](\d+\.\d+[\.\d]*)(?:\.min)?\.js',        "font-awesome"),
    (r'"@fortawesome/fontawesome[^"]*":\s*"[~^]?(\d+\.\d+[\.\d]*)"', "font-awesome"),
]
