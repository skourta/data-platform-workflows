import os
import re


BASE_DIR = os.path.normpath(f"{os.path.dirname(__file__)}/../..")
TOKENS_DIR = f"{BASE_DIR}/secscan-tokens"
RESULTS_DIR = f"{BASE_DIR}/secscan-results"
CSV_DELIMITER = ","

UBUNTU_CVE_API_URL = "https://ubuntu.com/security/cves/{}.json"
UBUNTU_CVE_INFO_URL = "https://ubuntu.com/security/{}"
MITRE_CVE_API_URL = "https://cveawg.mitre.org/api/cve/{}"
MITRE_CVE_INFO_URL = "https://www.cve.org/CVERecord?id={}"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
NVD_PATCH_SCORE_THRESHOLD = 60

KEV_REFERENCE_SUFFIX = "cisa.gov/known-exploited-vulnerabilities-catalog"
CVE_UNKNOWN_VALUE = "UNKNOWN"
CVE_NOT_IN_UBUNTU_STATUS = "not-in-ubuntu"
CVE_REGEX = re.compile(r"CVE-\d+-\d+")
CVE_CSV_HEADERS = [
    "CVE",
    "Known Exploited Vulnerability",
    "Severity",
    "CVSS3",
    "Description",
    "Ubuntu Security Link",
    "Affected Component",
    "Notification Source",
    "Relevant to Product",
    "Affected Releases",
    "Can it be remediated?",
    "Does a patch exist?",
    "Patch Source",
    "Details",
    "Remediation Status",
    "Patched Release",
    "Timestamp",
    "Jira Ticket",
    # The below are not part of the Vuln tracker template
    "CVE.org Link",
    "Published",
]
