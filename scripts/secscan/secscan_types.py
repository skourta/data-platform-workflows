import logging
import os
import re
import typing

from dataclasses import dataclass
from datetime import datetime
from dateutil.parser import parse
from enum import Enum

from constants import (
    CVE_UNKNOWN_VALUE,
    KEV_REFERENCE_SUFFIX,
    CSV_DELIMITER,
    UBUNTU_CVE_INFO_URL,
    MITRE_CVE_INFO_URL,
    CVE_CSV_HEADERS,
    NVD_PATCH_SCORE_THRESHOLD,
)


logging.basicConfig(
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


class ArtifactType(str, Enum):
    charm = "charm"
    oci   = "oci"
    snap  = "snap"

class ScannerType(str, Enum):
    blackduck = "blackduck"
    trivy     = "trivy"
    osv       = "osv"

class ScannerArtifactType(str, Enum):
    package         = "package"
    container_image = "container-image"

@dataclass(frozen=True)
class Scanner:
    value: str
    report_extension: str

    def __init__(self, scanner_type: ScannerType):
        if scanner_type not in ScannerType:
            raise ValueError(f"Invalid scanner value: {scanner_type}")

        match scanner_type:
            case ScannerType.blackduck:
                report_extension = "json"
            case ScannerType.trivy:
                report_extension = "html"
            case _:
                report_extension = "txt"

        # Frozen dataclass fields cannot be set directly, even in __init__
        super().__setattr__("value", scanner_type.value)
        super().__setattr__("report_extension", report_extension)


def parse_mitre_metrics_from_containers(containers: dict[str, typing.Any]) -> tuple[str, str]:
    """
    Parse CVSS and seveiry metrics from the given MITRE API JSON containers.
    Both unparsed CVSS3 score and severity are returned as strings.

    The MITRE API returns metrics with different keys depending on the CVE that
     all start with cvssv3. These metrics can be located in any container.
    """
    raw_cvss3 = "0.0"
    severity = CVE_UNKNOWN_VALUE
    candidate_metrics = []
    for key, container in containers.items():
        # Some containers contain maps of metrics, others contain lists of them
        if isinstance(container, dict):
            for metric in container.get("metrics", {}):
                for key, value in metric.items():
                    if "cvssv3" in key.lower():
                        candidate_metrics.append(value)
        elif isinstance(container, list):
            for item in container:
                if "metrics" in item:
                    for metric in item["metrics"]:
                        for key, value in metric.items():
                            if "cvssv3" in key.lower():
                                candidate_metrics.append(value)

    for candidate in candidate_metrics:
        raw_cvss3 = candidate.get("baseScore", "0.0")
        severity = candidate.get("baseSeverity", CVE_UNKNOWN_VALUE)
        if raw_cvss3 != "0.0" and severity != CVE_UNKNOWN_VALUE:
            return raw_cvss3, severity

    return raw_cvss3, severity

@dataclass(frozen=True)
class CVEData:
    id: str
    cvss3: float
    severity: str
    is_kev: bool
    patch_exists: bool
    patch_source: str
    published: datetime
    description: str
    ubuntu_security_link: str
    cve_org_link: str
    # Internal field, only used for checking whether the Ubuntu Security API
    # contains data about a CVE
    status: str = CVE_UNKNOWN_VALUE

    @classmethod
    def from_ubuntu_api_json(cls, cve_id: str, api_json: dict[str, typing.Any]) -> "CVEData":
        """Create a new CVEData object from an Ubuntu Security API JSON dict."""
        # The CVE API returns missing values as the key names mapped to null,
        # which ismapped to None in the parsed JSON. This means that we need to
        # set the default value after getting it from the JSON instead of as the
        # second argument passed to .get() calls.
        raw_cvss3 = api_json.get("cvss3") or "0.0"
        raw_published = api_json.get("published") or "1970-01-01"
        impact = api_json.get("impact") or {}
        base_metric = impact.get("baseMetricV3") or {}
        cvss3_metric = base_metric.get("cvssV3") or {}
        severity = cvss3_metric.get("baseSeverity") or CVE_UNKNOWN_VALUE
        raw_description = api_json.get("description") or ""

        references: list[str] = api_json.get("references") or []

        return cls(
            id = cve_id,
            cvss3 = float(raw_cvss3),
            severity = severity.upper(),
            is_kev = any(ref.lower().endswith(KEV_REFERENCE_SUFFIX) for ref in references),
            description = raw_description.strip().replace(CSV_DELIMITER, " "),
            # Set status to indicate whether the Ubuntu Security API contains
            # information about this vulnerability.
            status = api_json.get("status") or CVE_UNKNOWN_VALUE,
            published = parse(raw_published),
            ubuntu_security_link = UBUNTU_CVE_INFO_URL.format(cve_id),
            cve_org_link = MITRE_CVE_INFO_URL.format(cve_id),
            patch_exists = False,
            patch_source = "",
        )

    @classmethod
    def from_mitre_api_json(cls, cve_id: str, api_json: dict[str, typing.Any]) -> "CVEData":
        """Create a new CVEData object from a MITRE API JSON dict."""
        raw_published = api_json.get("datePublished", "1970-01-01")
        containers = api_json.get("containers", {})
        raw_cvss3, severity = parse_mitre_metrics_from_containers(containers)

        if severity == CVE_UNKNOWN_VALUE:
            logger.error("MITRE API returned empty severity for %s", cve_id)

        if raw_cvss3 == CVE_UNKNOWN_VALUE:
            logger.error("MITRE API returned empty CVSS3 score for %s", cve_id)

        raw_description = CVE_UNKNOWN_VALUE
        descriptions = api_json.get("containers", {}).get("cna", {}).get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang", "") == "en":
                raw_description = desc.get("value", CVE_UNKNOWN_VALUE)

        is_kev = False
        adp = api_json.get("containers", {}).get("adp", [])

        # The 'adp' array contains different objects, we need the 'metrics' one
        for adp_item in adp:
            if adp_item.get("metrics"):
                for metric in adp_item["metrics"]:
                    if metric.get("other", {}).get("type", "") == "kev":
                        is_kev = True

        return cls(
            id = cve_id,
            cvss3 = float(raw_cvss3),
            severity = severity.upper(),
            is_kev = is_kev,
            description = raw_description.strip().replace(CSV_DELIMITER, " "),
            published = parse(raw_published),
            ubuntu_security_link = UBUNTU_CVE_INFO_URL.format(cve_id),
            cve_org_link = MITRE_CVE_INFO_URL.format(cve_id),
            patch_exists = False,
            patch_source = "",
        )

    @classmethod
    def from_nvd_api_json(cls, cve_id: str, api_json: dict[str, typing.Any]) -> "CVEData":
        """Create a new CVEData object from a NVD API JSON dict."""
        vulns = api_json.get("vulnerabilities")
        if not len(vulns):
            logger.error(f"NVD API returned empty severity for {cve_id}")

        cve_obj = (vulns[0] or {}).get("cve") or {}

        # Fetch published date and description, which are not always present in the NVD API response. If they are missing, use default values.
        raw_published = cve_obj.get("published") or "1970-01-01"
        raw_description = CVE_UNKNOWN_VALUE
        descriptions = cve_obj.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang", "") == "en":
                raw_description = desc.get("value", CVE_UNKNOWN_VALUE)

        # Track any “patch-ish” evidence even if we don’t find a strong best URL
        saw_patch_tag = False
        saw_vendor_advisory_tag = False

        # Fetch references and check for any that look like they might be patch links, either based on their tags or their URLs.
        # If we find any strong candidates, we can mark the CVE as having a patch available even if there isn’t an explicit tag saying so.
        for ref in (cve_obj.get("references") or []):
            if not isinstance(ref, dict):
                continue
            url = (ref.get("url") or "").strip()
            tags = ref.get("tags") or []
            tags_l = [t.lower() for t in tags if isinstance(t, str)]

            if any("patch" in t for t in tags_l):
                saw_patch_tag = True
            if any("vendor advisory" in t for t in tags_l):
                saw_vendor_advisory_tag = True

            if not url:
                continue

            best_url = ""
            best_score = 0
            s = _get_nvd_reference_score(url, tags if isinstance(tags, list) else [])
            if s > best_score:
                best_score = s
                best_url = url

        # Based on the tags and URLs of the references, determine whether a patch likely exists for this CVE.
        # We use a heuristic score to determine this, but any explicit patch tag or vendor advisory tag is sufficient on its own.
        patch_exists = False
        if saw_patch_tag or saw_vendor_advisory_tag or best_score >= NVD_PATCH_SCORE_THRESHOLD:
            patch_exists = True

        patch_source = ""
        if best_url and best_score >= NVD_PATCH_SCORE_THRESHOLD:
            patch_source = best_url

        # Extract severity and CVSS3 score from the metrics containers
        metrics = cve_obj.get("metrics", {})
        nvd_sev = CVE_UNKNOWN_VALUE
        nvd_score = 0.0
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            arr = metrics.get(key) or []
            if arr:
                sev = (arr[0].get("cvssData") or {}).get("baseSeverity")
                if sev:
                    nvd_sev = sev.capitalize()
                    nvd_score = (arr[0].get("cvssData") or {}).get("baseScore", 0.0)
                    break

        return cls(
            id = cve_id,
            cvss3 = nvd_score,
            severity = nvd_sev,
            is_kev=False,
            published = parse(raw_published),
            description = raw_description.strip().replace(CSV_DELIMITER, " "),
            ubuntu_security_link = UBUNTU_CVE_INFO_URL.format(cve_id),
            cve_org_link = MITRE_CVE_INFO_URL.format(cve_id),
            patch_exists = patch_exists,
            patch_source = patch_source,
        )

    @classmethod
    def failed_fetch(cls, cve_id: str) -> "CVEData":
        """Create a new CVEData object for a failed data fetch."""
        return cls(
            id = cve_id,
            cvss3 = 0.0,
            severity = CVE_UNKNOWN_VALUE,
            is_kev=False,
            published = datetime.min,
            description = CVE_UNKNOWN_VALUE,
            ubuntu_security_link = UBUNTU_CVE_INFO_URL.format(cve_id),
            cve_org_link = MITRE_CVE_INFO_URL.format(cve_id),
            patch_exists = False,
            patch_source = CVE_UNKNOWN_VALUE,
        )

    @classmethod
    def from_csv_row(cls, row: dict[str, str]) -> "CVEData":
        """Create a new CVEData object from a CSV row."""
        return cls(
            id = row[CVE_CSV_HEADERS[0]],
            is_kev = row[CVE_CSV_HEADERS[1]].lower() == "yes",
            severity = row[CVE_CSV_HEADERS[2]],
            cvss3 = float(row[CVE_CSV_HEADERS[3]]),
            description = row[CVE_CSV_HEADERS[4]],
            ubuntu_security_link = row[CVE_CSV_HEADERS[5]],
            cve_org_link = row[CVE_CSV_HEADERS[18]],
            patch_exists = row[CVE_CSV_HEADERS[11]].lower() == "yes",
            patch_source = row[CVE_CSV_HEADERS[12]],
            published = parse(row[CVE_CSV_HEADERS[19]]),
        )

    @classmethod
    def merge(cls, data: typing.Optional["CVEData"], other: typing.Optional["CVEData"]) -> "CVEData":
        """Merge fields with 'other', using the higher quality values."""
        severity = data.severity
        if severity == CVE_UNKNOWN_VALUE:
            severity = other.severity

        description = data.description
        if description == CVE_UNKNOWN_VALUE:
            description = other.description

        return cls(
            id = data.id,
            cvss3 = max([data.cvss3, other.cvss3]),
            severity = severity.capitalize() if severity != CVE_UNKNOWN_VALUE else CVE_UNKNOWN_VALUE,
            is_kev=data.is_kev or other.is_kev,
            patch_exists = data.patch_exists or other.patch_exists,
            patch_source = data.patch_source or other.patch_source,
            published = max(data.published, other.published),
            description = description,
            ubuntu_security_link = data.ubuntu_security_link,
            cve_org_link = data.cve_org_link,
        )

    def to_csv_row(self) -> dict[str, str]:
        """Return the CSV representation of this object."""
        return {
            CVE_CSV_HEADERS[0]: self.id,
            CVE_CSV_HEADERS[1]: "Yes" if self.is_kev else "No",
            CVE_CSV_HEADERS[2]: self.severity,
            CVE_CSV_HEADERS[3]: str(self.cvss3),
            CVE_CSV_HEADERS[4]: self.description,
            CVE_CSV_HEADERS[5]: self.ubuntu_security_link or self.cve_org_link,
            # CVE_CSV_HEADERS[6]: "", # Affected Component is populated in aggregate_scan_results step
            # CVE_CSV_HEADERS[7]: "", # Notification Source is populated in aggregate_scan_results step
            CVE_CSV_HEADERS[8]: "", # Relevant to Product is not a property of CVEData, it needs to be filled in separately based on the scan results
            # CVE_CSV_HEADERS[9]: "", # Affected Releases is populated in aggregate_scan_results step
            CVE_CSV_HEADERS[10]: "Yes" if self.patch_exists else "No",
            CVE_CSV_HEADERS[11]: "Yes" if self.patch_exists else "No",
            CVE_CSV_HEADERS[12]: self.patch_source,
            CVE_CSV_HEADERS[13]: "", # Details
            CVE_CSV_HEADERS[14]: "Pending", # Remediation Status
            CVE_CSV_HEADERS[15]: "", # Patched Release is not a property of CVEData, it needs to be filled in separately based on the scan results
            CVE_CSV_HEADERS[16]: "", # Timestamp is not a property of CVEData, it needs to be filled in separately based on the scan results
            CVE_CSV_HEADERS[17]: "", # Jira Ticket is not a property of CVEData, it needs to be filled in separately based on the scan results
            CVE_CSV_HEADERS[18]: self.cve_org_link,
            CVE_CSV_HEADERS[19]: self.published.strftime("%Y-%m-%d"),
        }

@dataclass(frozen=True)
class ArtifactProperties:
    scanners:      list[Scanner]
    artifact_type: ScannerArtifactType
    filename:      str
    version:       str

    def __post_init__(self):
        if self.filename != "" and self.version == "":
            raise ValueError(f"Version not set for the {self.artifact_type.value} {self.filename}")

type StageTasks = dict[ArtifactType, list[Scanner]]

class Stage(str, Enum):
    submit    = "submit"
    wait      = "wait"
    result    = "result"
    report    = "report"
    log       = "log"
    enrich    = "enrich"
    aggregate = "aggregate"

def _get_nvd_reference_score(url: str, tags: list[str]) -> int:
    """
    Return a heuristic score indicating how likely a reference points to
    an official vulnerability patch.
    """
    url_l = (url or "").lower()
    tags_l = [t.lower() for t in tags if isinstance(t, str)]

    score = 0

    # Tag-based
    if any("patch" in t for t in tags_l):
        score += 80
    if any("vendor advisory" in t for t in tags_l):
        score += 60
    if any("release notes" in t for t in tags_l):
        score += 40
    if any("third party advisory" in t for t in tags_l):
        score += 20

    # URL heuristics
    patterns = [
        (r"/security/advisories/", 70),
        (r"/commit/", 55),
        (r"/compare/", 35),
        (r"/releases/", 35),
        (r"/advisories/", 45),
        (r"/security", 25),
        (r"patch", 25),
        (r"hotfix", 25),
        (r"release", 10),
        (r"advisory", 10),
    ]
    for pat, pts in patterns:
        if re.search(pat, url_l):
            score += pts

    if any(h in url_l for h in ["github.com", "gitlab.com", "bitbucket.org"]):
        score += 8

    return score
