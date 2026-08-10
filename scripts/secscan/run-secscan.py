import csv
import concurrent.futures
import io
import logging
import os
import re
import requests
import shutil
import subprocess
import typing

from collections import defaultdict
from functools import cache
from pathlib import Path
from requests.adapters import HTTPAdapter

from config import Config
from constants import (
    CSV_DELIMITER,
    MITRE_CVE_API_URL,
    UBUNTU_CVE_API_URL,
    RESULTS_DIR,
    TOKENS_DIR,
    CVE_REGEX,
    CVE_NOT_IN_UBUNTU_STATUS,
    CVE_UNKNOWN_VALUE,
    CVE_CSV_HEADERS,
    NVD_CVE_API_URL,
)
from secscan_types import (
    ArtifactType,
    Scanner,
    CVEData,
    StageTasks,
    Stage,
)

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    config = Config.from_env(logger)
except Exception as e:
    logger.error(f"Failed to load config with error : {e}")
    exit(1)


def get_token_filename(artifact: ArtifactType, scanner: Scanner) -> str:
    """Return the token filename given by the artifact and scanner names."""
    return f"{TOKENS_DIR}/{artifact.value}-{scanner.value}-token.txt"


def submit_scan(artifact: ArtifactType, scanner: Scanner) -> None:
    """
    Submit a vulnerability identification scan request for the given artifact
    and scanner.
    """
    token = get_token_filename(artifact, scanner)
    filename = config.artifact_properties[artifact].filename
    ssdlc_v12_enabled = config.product_name != ""

    logger.info(f"Submitting scan request with SSDLC v1.2 support \
{'enabled' if ssdlc_v12_enabled else 'disabled'} \
for {artifact.value} with scanner {scanner.value} at {filename}...")
    try:
        args = [
            "secscan-client",
            "--batch",
            "submit",
            "--scanner", scanner.value,
            "--type", config.artifact_properties[artifact].artifact_type.value,
            "--format", artifact.value,
            "--token", token,
            filename
        ]
        if ssdlc_v12_enabled:
            args.extend([
                "--ssdlc-product-name", config.product_name,
                "--ssdlc-product-version", config.artifact_properties[artifact].version,
                "--ssdlc-product-channel", config.release_channel,
                "--ssdlc-cycle", config.cycle,
            ])

        subprocess.run(args, check=True)
        logger.info(f"Successfully submitted scan request for {artifact.value} with scanner {scanner.value}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to submit scan request for {artifact.value} with scanner {scanner.value} with exit code {e.returncode}.")
        raise e


def wait_for_scan_completion(artifact: ArtifactType, scanner: Scanner) -> None:
    """
    Await the completion of a scan request specified by artifact and scanner.
    """
    token = get_token_filename(artifact, scanner)

    logger.info(f"Waiting for scan completion for {artifact.value} with scanner {scanner.value}...")
    try:
        subprocess.run(["secscan-client",
                        "--batch",
                        "wait",
                        "--token", token], check=True)
        logger.info(f"Successfully awaited scan completion for {artifact.value} with scanner {scanner.value}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to await scan completion for {artifact.value} with scanner {scanner.value} with exit code {e.returncode}.")
        raise e


def write_results_from_subprocess_result(result: typing.Union[subprocess.CompletedProcess, subprocess.CalledProcessError], file: io.TextIOWrapper) -> None:
    """Write the given subprocess result to the given file reference."""
    if result.stderr is not None and result.stderr.strip() != "":
        file.write(result.stderr)
    if result.stdout is not None and result.stdout.strip() != "":
        file.write(result.stdout)


def get_scan_result(artifact: ArtifactType, scanner: Scanner) -> None:
    """
    Get the result of a scan request specified by artifact and scanner.

    Scan results are saved in the top-level secscan-results directory in
     Contracts, separated by artifact type.

    False positives can be excluded by populating a text file with CVE
     identifiers, one per line, and supplying that in an environment variable (
     see config.py).
    """
    token = get_token_filename(artifact, scanner)

    logger.info(f"Retrieving scan results for {artifact.value} with scanner {scanner.value}...")
    res = None
    try:
        args = [
            "secscan-client",
            "--batch",
            "result",
            "--token", token
        ]
        if config.excluded_cves_file:
            args.append("--exclusions-filename")
            args.append(config.excluded_cves_file)
        res = subprocess.run(args,
                        check=True,
                        text=True,
                        # Capture all output.
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)

        if res.returncode == 0:
            # No CVEs found, and we did not list any as excluded that have not
            # been found by the scan.
            logger.info(f"Scan successful for {artifact.value} with scanner {scanner.value} with no CVEs and no unnecessary exclusions.")
    except subprocess.CalledProcessError as e:
        # Non-zero exit codes should not stop future tasks from running, so that
        # we can download relevant logs and full scan reports.
        if e.returncode == 101:
            # CVEs were found but we excluded ones that were not found, which is
            # okay, the tooling just warns us. We are using one exclusion file
            # for all scanner and artifact types, such warnings are expected.
            logger.warning(f"Scan successful for {artifact.value} with scanner {scanner.value} with unnecessary exclusions.")
        elif e.returncode >= 1 and e.returncode <= 99:
            logger.error(f"Scan failed for {artifact.value} with scanner {scanner.value} with a processing error {e.returncode}.")
        else:
            logger.info(f"Scan successful for {artifact.value} with scanner {scanner.value} with CVEs identified, secscan returned code {e.returncode}.")

        res = e

    with open(f"{RESULTS_DIR}/{artifact.value}/{artifact.value}_{scanner.value}_result.txt", "w") as f:
        write_results_from_subprocess_result(res, f)


def get_scan_report(artifact: ArtifactType, scanner: Scanner) -> None:
    """
    Get the report of a scan specified by artifact and scanner.

    Scan reports are saved in the top-level secscan-results directory in
     Contracts, separated by artifact type.
    """
    token = get_token_filename(artifact, scanner)

    logger.info(f"Retrieving scan report for {artifact.value} with scanner {scanner.value}...")
    res = None
    try:
        res = subprocess.run(["secscan-client",
                        "--batch",
                        "report",
                        "--token", token],
                        check=True,
                        text=True,
                        # Capture all output.
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)

        if res.returncode == 0:
            logger.info(f"Scan report successfully downloaded for {artifact.value} with scanner {scanner.value}.")

            with open(f"{RESULTS_DIR}/{artifact.value}/{artifact.value}_{scanner.value}_report.{scanner.report_extension}", "w") as f:
                write_results_from_subprocess_result(res, f)
    except subprocess.CalledProcessError as e:
        # Non-zero exit codes should not stop future tasks from running, so that
        # we can download relevant logs.
        logger.error(f"Scan report download failed for {artifact.value} with scanner {scanner.value} with exit code {e.returncode}.")


def get_scan_log(artifact: ArtifactType, scanner: Scanner) -> None:
    """
    Get the log of a scan specified by artifact and scanner.

    Scan logs are saved in the top-level secscan-results directory in
     Contracts, separated by artifact type.
    """
    token = get_token_filename(artifact, scanner)

    logger.info(f"Retrieving scan log for {artifact.value} with scanner {scanner.value}...")
    res = None
    try:
        res = subprocess.run(["secscan-client",
                        "--batch",
                        "log",
                        "--token", token],
                        check=True,
                        text=True,
                        # Capture all output.
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)

        if res.returncode == 0:
            logger.info(f"Scan log successfully downloaded for {artifact.value} with scanner {scanner.value}.")

            with open(f"{RESULTS_DIR}/{artifact.value}/{artifact.value}_{scanner.value}_log.txt", "w") as f:
                write_results_from_subprocess_result(res, f)
    except subprocess.CalledProcessError as e:
        # Non-zero exit codes should not stop future tasks from running, so that
        # we can download relevant logs.
        logger.error(f"Scan log download failed for {artifact.value} with scanner {scanner.value} with exit code {e.returncode}.")


def enrich_scan_results(artifact: ArtifactType, scanner: Scanner) -> None:
    """Enrich scan results with CVE data, saving the results as CSV."""
    logger.info(f"Identifying CVEs found for {artifact.value} with scanner {scanner.value}...")

    cve_data: list[CVEData] = []
    filename = f"{RESULTS_DIR}/{artifact.value}/{artifact.value}_{scanner.value}_result.txt"
    if not os.path.isfile(f"{RESULTS_DIR}/{artifact.value}/{artifact.value}_{scanner.value}_result.txt"):
        logger.warning(f"No results file found, skipping enrichment for {artifact.value} with scanner {scanner.value}.")
        return
    with open(filename, "r", newline="") as f:
        lines = f.read()
        all_cves = re.findall(CVE_REGEX, lines)
        logger.info(f"Found {len(all_cves)} CVEs for {artifact.value} with scanner {scanner.value}: {all_cves}")

        if len(all_cves) == 0:
            return

        # While secscan supposedly supports CVE exclusions (see above when we
        # get the scan results), this does not work as the excluded CVEs are
        # still included in scan results. So here we manually filter them out
        # based on the exclusions file.
        cves: list[str] = []
        if config.excluded_cves_file:
            with open(config.excluded_cves_file, "r") as exclusions_file:
                lines = exclusions_file.read()
                excluded = set(re.findall(CVE_REGEX, lines))
                logger.info(f"Found {len(excluded)} excluded CVEs for {artifact.value} with scanner {scanner.value}: {excluded}")
                cves = [cve for cve in all_cves if cve not in excluded]
                logger.info(f"After exclusions, enriching {len(cves)} CVEs for {artifact.value} with scanner {scanner.value}: {cves}")
        else:
            cves = [cve for cve in all_cves]
            logger.info(f"No exclusions specified, enriching {len(cves)} CVEs for {artifact.value} with scanner {scanner.value}: {cves}")

        for cve in cves:
            # Try to get data from the Ubuntu Security API first, if that does
            # not contain data about this CVE, fetch from the MITRE API as a
            # fallback.
            data = get_ubuntu_cve_data(cve)
            if data.status == CVE_NOT_IN_UBUNTU_STATUS:
                logger.info(f"Data for {cve} was not present in the Ubuntu Security database, fetching from the MITRE API instead...")
                data = get_mitre_cve_data(cve)
            elif data.cvss3 == 0.0 or data.severity == CVE_UNKNOWN_VALUE or data.status == CVE_UNKNOWN_VALUE:
                logger.info(f"Data for {cve} was incomplete in the Ubuntu Security database, fetching from the MITRE API instead...")
                mitre_data = get_mitre_cve_data(cve)
                data = CVEData.merge(data, mitre_data)

            if not data.patch_exists:
                logger.info(f"Enriching patch information for {cve}, checking the NVD database...")
                nvd_data = get_nvd_cve_data(cve)
                data = CVEData.merge(data, nvd_data)

            cve_data.append(data)

    if len(cve_data) == 0:
        logger.info(f"No CVEs found for {artifact.value} with scanner {scanner.value}, skipping enriched CSV generation.")
        return

    logger.info(f"Writing enriched CVE data to CSV for {artifact.value} with scanner {scanner.value}...")
    with open(f"{RESULTS_DIR}/{artifact.value}/{artifact.value}_{scanner.value}_enriched_result.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, delimiter=CSV_DELIMITER, quoting=csv.QUOTE_STRINGS, fieldnames=CVE_CSV_HEADERS)
        writer.writeheader()
        for row in cve_data:
            writer.writerow(row.to_csv_row())

    logger.info(f"Successfully saved enriched CVE data to CSV for {artifact.value} with scanner {scanner.value}.")


def aggregate_scan_results(artifact: ArtifactType) -> None:
    """Aggregate all CVEs found for the given artifact into one CSV file."""
    logger.info(f"Aggregating all CVEs found for artifact type {artifact.value}...")

    cve_data = defaultdict(list)
    row_count = 0
    for scanner in config.artifact_properties[artifact].scanners:
        filename = f"{RESULTS_DIR}/{artifact.value}/{artifact.value}_{scanner.value}_enriched_result.csv"
        # There might be no CVEs found by a scanner, so we might not have
        # a CSV result file for each
        if not os.path.isfile(filename):
            logger.info(f"No CVEs to include in aggregation for {artifact.value} with scanner {scanner.value}.")
            continue

        with open(filename, "r", newline="") as f:
            reader = csv.DictReader(f, delimiter=CSV_DELIMITER, quoting=csv.QUOTE_STRINGS, fieldnames=CVE_CSV_HEADERS)
            for row in reader:
                # Skip erronously read header rows that should have been skipped
                if row[CVE_CSV_HEADERS[0]] == CVE_CSV_HEADERS[0]:
                    continue

                row_count += 1
                cve_data[scanner.value].append(CVEData.from_csv_row(row))

    if len(cve_data) == 0:
        logger.info(f"No aggregated CVEs found for artifact type {artifact.value}.")
        return
    else:
        logger.info(f"Found {row_count} aggregated CVEs for artifact type {artifact.value}, deduplicating them...")

    deduplicated = defaultdict(list)
    for scanner, cves in cve_data.items():
        for cve in cves:
            deduplicated[cve].append(scanner)

    logger.info(f"Saving {len(deduplicated)} deduplicated aggregated CVEs for artifact type {artifact.value}...")
    with open(f"{RESULTS_DIR}/{artifact.value}/aggregated_results.csv", "w", newline="") as f:
        expanded_headers = CVE_CSV_HEADERS
        writer = csv.DictWriter(f, delimiter=CSV_DELIMITER, quoting=csv.QUOTE_STRINGS, fieldnames=expanded_headers)
        writer.writeheader()

        for cve, scanners in deduplicated.items():
            row = cve.to_csv_row()
            # Populate affected component
            row[CVE_CSV_HEADERS[6]] = config.artifact_properties[artifact].artifact_type.value

            # Populate affected release
            row[CVE_CSV_HEADERS[9]] = config.artifact_properties[artifact].version
            row[CVE_CSV_HEADERS[7]] = "; ".join(set(scanners))
            writer.writerow(row)

    logger.info(f"Successfully saved aggregated CVEs found for artifact type {artifact.value}.")


@cache
def get_ubuntu_cve_data(cve_id: str) -> CVEData:
    """Fetch and return data from the Ubuntu Security API for the given CVE."""
    logger.info(f"Fetching data from the Ubuntu Security API for {cve_id}...")
    try:
        adapter = HTTPAdapter(max_retries=config.retry)

        with requests.Session() as session:
            session.mount('https://', adapter)
            # The Ubuntu Security API is slow sometimes, give it 60s to respond
            r = session.get(UBUNTU_CVE_API_URL.format(cve_id), timeout=60)

            if r.status_code == 200:
                cve_data = CVEData.from_ubuntu_api_json(cve_id, r.json())
                logger.info(f"Successfully fetched data from the Ubuntu Security API for {cve_id}.")
                return cve_data

            logger.error(f"Failed to fetch data from the Ubuntu Security API for {cve_id} with status {r.status_code} and error {r.text}")
    except Exception as e:
        logger.error(f"Failed to fetch data from the Ubuntu Security API for {cve_id} with exception: {e}")
        # Failed data fetches for a few CVEs should not stop the pipeline
        return CVEData.failed_fetch(cve_id)


@cache
def get_mitre_cve_data(cve_id: str) -> CVEData:
    """Fetch and return data from the MITRE API for the given CVE identifier."""
    logger.info(f"Fetching data from the MITRE API for {cve_id}...")
    try:
        adapter = HTTPAdapter(max_retries=config.retry)

        with requests.Session() as session:
            session.mount('https://', adapter)
            r = session.get(MITRE_CVE_API_URL.format(cve_id), timeout=30)

            if r.status_code == 200:
                cve_data = CVEData.from_mitre_api_json(cve_id, r.json())
                logger.info(f"Successfully fetched data from the MITRE API for {cve_id}.")
                return cve_data

            logger.error(f"Failed to fetch data from the MITRE API for {cve_id} with status {r.status_code} and error {r.text}")
    except Exception as e:
        logger.error(f"Failed to fetch data from the MITRE API for {cve_id} with exception: {e}")
        # Failed data fetches for a few CVEs should not stop the pipeline
        return CVEData.failed_fetch(cve_id)

@cache
def get_nvd_cve_data(cve_id: str) -> CVEData:
    """Fetch and return data from the NVD API for the given CVE identifier."""
    logger.info(f"Fetching data from the NVD API for {cve_id}...")
    try:
        adapter = HTTPAdapter(max_retries=config.retry)

        with requests.Session() as session:
            session.mount('https://', adapter)
            nvd_api_key = os.environ.get("NVD_API_KEY")
            headers = {}
            # Having an API key helps with rate limits, but the API can still be accessed without one.
            if nvd_api_key:
                headers = {"apiKey": nvd_api_key}
            r = session.get(NVD_CVE_API_URL.format(cve_id), timeout=30, headers=headers)

            if r.status_code == 200:
                cve_data = CVEData.from_nvd_api_json(cve_id, r.json())
                logger.info(f"Successfully fetched data from the NVD API for {cve_id}.")
                return cve_data

            logger.error(f"Failed to fetch data from the NVD API for {cve_id} with status {r.status_code} and error {r.text}")
    except Exception as e:
        logger.error(f"Failed to fetch data from the NVD API for {cve_id} with exception: {e}")
        # Failed data fetches for a few CVEs should not stop the pipeline
        return CVEData.failed_fetch(cve_id)

def create_directories() -> None:
    """Create all results and tokens directories."""
    Path(TOKENS_DIR).mkdir(parents=True, exist_ok=True)

    for artifact in config.artifact_properties:
        dir = f"{RESULTS_DIR}/{artifact.value}/"
        Path(dir).mkdir(parents=True, exist_ok=True)


def cleanup_tokens() -> None:
    """Delete the tokens directory and its contents."""
    try:
        shutil.rmtree(TOKENS_DIR)
    except Exception as e:
        logger.error(f"Failed to remove {TOKENS_DIR} with error {e}")


def run_stage(stage: Stage, func: typing.Callable, tasks: StageTasks) -> StageTasks:
    """
    Run the given function on the tasks belonging to a stage of the scanning
    process and return the tasks that succeeded and should be used in subsequent
    stages. Tasks are stopped if the stage takes longer than the timeout set in
    config.py.

    Stages are only run if they are in the config.stages_to_run list, otherwise
    they are skipped. This allows for selective retries of failed stages.
    """
    if stage not in config.stages_to_run:
        logger.warning(f"Skipping stage {stage} because only the {config.stages_to_run} stages are set to run.")
        return tasks

    next_tasks = defaultdict(list)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = {}
        for artifact, scanners in tasks.items():
            for scanner in scanners:
                results[(artifact, scanner)] = executor.submit(func, artifact, scanner)

        concurrent.futures.wait(results.values(), config.stage_timeout)
        for key, future in results.items():
            try:
                future.result()
                next_tasks[key[0]].append(key[1])
            except Exception as e:
                logger.exception(f"Failed to run stage {stage.value} for {key} with exception {e}")

    return next_tasks


if __name__ == "__main__":
    try:
        create_directories()

        submit_tasks = {}
        for artifact, properties in config.artifact_properties.items():
            submit_tasks[artifact] = properties.scanners

        wait_tasks = run_stage(Stage.submit, submit_scan, submit_tasks)
        result_tasks = run_stage(Stage.wait, wait_for_scan_completion, wait_tasks)
        enrichment_tasks = run_stage(Stage.result, get_scan_result, result_tasks)

        # Always download reports and logs, even when the result is failure
        run_stage(Stage.report, get_scan_report, result_tasks)
        run_stage(Stage.log, get_scan_log, result_tasks)
        final_tasks = run_stage(Stage.enrich, enrich_scan_results, enrichment_tasks)

        # Treat aggregation as the 'aggregate' stage
        if Stage.aggregate not in config.stages_to_run:
            logger.warning(f"Skipping result aggregation because only the {config.stages_to_run} stages are set to run.")
        else:
            for artifact in config.artifact_properties:
                aggregate_scan_results(artifact)

        if len(final_tasks.values()) != len(submit_tasks.values()):
            diff = []
            for artifact, scanners in submit_tasks.items():
                if artifact not in final_tasks:
                    for scanner in scanners:
                        diff.append(f"{artifact.value}-{scanner.value}")
                elif set(scanners) != set(final_tasks[artifact]):
                    for scanner in scanners:
                        if scanner not in final_tasks[artifact]:
                             diff.append(f"{artifact.value}-{scanner.value}")
            raise RuntimeError(f"Failed to run vulnerability identification scan for {diff}")

        logger.info("Vulnerability identification scans completed successfully.")
    finally:
        if config.keep_tokens:
            logger.warning("Skipping token cleanup as 'keep_tokens' is set to 'true', remember to delete the token files after use.")
        else:
            logger.info("Cleaning up tokens as 'keep_tokens' is not set to 'true'...")
            cleanup_tokens()
