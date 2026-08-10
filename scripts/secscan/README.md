# Vulnerability identification scan runner

Runs vulnerability identification scans using the `secscan` tool, saving the
 results in the `secscan-results` directory.

More information about the `secscan` tool and the configuration it supports can
 be found in the [SSDLC specification](https://docs.google.com/document/d/1CRRPeGyrh5KeJy-TF0R1Tk-_l60qVP0GpfjRluMaUqM/edit).

 This tool requires Python 3.12+ to run.

## Supported artifacts and scanners

This tool currently supports a subset of artifact and scanner types available
in the `secscan` tool:

* charm
  * Blackduck
  * Trivy
  * OSV
* OCI image
  * Blackduck
  * Trivy
  * OSV

## Stages

The scanning process consists of the following stages:

1. submit: Submit a scan request using the `secscan` tool.
2. wait: Await the completion of a scan using the `secscan` tool.
3. result: Download the result of a scan using the `secscan` tool.
4. report: Download a scan report using the `secscan` tool.
5. log: Download a scan log file using the `secscan` tool.
6. enrich: Enrich the results of a scan with CVE information.
7. aggregate: Aggregate all scan results per artifact type.

## Configuration

The tool currently supports the following configuration options through the use
of environment variables:

* Stages to run through setting `VULN_IDENTIFICATION_STAGES_TO_RUN` to a comma-
separated list of stages. For example `"submit, wait, result"`. Defaults to
 running all stages.
* Keeping the scan tokens issued upon scan submission instead of deleting them
 at the end of a run by setting `VULN_IDENTIFICATION_KEEP_TOKENS` to `True`.
 Defaults to `False`.
* The timeout applied to each stage by setting
  `VULN_IDENTIFICATION_STAGE_TIMEOUT_SECONDS` to the number of seconds to wait
 before terminating each stage due to timeout. Defaults to 1 hour (3600s).
* Artifacts to scan by populating the `CHARM_FILENAME` and `OCI_FILENAME`
 environment variables. If either of these environment variables are empty or
 not populated, scans are not run for that artifact type.

False positive CVEs can be excluded from results by populating a text file with
 CVE identifiers, one per line (comments starting with `#` are allowed), and
 supplying its location in the `EXCLUDED_CVES_FILE` environment variable (see
 config.py).
