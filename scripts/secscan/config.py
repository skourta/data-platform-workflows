import os
import typing

from dataclasses import dataclass
from logging import Logger
from urllib3.util import Retry

from secscan_types import (
    ArtifactType,
    ArtifactProperties,
    Scanner,
    ScannerType,
    ScannerArtifactType,
    Stage,
)


def get_env_var_or_raise(env_var: str, default: typing.Any = None) -> typing.Any:
    """
    Gets the specified env variable or raises an error if a default is not
    specified and the variable is not set.
    """
    val = os.environ.get(env_var, default)
    if val is None:
        raise ValueError(f"{env_var} environment variable is not set")

    if default != "" and isinstance(val, str) and val.strip() == "":
        raise ValueError(f"{env_var} environment variable is empty")

    return val


@dataclass(frozen=True)
class Config:
    artifact_properties: dict[ArtifactType, ArtifactProperties]
    retry: Retry
    stage_timeout: int
    stages_to_run: list[Stage]
    keep_tokens: bool
    excluded_cves_file: typing.Optional[str]
    product_name: str
    cycle: str
    release_channel: str

    @classmethod
    def from_env(cls, logger: Logger) -> 'Config':
        """Create a Config from environment variables."""
        # Allow skipping stages.
        default_stages = [stage for stage in Stage.__members__]
        stages = get_env_var_or_raise("VULN_IDENTIFICATION_STAGES_TO_RUN", ",".join(default_stages))
        stages = [Stage(stage.strip()) for stage in stages.split(",")]
        logger.info(f"Configured to run stages: {stages}.")

        # Allow reusing scan tokens so that later runs can retry failed stages.
        keep_tokens = get_env_var_or_raise("VULN_IDENTIFICATION_KEEP_TOKENS", "false")
        keep_tokens = keep_tokens.strip().lower() == "true"
        logger.info(f"Keeping secscan tokens: {keep_tokens}.")

        # Default to 1 hour (3600s) - some of the stages can take a long time.
        timeout = get_env_var_or_raise("VULN_IDENTIFICATION_STAGE_TIMEOUT_SECONDS", 3600)
        logger.info(f"Configured timeout for each stage: {timeout} seconds.")

        # Default to not using a CVE exclusions file.
        excluded_cves_file = get_env_var_or_raise("EXCLUDED_CVES_FILE", "")
        if excluded_cves_file:
            logger.info(f"Using CVE exclusions file {excluded_cves_file} .")
        else:
            logger.info(f"No CVE exclusions file specified.")

        # Accept empty product names for now, until SSDLC v1.2 is fully adopted.
        product_name = get_env_var_or_raise("PRODUCT_NAME", "")
        cycle = get_env_var_or_raise("CYCLE", "")
        release_channel = get_env_var_or_raise("RELEASE_CHANNEL", "")
        if product_name:
            logger.info(f"Using product name {product_name} - SSDLC v1.2 support is enabled.")
        else:
            logger.info(f"No product name specified, SSDLC v1.2 support is disabled.")

        charm_filename = get_env_var_or_raise("CHARM_FILENAME", "")
        charm_version = get_env_var_or_raise("CHARM_VERSION", "")
        oci_filename = get_env_var_or_raise("OCI_FILENAME", "")
        oci_version = get_env_var_or_raise("OCI_VERSION", "")
        snap_filename = get_env_var_or_raise("SNAP_FILENAME", "")
        snap_name = get_env_var_or_raise("SNAP_NAME", "")
        snap_version = get_env_var_or_raise("SNAP_VERSION", "")

        if snap_filename and snap_name:
            raise ValueError("Only one of SNAP_FILENAME or SNAP_NAME should be set")

        # Handle specifying which artifact types to run by leaving the
        # corresponding env var empty.
        artifact_properties: dict[ArtifactType, ArtifactProperties] = {}
        if charm_filename:
            artifact_properties[ArtifactType.charm] = ArtifactProperties(
                scanners=[
                    Scanner(ScannerType.blackduck),
                    Scanner(ScannerType.trivy),
                    Scanner(ScannerType.osv),
                ],
                artifact_type=ScannerArtifactType.package,
                filename=charm_filename,
                version=charm_version
            )

        if oci_filename:
            artifact_properties[ArtifactType.oci] = ArtifactProperties(
                scanners=[
                    Scanner(ScannerType.blackduck),
                    Scanner(ScannerType.trivy),
                    Scanner(ScannerType.osv),
                ],
                artifact_type=ScannerArtifactType.container_image,
                filename=oci_filename,
                version=oci_version
            )

        if snap_filename or snap_name:
            artifact_properties[ArtifactType.snap] = ArtifactProperties(
                scanners=[
                    Scanner(ScannerType.blackduck),
                    Scanner(ScannerType.trivy),
                    Scanner(ScannerType.osv),
                ],
                artifact_type=ScannerArtifactType.package,
                filename=snap_name if snap_name else snap_filename,
                version=snap_version
            )

        if len(artifact_properties) == 0:
            raise ValueError(f"No artifact types set up. At least one of {", ".join(ArtifactType)} must be set up")

        return cls(
            artifact_properties = artifact_properties,
            retry = Retry(
                total=3,
                backoff_factor=2,
                status_forcelist=[429, 500, 502, 503, 504],
            ),
            stage_timeout = timeout,
            stages_to_run = stages,
            keep_tokens = keep_tokens,
            excluded_cves_file = excluded_cves_file,
            product_name=product_name,
            cycle=cycle,
            release_channel=release_channel,
        )
