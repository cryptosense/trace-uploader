import argparse
from base64 import b64decode, b64encode
from collections import defaultdict
from json import dumps, loads
import logging
import os
from os import getenv
from os.path import basename, getsize
import re
from subprocess import CompletedProcess, run
import sys
from time import sleep
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

logger = logging.getLogger(__name__)


class Colors:
    BLUE = "\033[0;34m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[0;31m"
    RESET = "\033[0m"
    YELLOW = "\033[1;33m"


LEVEL_COLORS = {
    logging.DEBUG: Colors.DIM,
    logging.INFO: Colors.BLUE,
    logging.WARNING: Colors.YELLOW,
    logging.ERROR: Colors.RED,
    logging.CRITICAL: Colors.RED,
}


def get_formatter(level: int) -> logging.Formatter:
    if sys.stderr.isatty() and os.name != "nt":
        dim = Colors.DIM
        reset = Colors.RESET
        bold = Colors.BOLD
        level_colors = LEVEL_COLORS
    else:
        dim = ""
        bold = ""
        reset = ""
        level_colors = defaultdict(lambda: "")

    return logging.Formatter(
        f"{dim}%(asctime)s{reset}"
        f" {level_colors[level]}{bold}%(levelname)s{reset}"
        f" %(message)s"
    )


class Formatter(logging.Formatter):
    def __init__(self) -> None:
        self.formatters = {level: get_formatter(level) for level in LEVEL_COLORS}

    def format(self, record: logging.LogRecord) -> str:
        return self.formatters[record.levelno].format(record)


def initialize_logging(verbose: bool) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(Formatter())
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, handlers=[handler])


class GraphQLClient:
    api_key: str
    api_url: str
    ca_cert: Optional[str]

    def __init__(
        self,
        api_key: str,
        api_url: str,
        ca_cert: Optional[str],
        check_ca_cert: bool = True,
    ):
        self.api_key = api_key
        self.api_url = api_url
        self.ca_cert = ca_cert
        self.check_ca_cert = check_ca_cert

    def _post(self, data: str) -> CompletedProcess:
        query = ["curl", "--request", "POST"]
        if self.ca_cert and self.check_ca_cert:
            query += ["--cacert", f"{self.ca_cert}"]
        if not self.check_ca_cert:
            query += ["--insecure"]
        query += [
            "--header",
            f"API-KEY: {self.api_key}",
            "--header",
            "Content-Type: application/json",
            "--data",
            data,
            self.api_url,
        ]
        return run(query, capture_output=True)

    def _put(self, data: str) -> CompletedProcess:
        query = ["curl", "--request", "PUT"]
        if self.ca_cert and self.check_ca_cert:
            query += ["--cacert", f"{self.ca_cert}"]
        if not self.check_ca_cert:
            query += ["--insecure"]
        query += [
            "--header",
            f"API-KEY: {self.api_key}",
            "--header",
            "Content-Type: application/json",
            "--data",
            data,
            self.api_url,
        ]
        return run(query, capture_output=True)

    def query(
        self, query: str, variables: Optional[Mapping[str, Any]] = None
    ) -> Mapping[str, Any]:
        data = {
            "query": query,
            "variables": variables,
        }
        response = self._post(data=dumps(data))
        if response.returncode != 0:
            logger.error(
                f"System call to curl returned non-zero return code: {response.returncode}"
            )
            exit(1)

        response_json = loads(response.stdout.decode())
        if "errors" in response_json.keys():
            logger.error(
                f"Unexpected GraphQL response: \n{dumps(response_json, indent=2)}"
            )
            exit(1)
        return response_json["data"]


class CsApiClient:
    graphql_client: GraphQLClient

    def __init__(
        self,
        api_key: str,
        api_url: str,
        ca_cert: Optional[str],
        check_ca_cert: bool = True,
    ):
        if ca_cert:
            logger.debug(
                f"Initializing API client (URL: {api_url}, CA cert: {ca_cert})"
            )
        elif not check_ca_cert:
            logger.debug(f"Initializing API client (URL: {api_url}, no CA check)")
        else:
            logger.debug(f"Initializing API client (URL: {api_url})")
        self.graphql_client = GraphQLClient(
            api_key=api_key,
            api_url=api_url,
            ca_cert=ca_cert,
            check_ca_cert=check_ca_cert,
        )

    def generate_trace_upload_post(self) -> Tuple[str, str, str]:
        logger.info("Getting presigned request from CAP")
        generate_trace_upload_query = """
            mutation {
                generateTraceUploadPost(input: {}) {
                    url
                    formData
                    method
                }
            }
        """
        response = self.graphql_client.query(query=generate_trace_upload_query)
        object_storage_url = response["generateTraceUploadPost"]["url"]
        form_data = response["generateTraceUploadPost"]["formData"]
        method = response["generateTraceUploadPost"]["method"]
        return (object_storage_url, form_data, method)

    def create_trace(
        self,
        project_id: int,
        slot_name: Optional[str],
        name: str,
        key: str,
        size: int,
    ) -> int:
        logger.info(
            f"Registering trace in CAP (name: {name}, project ID: {project_id})"
        )
        query = """
            mutation (
                $projectId: ID!,
                $name: String!,
                $slotName: String,
                $key: String!,
                $size: Int!,
            ) {
                createTrace(
                    input: {
                        projectId: $projectId,
                        name: $name,
                        defaultSlotName: $slotName,
                        key: $key,
                        size: $size
                    }
                ) {
                    trace {
                        id
                    }
                }
            }
        """
        response = self.graphql_client.query(
            query=query,
            variables={
                "projectId": to_global_id("Project", project_id),
                "name": name,
                "slotName": slot_name,
                "key": key,
                "size": size,
            },
        )
        return from_global_id("Trace", response["createTrace"]["trace"]["id"])

    def generate_report(self, trace_id: int, profile_id: int) -> int:
        logger.info(
            f"Generating report (trace ID: {trace_id}, profile ID: {profile_id})"
        )
        query = """
            mutation ($traceId: ID!, $profileId: ID!) {
              analyze(
                input: {
                    traceId: $traceId,
                    profileId: $profileId
                }
            ) {
            report {
              id
              name
            }
          }
        }
        """
        response = self.graphql_client.query(
            query,
            variables={
                "traceId": to_global_id("Trace", trace_id),
                "profileId": to_global_id("Profile", profile_id),
            },
        )
        return from_global_id("Report", response["analyze"]["report"]["id"])

    def wait_for_trace_done(self, trace_id: int) -> None:
        finished = False
        while not finished:
            sleep(1)
            logger.debug(f"Checking if trace upload is complete (ID: {trace_id})")
            result = self.graphql_client.query(
                query="""
                    query TraceStatus($id: ID!) {
                        node(id: $id) {
                            __typename

                            ... on TraceFailed {
                                reason
                            }
                            ... on TraceDone {
                                name
                            }
                        }
                    }
                """,
                variables={
                    "id": to_global_id("Trace", trace_id),
                },
            )
            status = result["node"]["__typename"]
            finished = (status == "TraceFailed") or (status == "TraceDone")
        logger.debug(f"Trace upload complete (ID: {trace_id}, status: {status})")
        if status == "TraceFailed":
            logger.error(
                f"Trace upload failed (ID: {trace_id}, reason: {result['node']['reason']})"
            )
            exit(1)

    def wait_for_report_done(self, report_id: int) -> None:
        finished = False
        while not finished:
            sleep(1)
            logger.debug(f"Checking if report is complete (ID: {report_id})")
            result = self.graphql_client.query(
                query="""
                    query ReportStatus($id: ID!) {
                        node(id: $id) {
                            __typename

                            ... on ReportFailed {
                                reason
                            }
                            ... on ReportDone {
                                name
                            }
                        }
                    }
                """,
                variables={
                    "id": to_global_id("Report", report_id),
                },
            )
            status = result["node"]["__typename"]
            finished = (status == "ReportFailed") or (status == "ReportDone")
        logger.debug(f"Report complete (ID: {report_id}, status: {status})")
        if status == "TraceFailed":
            logger.error(
                f"Analysis failed (ID: {report_id}, reason: {result['node']['reason']})"
            )
            exit(1)


class S3Client:
    object_storage_url: str
    ca_cert: Optional[str]

    def __init__(
        self,
        object_storage_url: str,
        ca_cert: Optional[str],
        check_ca_cert: bool = True,
        upload_method: str = "POST",
    ):
        self.object_storage_url = object_storage_url
        self.ca_cert = ca_cert
        self.check_ca_cert = check_ca_cert
        self.upload_method = upload_method

    def mime_type(self, trace_file: str) -> str:
        if trace_file.endswith(".cst.gz"):
            return "application/gzip"
        elif trace_file.endswith(".cst"):
            return ""
        elif trace_file.endswith(".pcap"):
            return "application/octet-stream"
        else:
            print(
                "Trace file extension must be either .pacp, .cst.gz or .cst",
                file=sys.stderr,
            )
            exit(1)

    def upload_to_s3(self, form_data: Optional[str], trace_file: str) -> None:
        fields = {}
        if form_data:
            fields = loads(form_data)
            fields["success_action_status"] = str(fields["success_action_status"])
            fields["x-amz-meta-filename"] = basename(trace_file)

        mime_type = self.mime_type(trace_file)
        query = ["curl"]
        if self.ca_cert and self.check_ca_cert:
            query += ["--cacert", self.ca_cert]
        if not self.check_ca_cert:
            query += ["--insecure"]
        query += ["-X", self.upload_method]
        if self.upload_method == "POST":
            for key, value in fields.items():
                query += ["--form", f"{key}={value}"]
            query += [
                "--form",
                f"Content-Type={mime_type}",
                "--form",
                f"file=@{trace_file}",
                self.object_storage_url,
            ]
        elif self.upload_method == "PUT":
            query += [
                "--header",
                "Content-Type: application/octet-stream",
                "--data-binary",
                f"@{trace_file}",
                self.object_storage_url,
            ]
        else:
            logger.error(f"Unknown upload method: {self.upload_method}")
            exit(1)

        response = run(query, capture_output=True)
        if response.returncode != 0:
            logger.error(
                f"Upload to object storage failed (status code: {response.returncode})"
            )
            exit(1)

        output = response.stdout.decode()
        if self.upload_method == "POST":
            try:
                xml = ElementTree.fromstring(output)
                if xml.tag == "Error":
                    logger.error(
                        f"Storage backend returned an error: \n{output}",
                    )
                    exit(1)
            except ElementTree.ParseError:
                logger.error(
                    f"Unable to parse the response of the backend:\n{output}",
                )
                exit(1)
            xml_key = xml.find("Key")
            assert (
                xml_key is not None
            ), "The storage backend sent an unexpected response."
            self.key = xml_key.text
        else:
            path = urlsplit(self.object_storage_url).path
            self.key = "/".join(path.split("/")[-2:])

    def get_key(self) -> str:
        assert (
            self.key is not None
        ), "Tried to extract key from S3 storage before initialization."
        return self.key


def getenv_or_exit(name: str) -> str:
    result = getenv(name)
    if result is None:
        exit(f"{name} is not defined")
    return result


def to_global_id(type_: str, id_: int) -> str:
    return b64encode(f"{type_}:{id_}".encode()).decode()


def from_global_id(type_: str, id_: str) -> int:
    decoded = b64decode(id_.encode()).decode()
    match = re.match(rf"^{type_}:(?P<id>\d+)$", decoded)
    assert match is not None, "Invalid type or format"
    return int(match.groupdict()["id"])


def main():
    parser = argparse.ArgumentParser(description="Cryptosense API client")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Trace or scan file to upload.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable the certificate validation.",
    )
    parser.add_argument(
        "--trace-file",
        type=str,
        required=True,
        help="Trace or scan file to upload.",
    )
    parser.add_argument(
        "--project-id",
        type=int,
        required=True,
        help="Numerical ID of the project the trace file should be added to.",
    )
    parser.add_argument(
        "--slot-name",
        type=str,
        help="Name of the (existing or not) slot the trace should be added to.",
    )
    parser.add_argument(
        "--profile-id",
        type=int,
        help="""
            Numerical ID of the project to use for analysis. Specifying this argument
            triggers an analysis after trace upload.
        """,
    )
    parser.add_argument(
        "--trace-name", type=str, help="Name of the trace that will be created."
    )
    parser.add_argument(
        "--put-url",
        type=str,
        help="Directly use a provided PUT url instead of querying a new signature.",
    )
    args = parser.parse_args()
    trace_file_name = args.trace_file
    trace_name = args.trace_name
    project_id = args.project_id
    profile_id = args.profile_id
    slot_name = args.slot_name
    put_url = args.put_url
    check_ca_cert = not args.insecure

    initialize_logging(verbose=args.verbose)

    api_key = getenv_or_exit("CS_API_KEY")
    root_url = getenv_or_exit("CS_ROOT_URL")
    ca_cert = getenv("CS_CA_CERT")

    api_url = urljoin(root_url, "/api/v2")
    api_client = CsApiClient(
        api_key=api_key, api_url=api_url, ca_cert=ca_cert, check_ca_cert=check_ca_cert
    )

    if not put_url:
        (
            object_storage_url,
            form_data,
            method,
        ) = api_client.generate_trace_upload_post()
        s3_client = S3Client(
            object_storage_url=object_storage_url,
            ca_cert=ca_cert,
            check_ca_cert=check_ca_cert,
            upload_method=method,
        )
    else:
        object_storage_url = put_url
        form_data: Dict[str, str] = {}  # type: ignore [no-redef]
        s3_client = S3Client(
            object_storage_url=object_storage_url,
            ca_cert=ca_cert,
            upload_method="PUT",
            check_ca_cert=check_ca_cert,
        )
    logger.info(f"Using object storage URL: {object_storage_url}")
    s3_client.upload_to_s3(form_data, trace_file_name)
    s3_key = s3_client.get_key()

    size = getsize(trace_file_name)
    if trace_name is None:
        trace_name = basename(trace_file_name)

    trace_id = api_client.create_trace(
        project_id=project_id,
        slot_name=slot_name,
        name=trace_name,
        key=s3_key,
        size=size,
    )
    api_client.wait_for_trace_done(trace_id=trace_id)

    trace_url = urljoin(root_url, f"/project/{project_id}/traces/{trace_id}")
    logger.info(f"Trace available at {trace_url}")

    if profile_id is not None:
        report_id = api_client.generate_report(trace_id=trace_id, profile_id=profile_id)
        api_client.wait_for_report_done(report_id)

        report_url = urljoin(root_url, f"/report/{report_id}/inventory")
        logger.info(f"Report available at {report_url}")


if __name__ == "__main__":
    main()
