from base64 import b64decode, b64encode
from json import dumps, loads
from os import getenv
from os.path import basename, getsize
from subprocess import CompletedProcess, run
from sys import argv, exit
from time import sleep
from typing import Any, Mapping, Optional, Tuple
from urllib.parse import urljoin
from xml.etree import ElementTree


class GraphQLClient:
    api_key: str
    api_url: str
    ca_cert: Optional[str]

    def __init__(self, api_key: str, api_url: str, ca_cert: Optional[str]):
        self.api_key = api_key
        self.api_url = api_url
        self.ca_cert = ca_cert

    def _post(self, data: str) -> CompletedProcess:
        query = ["curl", "--request", "POST"]
        if self.ca_cert:
            query += ["--cacert", f"{self.ca_cert}"]
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
        self, query: str, variables: Mapping[str, Any] = None
    ) -> Mapping[str, Any]:
        data = {
            "query": query,
            "variables": variables,
        }
        response = self._post(data=dumps(data))
        if response.returncode != 0:
            print(
                f"System call to curl returned non-zero return code: {response.returncode}"
            )
            exit(1)
        response_json = loads(response.stdout.decode())
        if "errors" in response_json.keys():
            print("Unexpected GraphQL response:")
            print(dumps(response_json, indent=2))
            exit(1)
        return response_json["data"]


class CsApiClient:
    graphql_client: GraphQLClient

    def __init__(self, api_key: str, api_url: str, ca_cert: Optional[str]):
        self.graphql_client = GraphQLClient(
            api_key=api_key, api_url=api_url, ca_cert=ca_cert
        )

    def generate_trace_upload_post(self) -> Tuple[str, str]:
        generate_trace_upload_query = """
            mutation {
                generateTraceUploadPost(input: {}) {
                    url
                    formData
                }
            }
        """
        response = self.graphql_client.query(query=generate_trace_upload_query)
        object_storage_url = response["generateTraceUploadPost"]["url"]
        form_data = response["generateTraceUploadPost"]["formData"]
        return (object_storage_url, form_data)

    def create_trace(self, project_id: str, name: str, key: str, size: int) -> str:
        query = """
            mutation (
                $projectId: ID!,
                $name: String!,
                $key: String!,
                $size: Int!
            ) {
                createTrace(
                    input: {
                        projectId: $projectId,
                        name: $name,
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
            variables={"projectId": project_id, "name": name, "key": key, "size": size},
        )
        return response["createTrace"]["trace"]["id"]

    def generate_report(self, trace_id: str, profile_id: str) -> str:
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
            variables={"traceId": trace_id, "profileId": profile_id},
        )
        return response["analyze"]["report"]["id"]

    def wait_for_trace_done(self, trace_id: str) -> None:
        finished = False
        while not finished:
            sleep(1)
            print("Checking if trace upload is complete...")
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
                    "id": trace_id,
                },
            )
            status = result["node"]["__typename"]
            print(f"status = {status}")
            finished = (status == "TraceFailed") or (status == "TraceDone")
        status = result["node"]["__typename"]
        assert status == "TraceDone", f'Failed trace upload: {result["node"]["reason"]}'

    def wait_for_report_done(self, report_id: str) -> None:
        finished = False
        while not finished:
            sleep(1)
            print("Checking if report is complete...")
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
                    "id": report_id,
                },
            )
            status = result["node"]["__typename"]
            print(f"status = {status}")
            finished = (status == "ReportFailed") or (status == "ReportDone")
        status = result["node"]["__typename"]
        assert status == "ReportDone", f'Failed report: {result["node"]["reason"]}'


class S3Client:
    object_storage_url: str
    ca_cert: Optional[str]

    def __init__(self, object_storage_url: str, ca_cert: Optional[str]):
        self.object_storage_url = object_storage_url
        self.ca_cert = ca_cert

    def upload_to_s3(self, form_data: str, trace_file: str) -> None:
        fields = loads(form_data)

        fields["success_action_status"] = str(fields["success_action_status"])
        fields["x-amz-meta-filename"] = basename(trace_file)

        query = ["curl"]
        if self.ca_cert:
            query += ["--cacert", self.ca_cert]
        for (key, value) in fields.items():
            query += ["--form", f"{key}={value}"]
        query += [
            "--form",
            f"file=@{trace_file};type=application/gzip",
            self.object_storage_url,
        ]

        response = run(query, capture_output=True)

        if response.returncode != 0:
            print("S3 upload failed")
            print(f"status code = {response.returncode}")
            exit(1)

        xml_key = ElementTree.fromstring(response.stdout.decode()).find("Key")
        assert xml_key is not None, "The storage backend sent an unexpected response."
        self.key = xml_key.text

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
    temp_ = b64decode(id_).decode()
    return int(temp_[len(type_) + 1 :])


def main():
    api_key = getenv_or_exit("CS_API_KEY")
    root_url = getenv_or_exit("CS_ROOT_URL")
    ca_cert = getenv("CS_CA_CERT")

    if len(argv) < 3:
        print(f"Usage: {basename(argv[0])} <trace-file> <project-id> [<profile-id>]")
        exit(1)

    trace_file_name = argv[1]
    project_id = int(argv[2])

    print(f"trace_file = {trace_file_name}")
    print(f"project_id = {project_id}")
    print("CS_API_KEY found")
    print(f"CS_ROOT_URL = {root_url}")
    if ca_cert:
        print(f"CS_CA_CERT = {ca_cert}")
    else:
        print("No CA cert provided")

    opaque_project_id = to_global_id(type_="Project", id_=project_id)
    trace_name = basename(trace_file_name)

    print(f"Trace name = {trace_name}")

    api_url = urljoin(root_url, "/api/v2")
    print(f"API URL = {api_url}")
    api_client = CsApiClient(api_key=api_key, api_url=api_url, ca_cert=ca_cert)

    (object_storage_url, form_data) = api_client.generate_trace_upload_post()
    print(f"Object storage URL = {object_storage_url}")
    s3_client = S3Client(object_storage_url=object_storage_url, ca_cert=ca_cert)
    s3_client.upload_to_s3(form_data, trace_file_name)
    s3_key = s3_client.get_key()

    size = getsize(trace_file_name)
    print(f"Trace file size = {size} bytes")

    trace_id = api_client.create_trace(opaque_project_id, trace_name, s3_key, size)
    api_client.wait_for_trace_done(trace_id)

    actual_trace_id = from_global_id(type_="Trace", id_=trace_id)
    trace_url = urljoin(root_url, f"/project/{project_id}/traces/{actual_trace_id}")
    print(f"Trace available at {trace_url}")

    if len(argv) > 3:
        profile_id = int(argv[3])
        print(f"profile_id = {profile_id}")

        opaque_profile_id = to_global_id(type_="Profile", id_=profile_id)

        report_id = api_client.generate_report(trace_id, opaque_profile_id)
        api_client.wait_for_report_done(report_id)

        actual_report_id = from_global_id(type_="Report", id_=report_id)
        report_url = urljoin(root_url, f"/report/{actual_report_id}/inventory")
        print(f"Report available at {report_url}")


if __name__ == "__main__":
    main()
