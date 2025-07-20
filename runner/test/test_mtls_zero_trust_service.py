from datetime import datetime, timedelta
import hashlib
import os
from unittest.mock import Mock
import pytest
import httpx
from cryptography import x509
import yaml
import cloudflare
from cloudflare import ConflictError
from runner.src.model import EnvironmentModel, InputModel
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import github_service
from runner.src import cloudflare_token_service
from runner.src import mtls_zero_trust_service
from runner.src import exceptions
from runner.src import working_dir as wd
from runner.src import venafi_service
from runner.src import terraform_service
from runner.src import helpers
import unittest


jwt_token_info = JWTTokenInfo(
    repo_name="repo_name",
    branch_name="abc",
    authorized=True,
    org_name="CBA-General",
)


def test_get_mtls(monkeypatch):
    # success scenario
    current_state = [{"name": "cert1", "zero_trust_name": "zt_name1", "domain": "fqdn"}]
    monkeypatch.setattr(mtls_zero_trust_service, "get_mtls_tf_state", lambda x, y, z: current_state)
    monkeypatch.setattr(
        mtls_zero_trust_service, "load_mtls_parameters", lambda x, y, z: {"certs": [
            {"name": "cert2"}], "leaf_common_names": [{"friendlyname": "friendlyname", "common_name": "common_name"}]}
    )
    monkeypatch.setattr(
        mtls_zero_trust_service, "get_mtls_certs_from_tenant_repo", lambda w, x, y, z: None
    )

    terraform_output = "terraform_stdout"
    monkeypatch.setattr(terraform_service, "run", lambda x, y: terraform_output)

    process_cert_res = (["cert2"], ["cert1"])
    monkeypatch.setattr(mtls_zero_trust_service, "process_mtls_certs_plan", lambda x, y, z: process_cert_res)

    expected_res = {"terraform_stdout": "terraform_stdout", "current_state": current_state, "certs_to_add": process_cert_res[0], "certs_to_remove": process_cert_res[1]}
    input_model = InputModel(
        environment="dev", action="plan", config_type="mtls", fqdn="fqdn"
    )
    assert mtls_zero_trust_service.get_mtls(jwt_token_info, input_model) == expected_res


    # Failure - Error in creating working directory
    monkeypatch.setattr(wd, "create_dir", lambda: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.get_mtls(
            jwt_token_info, input_model)


def test_update_mtls(monkeypatch):
    # Success - Update mTLS
    monkeypatch.setattr(
        mtls_zero_trust_service, "load_mtls_parameters", lambda x, y, z: {"certs": [
            {"name": "cert"}], "leaf_common_names": [{"friendlyname": "friendlyname", "common_name": "common_name"}], "authenticated_origin_pulls_settings":True}
    )
    monkeypatch.setattr(
        mtls_zero_trust_service, "get_mtls_certs_from_tenant_repo", lambda w, x, y, z: None
    )
    monkeypatch.setattr(mtls_zero_trust_service, "get_mtls_tf_state", lambda x, y, z: [
                        {"name": "cert", "zero_trust_name": "", "domain": "fqdn"}])
    monkeypatch.setattr(terraform_service, "run", lambda x, y: "terraform_stdout")
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: ([
            "token_store"],"token")
    )
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(
        mtls_zero_trust_service,
        "upload_zero_trust_mtls_cert",
        lambda v, w, x, y, z: [
            {"name": "cert", "zero_trust_name": "zero_trust_name", "domain": "fqdn"}]
    )
    monkeypatch.setattr(mtls_zero_trust_service,
                        "remove_zero_trust_mtls_cert", lambda v, w, x, y, z: None)
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(mtls_zero_trust_service, "process_authenticated_origin_pulls", lambda x, y, z: True)
    expected_res = {"terraform_stdout": "terraform_stdout", "current_state": [{"name": "cert", "zero_trust_name": "zero_trust_name", "domain": "fqdn"}]}
    input_model = InputModel(
        environment="dev", action="apply", config_type="mtls", fqdn="fqdn"
    )
    assert mtls_zero_trust_service.update_mtls(
        jwt_token_info, input_model) == expected_res

    # Failure - Error in creating working directory
    monkeypatch.setattr(wd, "create_dir", lambda: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.update_mtls(
            jwt_token_info, input_model)

    # Failure - Error in running Terraform service
    monkeypatch.setattr(terraform_service, "run", raise_exception)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.update_mtls(
            jwt_token_info, input_model)


def test_load_cert_parameters(monkeypatch):
    # Success scenario
    cwd = wd.create_dir()
    data = {"certs": [{"name": "cert", "ca_chain_filename": "filename.pem"}], "leaf_common_names": [
        {"friendlyname": "friendlyname", "common_name": "common_name"}]}
    with open(f"{cwd}/mtls_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    assert mtls_zero_trust_service.load_mtls_parameters(
        "token", "input_url", cwd) == data
    wd.delete_dir(cwd)

    # Failure scenario - Error in reading file using Github service
    monkeypatch.setattr(
        github_service, "main", raise_github_service_exception_load_mtls_params
    )
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)

    # Failure scenario - Error in reading file using Github service
    monkeypatch.setattr(github_service, "main", raise_exception)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)

    # Failure scenario - mtls parameters is empty
    cwd = wd.create_dir()
    data = {}
    with open(f"{cwd}/mtls_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)
    wd.delete_dir(cwd)

    # Failure scenario - leaf_common_names key missing
    cwd = wd.create_dir()
    data = {"certs": [{"name": "cert", "ca_chain_filename": "filename.pem"}]}
    with open(f"{cwd}/mtls_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)
    wd.delete_dir(cwd)

    # Failure scenario - missing required keys in leaf_common_names
    cwd = wd.create_dir()
    data = {"certs": [{"name": "cert", "ca_chain_filename": "filename.pem"}], "leaf_common_names": [
        {"friendlyname": "friendlyname"}]}
    with open(f"{cwd}/mtls_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)
    wd.delete_dir(cwd)

    # Failure scenario - certs key empty
    cwd = wd.create_dir()
    data = {"certs": [], "leaf_common_names": [
        {"friendlyname": "friendlyname", "common_name": "common_name"}]}
    with open(f"{cwd}/mtls_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)
    wd.delete_dir(cwd)

    # Failure scenario - missing required keys in certs
    cwd = wd.create_dir()
    data = {"certs": [{"name": "cert"}], "leaf_common_names": [
        {"friendlyname": "friendlyname", "common_name": "common_name"}]}
    with open(f"{cwd}/mtls_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)
    wd.delete_dir(cwd)

    # Failure scenario - duplicate names
    cwd = wd.create_dir()
    data = {"certs": [
        {"name": "cert", "common_name": "common_name1",
            "ca_chain_filename": "filename1.pem"},
        {"name": "cert", "common_name": "common_name2",
            "ca_chain_filename": "filename2.pem"}
    ],
        "leaf_common_names": [
            {"friendlyname": "friendlyname", "common_name": "common_name"}
    ]
    }
    with open(f"{cwd}/mtls_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    with pytest.raises(exceptions.MtlsServiceException):
        mtls_zero_trust_service.load_mtls_parameters("token", "input_url", cwd)
    wd.delete_dir(cwd)


def test_get_mtls_certs_from_tenant_repo(monkeypatch):
    monkeypatch.setattr(
        github_service, "get_multiple_file_content", lambda x, y, z, w: None)

    cwd = wd.create_dir()
    input_model = InputModel(
        environment="dev", action="plan", config_type="mtls", fqdn="fqdn"
    )
    assert mtls_zero_trust_service.get_mtls_certs_from_tenant_repo(
        jwt_token_info, input_model, cwd, [{"ca_chain_filename": "filename1.pem"}]) is None
    wd.delete_dir(cwd)


def test_process_mtls_certs_plan(monkeypatch):
    # setup
    filename1 = "filename1.pem"
    filename2 = "filename2.pem"

    cwd = wd.create_dir()
    data1 = "certificatedata1"
    with open(f"{cwd}/{filename1}", "w", encoding="utf-8") as file:
        file.write(data1)

    data2 = "certificatedata2"
    with open(f"{cwd}/{filename2}", "w", encoding="utf-8") as file:
        file.write(data2)

    # success scenario - add new cert
    current_state = [{"name": "cert1", "zero_trust_name": "zt_name1"}]
    new_mtls_state = [{"name": "cert1", "ca_chain_filename": filename1}, {"name": "cert2", "ca_chain_filename": filename2}]

    cert_name_mock = ["zt_name1", "zt_name2"]
    get_cert_name_mock = Mock(side_effect=cert_name_mock)
    monkeypatch.setattr(mtls_zero_trust_service, "get_cert_name", get_cert_name_mock)
    
    new_certs, certs_to_remove = mtls_zero_trust_service.process_mtls_certs_plan(current_state, new_mtls_state, cwd)
    assert get_cert_name_mock.call_count == len(cert_name_mock)
    assert len(new_certs) == 1
    assert len(certs_to_remove) == 0

    # success scenario - remove cert
    cert_name_mock = ["zt_name1"]
    get_cert_name_mock = Mock(side_effect=cert_name_mock)
    monkeypatch.setattr(mtls_zero_trust_service, "get_cert_name", get_cert_name_mock)

    current_state = [{"name": "cert1", "zero_trust_name": "zt_name1"}, {"name": "cert2", "zero_trust_name": "zt_name2"}]
    new_mtls_state = [{"name": "cert2", "ca_chain_filename": filename1}]
    new_certs, certs_to_remove = mtls_zero_trust_service.process_mtls_certs_plan(current_state, new_mtls_state, cwd)
    assert get_cert_name_mock.call_count == len(cert_name_mock)
    assert len(new_certs) == 0
    assert len(certs_to_remove) == 1

    # # success scenario - no change
    cert_name_mock = ["zt_name1", "zt_name2"]
    get_cert_name_mock = Mock(side_effect=cert_name_mock)
    monkeypatch.setattr(mtls_zero_trust_service, "get_cert_name", get_cert_name_mock)

    current_state = [{"name": "cert1", "zero_trust_name": "zt_name1"}, {"name": "cert2", "zero_trust_name": "zt_name2"}]
    new_mtls_state = [{"name": "cert1", "ca_chain_filename": filename1}, {"name": "cert2", "ca_chain_filename": filename2}]
    new_certs, certs_to_remove = mtls_zero_trust_service.process_mtls_certs_plan(current_state, new_mtls_state, cwd)
    assert get_cert_name_mock.call_count == len(cert_name_mock)
    assert len(new_certs) == 0
    assert len(certs_to_remove) == 0

    wd.delete_dir(cwd)

class TestUploadZeroTrustMtlsCert(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _get_monkeypatch(self, monkeypatch):
        self.monkeypatch = monkeypatch

    def test_no_matching_cert(self):
        monkeypatch = self.monkeypatch
        # Success scenario - no matching cert found, uploading new cert
        monkeypatch.setattr(x509, "load_pem_x509_certificate",
                            lambda x, y: MockCertInfo())
        monkeypatch.setattr(cloudflare.Cloudflare, "__init__",
                            MockCloudflare.__init__)
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_cert_name", lambda x: "zero_trust_name")
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_md5_fingerprint", lambda x: "fingerprint")
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_all_certs_with_same_fingerprint", lambda x, y, z: [])
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_matching_cert_by_name", lambda x, y: None)

        cwd = wd.create_dir()
        data = "certificatedata"
        filename = "filename.pem"
        with open(f"{cwd}/{filename}", "w", encoding="utf-8") as file:
            file.write(data)
        res = mtls_zero_trust_service.upload_zero_trust_mtls_cert(
            [{'name': "cert", 'ca_chain_filename': filename}], "fqdn", "token", "account", cwd)
        expected_res = [
            {"name": "cert", "zero_trust_name": "zero_trust_name", "cert_id": "id", "domain": "fqdn"}]
        self.assertCountEqual(res, expected_res)
        wd.delete_dir(cwd)

    def test_matching_cert(self):
        monkeypatch = self.monkeypatch
        monkeypatch.setattr(x509, "load_pem_x509_certificate",
                            lambda x, y: MockCertInfo())
        monkeypatch.setattr(cloudflare.Cloudflare, "__init__",
                            MockCloudflare.__init__)
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_cert_name", lambda x: "zero_trust_name")
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_md5_fingerprint", lambda x: "fingerprint")
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_all_certs_with_same_fingerprint", lambda x, y, z: ["cert"])
        monkeypatch.setattr(mtls_zero_trust_service,
                            "get_matching_cert_by_name", lambda x, y: MockCertificate)
        monkeypatch.setattr(mtls_zero_trust_service,
                            "add_hostname_to_zero_trust_mtls_cert", lambda w, x, y, z: None)

        # conflict
        cwd = wd.create_dir()
        data = "certificatedata"
        filename = "filename.pem"
        with open(f"{cwd}/{filename}", "w", encoding="utf-8") as file:
            file.write(data)
        res = mtls_zero_trust_service.upload_zero_trust_mtls_cert(
            [{'name': "cert", 'ca_chain_filename': filename}], "fqdn", "token", "account", cwd)
        expected_res = [
            {"name": "cert", "zero_trust_name": "zero_trust_name", "cert_id": "id", "domain": "fqdn"}]
        self.assertCountEqual(res, expected_res)
        wd.delete_dir(cwd)

    def test_mtls_upload_file_doesnt_exist(self):
        cwd = wd.create_dir()
        filename = "filename1.pem"
        with pytest.raises(FileNotFoundError):
            mtls_zero_trust_service.upload_zero_trust_mtls_cert(
                [{'name': "cert", 'ca_chain_filename': filename}], "fqdn", "token", "account", cwd)
        wd.delete_dir(cwd)


def test_remove_zero_trust_mtls_cert(monkeypatch):
    # Success scenario - no certs to remove zt trust empty
    mtls_before_certs = [{"name": "cert", "zero_trust_name": "", "domain": "fqdn"}]
    mtls_after_certs = [{"name": "cert", "zero_trust_name": "zt_cert", "domain": "fqdn"}]
    assert mtls_zero_trust_service.remove_zero_trust_mtls_cert(
        mtls_before_certs, mtls_after_certs, 'token', 'account_id', 'fqdn') is None

    # Success scenario - no certs to remove no change
    mtls_before_certs = [{"name": "cert", "zero_trust_name": "zt_cert", "domain": "fqdn"}]
    mtls_after_certs = [{"name": "cert", "zero_trust_name": "zt_cert", "domain": "fqdn"}]
    assert mtls_zero_trust_service.remove_zero_trust_mtls_cert(
        mtls_before_certs, mtls_after_certs, 'token', 'account_id', 'fqdn') is None

    # Success scenario - no certs to remove added a cert
    mtls_before_certs = [{"name": "cert", "zero_trust_name": "zt_cert", "domain": "fqdn"}]
    mtls_after_certs = [{"name": "cert", "zero_trust_name": "zt_cert", "domain": "fqdn"}, {
        "name": "cert2", "zero_trust_name": "zt_cert2", "domain": "fqdn"}]
    assert mtls_zero_trust_service.remove_zero_trust_mtls_cert(
        mtls_before_certs, mtls_after_certs, 'token', 'account_id', 'fqdn') is None

    # Success scenario - remove a cert do not delete cert
    mtls_before_certs = [{"name": "cert", "zero_trust_name": "zt_cert", "cert_id": "id1", "domain": "fqdn"}, {
        "name": "cert2", "zero_trust_name": "zt_cert2", "cert_id": "id2", "domain": "fqdn"}]
    mtls_after_certs = [
        {"name": "cert", "zero_trust_name": "zt_cert", "cert_id": "id1", "domain": "fqdn"}]
    monkeypatch.setattr(mtls_zero_trust_service,
                        "remove_hostname_from_zero_trust_mtls_cert", lambda w, x, y, z: ["hostname"])
    assert mtls_zero_trust_service.remove_zero_trust_mtls_cert(
        mtls_before_certs, mtls_after_certs, 'token', 'account_id', 'fqdn') is None

    # Success scenario - remove a cert delete cert
    mtls_before_certs = [{"name": "cert", "zero_trust_name": "zt_cert", "cert_id": "id1", "domain": "fqdn"}, {
        "name": "cert2", "zero_trust_name": "zt_cert2", "cert_id": "id2", "domain": "fqdn"}]
    mtls_after_certs = [
        {"name": "cert", "zero_trust_name": "zt_cert", "cert_id": "id1", "domain": "fqdn"}]
    monkeypatch.setattr(mtls_zero_trust_service,
                        "remove_hostname_from_zero_trust_mtls_cert", lambda w, x, y, z: [])
    monkeypatch.setattr(mtls_zero_trust_service,
                        "delete_mtls_cert", lambda x, y, z: None)
    assert mtls_zero_trust_service.remove_zero_trust_mtls_cert(
        mtls_before_certs, mtls_after_certs, 'token', 'account_id', 'fqdn') is None


def test_get_zero_trust_mtls_certs(monkeypatch):
    monkeypatch.setattr(cloudflare.Cloudflare, "__init__",
                        MockCloudflare.__init__)

    res = mtls_zero_trust_service.get_zero_trust_mtls_certs(
        "token", "account_id")
    assert res == [MockCertificate]


def test_get_all_certs_with_same_fingerprint(monkeypatch):
    # found a cert
    monkeypatch.setattr(cloudflare.Cloudflare, "__init__",
                        MockCloudflare.__init__)
    res = mtls_zero_trust_service.get_all_certs_with_same_fingerprint(
        "token", "account_id", "fingerprint")
    assert len(res) == 1

    # could not find a cert
    res = mtls_zero_trust_service.get_all_certs_with_same_fingerprint(
        "token", "account_id", "bad_fingerprint")
    assert len(res) == 0


def test_get_matching_cert_by_name(monkeypatch):
    # found a cert
    res = mtls_zero_trust_service.get_matching_cert_by_name(
        [MockCertificate], "name")
    assert res == MockCertificate

    # could not find a cert
    res = mtls_zero_trust_service.get_matching_cert_by_name(
        [MockCertificate], "bad_name")
    assert res is None


def test_get_cert_name(monkeypatch):
    # success scenario
    monkeypatch.setattr(x509, "load_pem_x509_certificate",
                        lambda x, y: MockCertInfo)
    cert_chain = "-----BEGIN CERTIFICATE-----\ncertificate1\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ncertificate2\n-----END CERTIFICATE-----\n"

    cert_chain = cert_chain.strip()
    h = hashlib.new('sha256')
    h.update(cert_chain.encode())
    sha = h.hexdigest()

    res = mtls_zero_trust_service.get_cert_name(cert_chain)
    expected_res = f"common_name+common_name:{sha}"
    assert res == expected_res


def test_add_hostname_to_zero_trust_mtls_cert(monkeypatch):
    monkeypatch.setattr(cloudflare.Cloudflare, "__init__",
                        MockCloudflare.__init__)

    # hostname already in list
    res = mtls_zero_trust_service.add_hostname_to_zero_trust_mtls_cert(
        "token", "hostname", "id", "account_id")
    assert res is None

    # hostname not in list
    res = mtls_zero_trust_service.add_hostname_to_zero_trust_mtls_cert(
        "token", "hostname2", "id", "account_id")
    assert "hostname" in res.associated_hostnames
    assert "hostname2" in res.associated_hostnames

    # reset
    MockCertificate.associated_hostnames = ["hostname"]


def test_remove_hostname_from_zero_trust_mtls_cert(monkeypatch):
    monkeypatch.setattr(cloudflare.Cloudflare, "__init__",
                        MockCloudflare.__init__)

    # hostname already in list
    res = mtls_zero_trust_service.remove_hostname_from_zero_trust_mtls_cert(
        "token", "hostname", "id", "account_id")
    assert len(res) == 0
    # reset
    MockCertificate.associated_hostnames = ["hostname"]

    # hostname not in list
    res = mtls_zero_trust_service.remove_hostname_from_zero_trust_mtls_cert(
        "token", "hostname2", "id", "account_id")
    assert len(res) == 1


def test_process_authenticated_origin_pulls(monkeypatch):
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    # AOP settings already enabled - Do nothing
    monkeypatch.setattr(
        mtls_zero_trust_service, "get_authenticated_origin_pulls", lambda x, y: True
    )
    assert (
        mtls_zero_trust_service.process_authenticated_origin_pulls(
            "token",
            "zone_name",
            {
                "authenticated_origin_pulls_settings": True
            },
        )
    )
    # AOP settings not enabled - Enable AOP
    monkeypatch.setattr(
        mtls_zero_trust_service, "get_authenticated_origin_pulls", lambda x, y: False
    )
    monkeypatch.setattr(
        mtls_zero_trust_service,
        "update_authenticated_origin_pulls",
        lambda x, y, z: True,
    )
    assert (
        mtls_zero_trust_service.process_authenticated_origin_pulls(
            "token",
            "zone_name",
            {
                "authenticated_origin_pulls_settings": True
            },
        )
    )
    # Disable AOP settings
    monkeypatch.setattr(
        mtls_zero_trust_service, "get_authenticated_origin_pulls", lambda x, y: True
    )
    monkeypatch.setattr(
        mtls_zero_trust_service,
        "update_authenticated_origin_pulls",
        lambda x, y, z: False,
    )
    assert not (
        mtls_zero_trust_service.process_authenticated_origin_pulls(
            "token",
            "zone_name",
            {
                "authenticated_origin_pulls_settings": False
            },
        )
    )


def test_update_authenticated_origin_pulls(monkeypatch):
    # Success scenario
    monkeypatch.setattr(cloudflare.Cloudflare, "__init__", MockCloudflare.__init__)
    assert mtls_zero_trust_service.update_authenticated_origin_pulls(
        "token", "zone_id", True
    )


def test_get_authenticated_origin_pulls(monkeypatch):
    # Success scenario
    monkeypatch.setattr(cloudflare.Cloudflare, "__init__", MockCloudflare.__init__)
    assert mtls_zero_trust_service.get_authenticated_origin_pulls("token", "zone_id")


def raise_exception(jwt_token_info, input_model, cwd):
    raise Exception("Error")


def raise_github_service_exception_load_mtls_params(jwt_token_info, input_model, cwd):
    raise exceptions.GithubServiceException("Error")


class MockCertInfo:
    class MockAttributes:
        value = "common_name"

    class MockSubject:
        def get_attributes_for_oid(self):
            return [MockCertInfo.MockAttributes]

    subject = MockSubject


class MockCloudflare:
    def __init__(self, api_token):
        self.zero_trust = ZeroTrust
        self.origin_tls_client_auth = MockOriginTlsClientAuth


class MockSettings:
    def update(zone_id, enabled):
        return MockUpdateResponse(enabled=enabled)

    def get(zone_id):
        return MockGetResponse()


class MockOriginTlsClientAuth:
    settings = MockSettings


class MockUpdateResponse:
    def __init__(self, enabled):
        self.enabled = enabled


class MockGetResponse:
    def __init__(self):
        self.enabled = True


class MockCertificate:
    name = "name"
    fingerprint = "md5=fingerprint"
    id = "id"
    associated_hostnames = ["hostname"]


class Certificates:
    class Response:
        request = None
        status_code = 200

    def create(certificate, name, account_id, associated_hostnames):
        return MockCertificate

    def get(cert_id, account_id):
        return MockCertificate

    def update(cert_id, account_id, associated_hostnames=None):
        cert = MockCertificate
        if associated_hostnames:
            cert.associated_hostnames = associated_hostnames
        return cert

    def list(account_id):
        return [MockCertificate]


class Access:
    certificates = Certificates


class ZeroTrust:
    access = Access
