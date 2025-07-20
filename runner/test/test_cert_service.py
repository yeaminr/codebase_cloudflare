from datetime import datetime, timedelta
import pytest
import httpx
from runner.src.model import InputModel
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import github_service
from runner.src import cloudflare_token_service
from runner.src import cert_service
from runner.src import exceptions
from runner.src import working_dir as wd
from runner.src import venafi_service
from runner.src import terraform_service
from runner.src import helpers


# Common Input
input_model = InputModel(
    environment="dev", action="plan", config_type="cert", fqdn="fqdn"
)
jwt_token_info = JWTTokenInfo(
    repo_name="repo_name",
    branch_name="abc",
    authorized=True,
    org_name="CBA-General",
)


# Test
def test_format_cert_input(monkeypatch):
    # Success - CERT input formatted correctly
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            }
        ]
    }
    # non prod assertion
    assert cert_service.format_cert_input(cert_parameters, "dev") == {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "country": "AU",
                "state": "NSW",
                "locality": "Sydney",
                "organization": "Commonwealth Bank of Australia",
                "organizational_unit": "Group Security",
                "key_type": "rsa2048",
                "signer": "ext",    # ext for nonprod by default
                "scope": "account",
                "name": "test",
            }
        ]
    }
    # prod assertion
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            }
        ]
    }
    assert cert_service.format_cert_input(cert_parameters, "prd") == {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "country": "AU",
                "state": "NSW",
                "locality": "Sydney",
                "organization": "Commonwealth Bank of Australia",
                "organizational_unit": "Group Security",
                "key_type": "rsa2048",
                "signer": "ext-ev", # ext-ev for prod by default
                "scope": "account",
                "name": "test",
            }
        ]
    }

    # Success priority_enabled
    cert_parameters = {
        "priority_enabled": True,
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "priority": 10,
            }
        ],
    }
    assert cert_service.format_cert_input(cert_parameters, "dev") == {
        "priority_enabled": True,
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "country": "AU",
                "state": "NSW",
                "locality": "Sydney",
                "organization": "Commonwealth Bank of Australia",
                "organizational_unit": "Group Security",
                "key_type": "rsa2048",
                "signer": "ext",
                "scope": "account",
                "name": "test",
                "priority": 10,
            }
        ],
    }
    # Error - "certs" not in cert_parameters
    cert_parameters = {
        "priority_enabled": True,
    }
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.format_cert_input(cert_parameters, "dev")

    # Error - priority_enabled is True but "priority" not in certs
    cert_parameters = {
        "priority_enabled": True,
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            }
        ],
    }
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.format_cert_input(cert_parameters, "dev")

    # Error - priority is not enabled but "priority" in certs
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "priority": 10,
            }
        ],
    }
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.format_cert_input(cert_parameters, "dev")

    # Error - Missing required key 'common_name'
    cert_parameters = {
        "certs": [
            {
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            }
        ]
    }
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.format_cert_input(cert_parameters, "dev")

    # Error - Missing required key 'name'
    cert_parameters = {
        "certs": [
            {
                "sans": ["test1", "test2"],
                "tso": 0,
                "common_name": "common_name",
            }
        ]
    }
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.format_cert_input(cert_parameters, "dev")

    # Error - Missing required key 'sans'
    cert_parameters = {
        "certs": [
            {
                "tso": 0,
                "common_name": "common_name",
                "name": "test",
            }
        ]
    }
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.format_cert_input(cert_parameters, "dev")

    # signer provided ext-ev in nonprod
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "signer": "ext-ev"
            }
        ]
    }
    assert cert_service.format_cert_input(cert_parameters, "dev") == {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "country": "AU",
                "state": "NSW",
                "locality": "Sydney",
                "organization": "Commonwealth Bank of Australia",
                "organizational_unit": "Group Security",
                "key_type": "rsa2048",
                "signer": "ext-ev",    # ext for nonprod by default
                "scope": "account",
                "name": "test",
            }
        ]
    }

    # signer provided ext in prod
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "signer": "ext"
            }
        ]
    }
    assert cert_service.format_cert_input(cert_parameters, "prd") == {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "country": "AU",
                "state": "NSW",
                "locality": "Sydney",
                "organization": "Commonwealth Bank of Australia",
                "organizational_unit": "Group Security",
                "key_type": "rsa2048",
                "signer": "ext",    # ext for nonprod by default
                "scope": "account",
                "name": "test",
            }
        ]
    }

    # invalid signer provided
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "signer": "invalid"
            }
        ]
    }
    with pytest.raises(exceptions.CertificateServiceException) as exc_info:
        cert_service.format_cert_input(cert_parameters, "dev")
    assert "Invalid signer provided" in str(exc_info.value)

    # test Bankwest org in nonprod
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "organization": "Bankwest"
            }
        ]
    }
    assert cert_service.format_cert_input(cert_parameters, "dev") == {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "country": "AU",
                "state": "NSW",
                "locality": "Sydney",
                "organization": "Bankwest",
                "organizational_unit": "Group Security",
                "key_type": "rsa2048",
                "signer": "ext",
                "scope": "account",
                "name": "test",
            }
        ]
    }

    # test Bankwest org in prod
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "organization": "Commonwealth Bank Of Australia (Bankwest)"
            }
        ]
    }
    assert cert_service.format_cert_input(cert_parameters, "prd") == {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "country": "AU",
                "state": "NSW",
                "locality": "Sydney",
                "organization": "Commonwealth Bank Of Australia (Bankwest)",
                "organizational_unit": "Group Security",
                "key_type": "rsa2048",
                "signer": "ext-ev",
                "scope": "account",
                "name": "test",
            }
        ]
    }

    # test bad org
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
                "organization": "Bad Org"
            }
        ]
    }
    with pytest.raises(exceptions.CertificateServiceException) as exc_info:
        cert_service.format_cert_input(cert_parameters, "dev")
    assert "Provided organization is not allowed for the selected signer" in str(exc_info.value)


    # Error - Duplicate value for 'name'
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            },
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            },
        ]
    }
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.format_cert_input(cert_parameters, "dev")


def test_list_cf_account_csr(monkeypatch):
    # Success - List CF Account Certs
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    assert cert_service.list_cf_account_csr("token", "account_id") == [
        {
            "sans": ["test1", "test2"],
            "common_name": "test",
            "id": "csr_id",
            "csr": "csr_string",
        },
        {
            "sans": ["test1", "test2"],
            "common_name": "test",
            "id": "csr_id",
            "csr": "csr_string",
        },
    ]
    # Failure scenario - HTTP error Failed to list account CSRs
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_account_csr("token", "http_error")

    # Failure scenario - "result" key missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_account_csr("token", "result_missing")

    # Result empty
    assert cert_service.list_cf_account_csr("token", "result_empty") == []

    # Result info missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_account_csr("token", "result_info_missing")


def test_get_cf_account_csr_by_input(monkeypatch):
    # Success - CSR found
    csr_params = {
        "common_name": "common_name",
        "sans": ["test1", "test2"],
        "name": "test",
    }
    all_account_csrs = [
        {
            "sans": ["test1", "test2"],
            "common_name": "common_name",
            "name": "test",
            "csr": "csr_string",
            "id": "csr_id",
        }
    ]

    assert cert_service.get_cf_account_csr_by_input(csr_params, all_account_csrs) == {
        "common_name": "common_name",
        "sans": ["test1", "test2"],
        "name": "test",
        "csr": "csr_string",
        "id": "csr_id",
    }

    # Error - CSR not found
    assert not cert_service.get_cf_account_csr_by_input(csr_params, [])


def test_get_cf_zone_cert_by_csr(monkeypatch):
    # Success - Cert found
    all_zone_certs = [
        {
            "id": "cert_id_1",
            "expires_on": "expires_on",
            "custom_csr_id": "other_csr_id",
        },
        {
            "id": "cert_id_2",
            "expires_on": "expires_on",
            "custom_csr_id": "csr_id",
        },
    ]
    assert cert_service.get_cf_zone_cert_by_csr("csr_id", all_zone_certs) == {
        "expires_on": "expires_on",
        "id": "cert_id_2",
        "custom_csr_id": "csr_id",
        "cert_pack_id": "cert_id_2",
    }

    # Cert not found
    assert not cert_service.get_cf_zone_cert_by_csr("csr_id", [])


def test_get_cf_zone_cert_by_id(monkeypatch):
    # Success - Get Zone Cert by ID
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    assert cert_service.get_cf_zone_cert_by_id("token", "zone_id", "cert_pack_id") == {
        "id": "cert_pack_id_1",
        "expires_on": "expires_on",
        "custom_csr_id": "csr_id",
    }

    # Get Zone Cert by ID - Result key missing
    assert not cert_service.get_cf_zone_cert_by_id(
        "token", "zone_id", "result_key_missing"
    )

    # Get Zone Cert by ID - No Cert found
    assert not cert_service.get_cf_zone_cert_by_id("token", "zone_id", "not_found")

    # Failure - Get Zone Cert by ID - HTTP error
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.get_cf_zone_cert_by_id("token", "zone_id", "http_error")


def test_generate_cf_account_csr(monkeypatch):
    # Success scenario
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    assert cert_service.generate_cf_account_csr("token", "account_id", "csr_input") == {
        "common_name": "test",
        "csr": "csr_string",
        "id": "csr_id",
        "sans": ["test1", "test2"],
    }

    # Failure scenario - HTTP error - Failed to generate CSR
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.generate_cf_account_csr("token", "http_error", "csr_input")

    # Failure scenario - "result" key missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.generate_cf_account_csr("token", "result_missing", "csr_input")


def test_list_cf_zone_certificates(monkeypatch):
    # Success scenario
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    assert cert_service.list_cf_zone_certificates("token", "zone_id") == [
        {
            "id": "cert_id_1",
            "type": "sni_custom",
            "hosts": "autopoc1.dev.evolveatcommbank.com.au",
            "expires_on": "expires_on",
            "custom_csr_id": "custom_csr_id",
        },
        {
            "id": "cert_id_1",
            "type": "sni_custom",
            "hosts": "autopoc1.dev.evolveatcommbank.com.au",
            "expires_on": "expires_on",
            "custom_csr_id": "custom_csr_id",
        },
    ]

    # Failure scenario - HTTP error - Failed to list certificates
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_zone_certificates("token", "http_error")

    # Failure scenario - "result" key missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_zone_certificates("token", "result_missing")

    # Result empty
    assert cert_service.list_cf_zone_certificates("token", "result_empty") == []

    # Result info missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_zone_certificates("token", "result_info_missing")


def test_upload_cf_zone_certificate(monkeypatch):
    # Success scenario
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    assert cert_service.upload_cf_zone_certificate(
        "token", "zone_id", "csr_id", "cert_string"
    ) == {"expires_on": "cert_expiry", "id": "cert_pack_id"}

    # Failure scenario - Failed to upload certificate
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.upload_cf_zone_certificate(
            "token", "http_error", "csr_id", "cert_string"
        )

    # Failure scenario - Failed to upload certificate - Empty response
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.upload_cf_zone_certificate(
            "token", "empty_result", "csr_id", "cert_string"
        )


def test_remove_cf_zone_certificate(monkeypatch):
    # Success scenario
    monkeypatch.setattr(httpx, "delete", mock_httpx_delete)
    try:
        cert_service.remove_cf_zone_certificate("token", "zone_id", "cert_pack_id")
    except Exception as e:
        assert False

    # Failure scenario - Failed to remove certificate
    monkeypatch.setattr(httpx, "delete", mock_httpx_delete)
    with pytest.raises(exceptions.CertificateServiceCFAPIException):
        cert_service.remove_cf_zone_certificate("token", "http_error", "cert_pack_id")

    # Failure scenario - Failed to remove certificate - Empty response
    monkeypatch.setattr(httpx, "delete", mock_httpx_delete)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.remove_cf_zone_certificate(
            "token", "empty_response", "cert_pack_id"
        )


def test_create_cert(monkeypatch):
    # Success scenario
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e: "certificate_string",
    )
    monkeypatch.setattr(
        cert_service,
        "upload_cf_zone_certificate",
        lambda a, b, c, d: {
            "expires_on": "cert_expiry",
            "id": "cert_pack_id",
        },
    )
    assert cert_service.create_cert(
        "token", "dev", "zone_id", {"id": "csr_id"}, {"signer": "ext", "tso": "CI1234", "sans": []}
    ) == {
        "expires_on": "cert_expiry",
        "id": "cert_pack_id",
    }

    # Failure scenario - Venafi refresh return None
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e: None,
    )
    assert cert_service.create_cert("token", "dev", "zone_id", {}, {"signer": "ext", "tso": "CI1234", "sans": []}) == None


def test_get_cert_success(monkeypatch):
    # Success - CSR and Cert To be Created and Uploaded
    monkeypatch.setattr(wd, "create_dir", lambda: "working_dir")
    monkeypatch.setattr(
        cert_service, "load_cert_parameters", lambda x, y, z: "cert_params"
    )
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token",
        lambda x : (["tokenid"], "dummy_token")
    )
    monkeypatch.setattr(
        cert_service, "get_cert_tf_state", lambda x, y, z: "cert_tf_state"
    )
    monkeypatch.setattr(cert_service, "process_cert_plan", lambda x, y, z: "cert_plan")
    monkeypatch.setattr(
        cert_service,
        "remove_cert_plan",
        lambda x, y: [
            {
                "name": "test",
                "csr_id": "csr_id",
                "cert_pack_id": "cert_pack_id",
                "expires_on": "expires_on",
                "common_name": "common_name",
                "sans": ["test1", "test2"],
            }
        ],
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(wd, "delete_dir", lambda x: None)
    assert cert_service.get_cert(input_model, jwt_token_info) == [
        {
            "name": "test",
            "csr_id": "csr_id",
            "cert_pack_id": "cert_pack_id",
            "expires_on": "expires_on",
            "common_name": "common_name",
            "sans": ["test1", "test2"],
        }
    ]


def test_get_cert_working_dir_none(monkeypatch):
    # Working dir is None or not created
    monkeypatch.setattr(wd, "create_dir", lambda: None)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.get_cert(input_model, jwt_token_info)


def test_process_cert_plan_csr_cert_not_exists(monkeypatch):
    # Success - CSR and Cert To be Created and Uploaded
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(cert_service, "list_cf_account_csr", lambda x, y: None)
    monkeypatch.setattr(cert_service, "list_cf_zone_certificates", lambda x, y: None)
    monkeypatch.setattr(cert_service, "get_cf_account_csr_by_input", lambda x, y: None)
    monkeypatch.setattr(cert_service, "get_cf_zone_cert_by_csr", lambda x, y: None)
    assert cert_service.process_cert_plan(
        {
            "certs": [
                {
                    "common_name": "common_name",
                    "sans": ["test1", "test2"],
                    "tso": 0,
                    "name": "test",
                }
            ]
        },
        input_model, "token",
    ) == [
        {
            "name": "test",
            "csr_id": "To be generated",
            "cert_pack_id": "To be generated",
            "expires_on": "",
            "common_name": "common_name",
            "sans": ["test1", "test2"],
        }
    ]


def test_process_cert_plan_csr_exists_cert_new(monkeypatch):
    # Success - CSR exists and Cert To be Created and Uploaded
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(cert_service, "list_cf_account_csr", lambda x, y: None)
    monkeypatch.setattr(cert_service, "list_cf_zone_certificates", lambda x, y: None)
    monkeypatch.setattr(
        cert_service,
        "get_cf_account_csr_by_input",
        lambda x, y: {
            "common_name": "common_name",
            "sans": ["test1", "test2"],
            "name": "test",
            "id": "csr_id",
        },
    )
    monkeypatch.setattr(cert_service, "get_cf_zone_cert_by_csr", lambda x, y: None)
    assert cert_service.process_cert_plan(
        {
            "certs": [
                {
                    "common_name": "common_name",
                    "sans": ["test1", "test2"],
                    "tso": 0,
                    "name": "test",
                }
            ]
        },
        input_model, "token",
    ) == [
        {
            "name": "test",
            "csr_id": "csr_id",
            "cert_pack_id": "To be generated",
            "expires_on": "",
            "common_name": "common_name",
            "sans": ["test1", "test2"],
        }
    ]


def test_process_cert_plan_csr_cert_exists(monkeypatch):
    # Success - CSR and Cert exists
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(cert_service, "list_cf_account_csr", lambda x, y: None)
    monkeypatch.setattr(cert_service, "list_cf_zone_certificates", lambda x, y: None)
    monkeypatch.setattr(
        cert_service,
        "get_cf_account_csr_by_input",
        lambda x, y: {
            "common_name": "common_name",
            "sans": ["test1", "test2"],
            "name": "test",
            "id": "csr_id",
        },
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y: {
            "expires_on": "expires_on",
            "cert_pack_id": "cert_pack_id",
            "custom_csr_id": "csr_id",
            "priority": 10,
        },
    )
    assert cert_service.process_cert_plan(
        {
            "priority_enabled": True,
            "certs": [
                {
                    "common_name": "common_name",
                    "sans": ["test1", "test2"],
                    "tso": 0,
                    "name": "test",
                    "priority": 10,
                }
            ],
        },
        input_model, "token",
    ) == [
        {
            "name": "test",
            "csr_id": "csr_id",
            "cert_pack_id": "cert_pack_id",
            "expires_on": "expires_on",
            "common_name": "common_name",
            "sans": ["test1", "test2"],
            "priority": "10",
        }
    ]
    # Success - CSR and Cert exists but priority is getting updated 5 to 10
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y: {
            "expires_on": "expires_on",
            "cert_pack_id": "cert_pack_id",
            "custom_csr_id": "csr_id",
            "priority": 5,
        },
    )
    assert cert_service.process_cert_plan(
        {
            "priority_enabled": True,
            "certs": [
                {
                    "common_name": "common_name",
                    "sans": ["test1", "test2"],
                    "tso": 0,
                    "name": "test",
                    "priority": 10,
                }
            ],
        },
        input_model, "token",
    ) == [
        {
            "name": "test",
            "csr_id": "csr_id",
            "cert_pack_id": "cert_pack_id",
            "expires_on": "expires_on",
            "common_name": "common_name",
            "sans": ["test1", "test2"],
            "priority": "5 -> 10",
        }
    ]


def test_process_cert_success(monkeypatch):
    # Success - CSR exist and Cert exist
    monkeypatch.setattr(
        cert_service,
        "load_cert_parameters",
        lambda x, y, z: {"priority_enabled": True, "certs": []},
    )
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x : (["tokenid"], "dummy_token")
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(
        cert_service, "get_cert_tf_state", lambda x, y, z: "cert_tf_state"
    )
    monkeypatch.setattr(
        cert_service,
        "process_cert_update",
        lambda x, y, z: None,
    )
    monkeypatch.setattr(terraform_service, "run", lambda x, y: None)
    monkeypatch.setattr(cert_service, "remove_cert", lambda a, b, c, d: None)
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(
        cert_service,
        "process_cert_priority",
        lambda a, b, c, d: [
            {
                "name": "test",
                "csr_id": "csr_id",
                "cert_pack_id": "cert_pack_id",
                "expires_on": "expires_on",
                "common_name": "common_name",
                "sans": ["test1"],
            }
        ],
    )
    monkeypatch.setattr(cert_service, "disable_universal_ssl", lambda x, y: None)
    assert cert_service.update_cert(input_model, jwt_token_info) == [
        {
            "name": "test",
            "csr_id": "csr_id",
            "cert_pack_id": "cert_pack_id",
            "expires_on": "expires_on",
            "common_name": "common_name",
            "sans": ["test1"],
        }
    ]


def test_process_working_dir_none(monkeypatch):
    # Working dir is None or not created
    monkeypatch.setattr(wd, "create_dir", lambda: None)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.update_cert(input_model, jwt_token_info)


def test_process_cert_update_csr_cert_exists(monkeypatch):
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            }
        ]
    }
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(cert_service, "list_cf_account_csr", lambda x, y: None)
    monkeypatch.setattr(cert_service, "list_cf_zone_certificates", lambda x, y: None)
    monkeypatch.setattr(
        cert_service,
        "get_cf_account_csr_by_input",
        lambda x, y: {
            "common_name": "common_name",
            "sans": ["test1", "test2"],
            "name": "test",
            "id": "csr_id",
        },
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y: {
            "expires_on": "expires_on",
            "cert_pack_id": "cert_pack_id",
            "custom_csr_id": "csr_id",
        },
    )
    assert cert_service.process_cert_update(cert_parameters, input_model, "token") == [
        {
            "cert_pack_id": "cert_pack_id",
            "common_name": "common_name",
            "csr_id": "csr_id",
            "expires_on": "expires_on",
            "name": "test",
            "sans": ["test1", "test2"],
        }
    ]


def test_process_cert_update_csr_exists_cert_new(monkeypatch):
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            }
        ]
    }
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(cert_service, "list_cf_account_csr", lambda x, y: None)
    monkeypatch.setattr(cert_service, "list_cf_zone_certificates", lambda x, y: None)
    monkeypatch.setattr(
        cert_service,
        "get_cf_account_csr_by_input",
        lambda x, y: {
            "common_name": "common_name",
            "sans": ["test1", "test2"],
            "name": "test",
            "id": "csr_id",
        },
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y: None,
    )
    monkeypatch.setattr(
        cert_service,
        "create_cert",
        lambda a, b, c, d, e: {
            "id": "cert_pack_id",
            "common_name": "common_name",
            "csr_id": "csr_id",
            "expires_on": "expires_on",
            "name": "test",
            "sans": ["test1", "test2"],
        },
    )
    assert cert_service.process_cert_update(cert_parameters, input_model, "token") == [
        {
            "cert_pack_id": "cert_pack_id",
            "common_name": "common_name",
            "csr_id": "csr_id",
            "expires_on": "expires_on",
            "name": "test",
            "sans": ["test1", "test2"],
        }
    ]


def test_process_cert_update_csr_cert_new(monkeypatch):
    cert_parameters = {
        "certs": [
            {
                "common_name": "common_name",
                "sans": ["test1", "test2"],
                "tso": 0,
                "name": "test",
            }
        ]
    }
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(cert_service, "list_cf_account_csr", lambda x, y: None)
    monkeypatch.setattr(cert_service, "list_cf_zone_certificates", lambda x, y: None)
    monkeypatch.setattr(
        cert_service,
        "get_cf_account_csr_by_input",
        lambda x, y: None,
    )
    monkeypatch.setattr(
        cert_service,
        "generate_cf_account_csr",
        lambda x, y, z: {
            "id": "csr_id",
            "common_name": "common_name",
            "sans": ["test1", "test2"],
        },
    )
    monkeypatch.setattr(
        cert_service,
        "create_cert",
        lambda a, b, c, d, e: {
            "id": "cert_pack_id",
            "common_name": "common_name",
            "csr_id": "csr_id",
            "expires_on": "expires_on",
            "name": "test",
            "sans": ["test1", "test2"],
        },
    )
    assert cert_service.process_cert_update(cert_parameters, input_model,"token") == [
        {
            "cert_pack_id": "cert_pack_id",
            "common_name": "common_name",
            "csr_id": "csr_id",
            "expires_on": "expires_on",
            "name": "test",
            "sans": ["test1", "test2"],
        }
    ]


def test_load_cert_parameters(monkeypatch):
    # Success scenario
    cwd = wd.create_dir()
    with open(f"{cwd}/cert_parameters.yml", "w", encoding="utf-8") as file:
        file.write("certs: yaml")

    input_model = InputModel(
        environment="dev",
        action="plan",
        config_type="cert",
        fqdn="example.com.au",
    )

    monkeypatch.setattr(github_service, "main", lambda x, y, z: None)
    monkeypatch.setattr(cert_service, "format_cert_input", lambda x, y: "cert_params")
    assert cert_service.load_cert_parameters(input_model, "token", cwd) == "cert_params"
    wd.delete_dir(cwd)

    # Failure scenario - Error in reading file using Github service
    monkeypatch.setattr(
        github_service, "main", raise_github_service_exception_load_cert_params
    )
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.load_cert_parameters(input_model, "token", cwd)

    # Failure scenario - Error in reading file using Github service
    monkeypatch.setattr(github_service, "main", raise_exception_load_cert_params)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.load_cert_parameters(input_model, "token", cwd)


def test_get_cert_tf_state(monkeypatch):
    # Success scenario
    monkeypatch.setattr(wd, "copy_tf_files", lambda x, y: None)
    monkeypatch.setattr(
        terraform_service, "terraform_init", lambda x, y, z: (0, "stdout", "stderr")
    )
    monkeypatch.setattr(
        terraform_service,
        "terraform_output",
        lambda x, y, z: (0, '{"cert_pack_id": "cert_pack_id"}', "stderr"),
    )
    assert cert_service.get_cert_tf_state(
        "working_dir", input_model, "output_name"
    ) == {"cert_pack_id": "cert_pack_id"}

    # Failure scenario - Error in Terraform init
    monkeypatch.setattr(
        terraform_service, "terraform_init", lambda x, y, z: (1, "stdout", "stderr")
    )
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.get_cert_tf_state("working_dir", input_model, "output_name")

    # Failure scenario - Error in Terraform output
    monkeypatch.setattr(
        terraform_service, "terraform_init", lambda x, y, z: (0, "stdout", "stderr")
    )
    monkeypatch.setattr(
        terraform_service,
        "terraform_output",
        lambda x, y, z: (1, "stdout", "stderr"),
    )
    assert (
        cert_service.get_cert_tf_state("working_dir", input_model, "output_name") == {}
    )


def test_remove_cert(monkeypatch):
    # Cert id before and after empty
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_id",
        lambda x, y, z: {"result": {"id": "cert_pack_id"}},
    )
    monkeypatch.setattr(
        cert_service, "remove_cf_zone_certificate", lambda x, y, z: None
    )
    assert cert_service.remove_cert("token", "zone_id", {}, {}) is None

    # Cert id before and after not empty
    def mock_remove_cf_zone_certificate(token, zone_id, cert_pack_id):
        if cert_pack_id == "cert_id_2":
            return None
        else:
            raise Exception(f"{cert_pack_id} removed")

    monkeypatch.setattr(
        cert_service, "remove_cf_zone_certificate", mock_remove_cf_zone_certificate
    )
    assert (
        cert_service.remove_cert(
            "token",
            "zone_id",
            {"cert_id_1": "cert_id_1", "cert_id_2": "cert_id_2"},
            {"cert_id_1": "cert_id_1"},
        )
        is None
    )

    # Cert id in state but not in CF
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_id",
        lambda x, y, z: None,
    )
    monkeypatch.setattr(
        cert_service, "remove_cf_zone_certificate", mock_remove_cf_zone_certificate
    )
    assert (
        cert_service.remove_cert(
            "token",
            "zone_id",
            {"cert_id_1": "cert_id_1"},
            {"cert_id_2": "cert_id_2"},
        )
        is None
    )


def test_remove_cert_plan(monkeypatch):
    # Success scenario
    cert_ids_from_state = {
        "v1": {
            "cert_pack_id": "cert_pack_id_v1",
            "common_name": "common_name",
            "csr_id": "csr_id_v1",
            "expires_on": "expires_on",
            "sans": ["test_v1"],
            "name": "v1",
        },
        "v2": {
            "cert_pack_id": "cert_pack_id_v2",
            "common_name": "common_name",
            "csr_id": "csr_id_v2",
            "expires_on": "expires_on",
            "sans": ["test_v2"],
            "name": "v2",
        },
    }
    cert_output_response = [
        {
            "cert_pack_id": "cert_pack_id_v2",
            "common_name": "common_name",
            "csr_id": "csr_id_v2",
            "expires_on": "expires_on",
            "name": "v2",
            "sans": ["test_v2"],
        }
    ]
    assert cert_service.remove_cert_plan(cert_ids_from_state, cert_output_response) == [
        {
            "cert_pack_id": "cert_pack_id_v2",
            "common_name": "common_name",
            "csr_id": "csr_id_v2",
            "expires_on": "expires_on",
            "name": "v2",
            "sans": ["test_v2"],
        },
        {
            "cert_pack_id": "cert_pack_id_v1 To be removed",
            "common_name": "common_name",
            "csr_id": "csr_id_v1",
            "expires_on": "expires_on",
            "name": "v1",
            "sans": ["test_v1"],
        },
    ]


def test_process_cert_priority(monkeypatch):
    # Success scenario
    cert_parameters = {
        "certs": [
            {
                "name": "test",
                "priority": 10,
            }
        ]
    }
    cert_output_response = [
        {
            "cert_pack_id": "cert_pack_id",
            "name": "test",
        }
    ]
    monkeypatch.setattr(
        cert_service,
        "update_cf_zone_cert_priority",
        lambda x, y, z: [
            {
                "id": "cert_pack_id",
                "priority": 10,
            }
        ],
    )
    assert cert_service.process_cert_priority(
        cert_parameters, cert_output_response, "cf_token", "zone_id"
    ) == [
        {
            "name": "test",
            "cert_pack_id": "cert_pack_id",
            "priority": 10,
        }
    ]


def test_update_cf_zone_cert_priority(monkeypatch):
    # Success - Update CF Zone Cert Priority
    monkeypatch.setattr(httpx, "put", mock_httpx_put)
    assert cert_service.update_cf_zone_cert_priority(
        "token", "zone_id", {"payload": "test"}
    ) == [
        {
            "id": "cert_id",
            "type": "sni_custom",
            "hosts": [
                "test1",
            ],
            "expires_on": "expires_on",
            "priority": 10,
            "status": "active",
            "custom_csr_id": "csr_id",
        }
    ]

    # Result key missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.update_cf_zone_cert_priority(
            "token", "zone_id_result_key_missing", {"payload": "test"}
        )

    # HTTP error
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.update_cf_zone_cert_priority(
            "token", "zone_id_http_error", {"payload": "test"}
        )


# Mocks
def mock_delete_all_tokens(token_store, token):
    raise Exception("Error")


def mock_get_file_content(cert_input_url, working_dir):
    raise Exception("Error")


def mock_httpx_get(url, headers=None):
    if (
        url
        == "https://api.cloudflare.com/client/v4/accounts/account_id/custom_csrs?page=1&per_page=50"
    ) or (
        url
        == "https://api.cloudflare.com/client/v4/accounts/account_id/custom_csrs?page=2&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sans": ["test1", "test2"],
                        "common_name": "test",
                        "id": "csr_id",
                        "csr": "csr_string",
                    }
                ],
                "result_info": {
                    "page": 1,
                    "per_page": 1,
                    "total_pages": 2,
                    "count": 1,
                    "total_count": 1,
                },
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_missing/custom_csrs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result_missing": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_empty/custom_csrs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_info_missing/custom_csrs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sans": ["test1", "test2"],
                        "common_name": "test",
                        "id": "csr_id",
                        "csr": "csr_string",
                    }
                ]
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates/cert_pack_id"
    ):
        return httpx.Response(
            200,
            json={
                "result": {
                    "id": "cert_pack_id_1",
                    "expires_on": "expires_on",
                    "custom_csr_id": "csr_id",
                },
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates/result_key_missing"
    ):
        return httpx.Response(
            200,
            json={},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates/not_found"
    ):
        return httpx.Response(
            404,
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates/http_error"
    ):
        return httpx.Response(
            500,
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates?page=1&per_page=50"
    ) or (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates?page=2&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "id": "cert_id_1",
                        "type": "sni_custom",
                        "hosts": "autopoc1.dev.evolveatcommbank.com.au",
                        "expires_on": "expires_on",
                        "custom_csr_id": "custom_csr_id",
                    }
                ],
                "result_info": {
                    "page": 1,
                    "per_page": 50,
                    "total_pages": 2,
                    "count": 0,
                    "total_count": 1,
                },
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/cert_exist/custom_certificates?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "id": "cert_id_1",
                        "type": "sni_custom",
                        "hosts": "autopoc1.dev.evolveatcommbank.com.au",
                        "expires_on": "expires_on",
                        "custom_csr_id": "custom_csr_id",
                    }
                ],
                "result_info": {
                    "page": 1,
                    "per_page": 50,
                    "total_pages": 1,
                    "count": 0,
                    "total_count": 1,
                },
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/result_missing/custom_certificates?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result_missing": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/result_empty/custom_certificates?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/result_info_missing/custom_certificates?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sans": ["test1", "test2"],
                        "common_name": "test",
                        "id": "csr_id",
                        "csr": "csr_string",
                    }
                ]
            },
            request=httpx.Request("GET", "test"),
        )
    return httpx.Response(
        404,
        request=httpx.Request("GET", "test"),
    )


def mock_httpx_post(url, json, headers):
    if url == "https://api.cloudflare.com/client/v4/accounts/account_id/custom_csrs":
        return httpx.Response(
            201,
            json={
                "result": {
                    "sans": ["test1", "test2"],
                    "common_name": "test",
                    "id": "csr_id",
                    "csr": "csr_string",
                }
            },
            request=httpx.Request("POST", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_missing/custom_csrs"
    ):
        return httpx.Response(
            201,
            json={"result_missing": {}},
            request=httpx.Request("POST", "test"),
        )

    elif (
        url == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates"
    ):
        return httpx.Response(
            200,
            json={"result": {"expires_on": "cert_expiry", "id": "cert_pack_id"}},
            request=httpx.Request("POST", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/empty_result/custom_certificates"
    ):
        return httpx.Response(
            200,
            json={},
            request=httpx.Request("POST", "test"),
        )
    return httpx.Response(
        404,
        request=httpx.Request("POST", "test"),
    )


def mock_httpx_delete(url, headers):
    if (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates/cert_pack_id"
    ):
        return httpx.Response(
            200,
            request=httpx.Request("DELETE", "test"),
            json={"result": {"id": "cert_pack_id"}},
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/empty_response/custom_certificates/cert_pack_id"
    ):
        return httpx.Response(
            200,
            request=httpx.Request("DELETE", "test"),
            json={},
        )
    return httpx.Response(
        404,
        request=httpx.Request("DELETE", "test"),
    )


def mock_httpx_put(url, json, headers):
    if (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates/prioritize"
    ):
        return httpx.Response(
            200,
            request=httpx.Request("PUT", "test"),
            json={
                "result": [
                    {
                        "id": "cert_id",
                        "type": "sni_custom",
                        "hosts": [
                            "test1",
                        ],
                        "expires_on": "expires_on",
                        "priority": 10,
                        "status": "active",
                        "custom_csr_id": "csr_id",
                    },
                ],
                "success": True,
                "errors": [],
                "messages": [],
            },
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id_result_key_missing/custom_certificates/prioritize"
    ):
        return httpx.Response(
            200,
            request=httpx.Request("PUT", "test"),
            json={},
        )
    return httpx.Response(
        404,
        request=httpx.Request("PUT", "test"),
    )


def raise_exception_load_cert_params(jwt_token_info, input_model, cwd):
    raise Exception("Error")


def raise_github_service_exception_load_cert_params(jwt_token_info, input_model, cwd):
    raise exceptions.GithubServiceException("Error")
