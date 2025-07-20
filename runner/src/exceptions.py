"""
Exception classes for API
"""
class TerraformServiceException(Exception):
    """
    High level exception for TerraformService
    """

    def __init__(self, message="Terraform Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class TerraformServiceBackendException(TerraformServiceException):
    """
    Backend configuration Exception
    """

class TerraformServiceOperationException(TerraformServiceException):
    """
    Error in terraform operation init, plan, apply, import
    """

class CfTerraformingException(TerraformServiceException):
    """
    Error in cf-terraforming
    """

class AuthJKWSFetchException(Exception):
    """
    Failed to fetch the .well-known/jwks endpoint to get the public key
    """
    error = "Error in fetching Github JWKS"

class TokenServiceException(Exception):
    """
    High level exception for TokenService
    """

    def __init__(self, message="Token Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class TokenServiceMissingInitialApiTokenException(TokenServiceException):
    """
    Missing initial Cloudflare API token exception
    """

class TokenServiceMissingZoneNameException(TokenServiceException):
    """
    Missing zone name exception
    """

class GithubServiceException(Exception):
    """
    High level exception for GithubService
    """

    def __init__(self, message="Github Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class GithubServiceInvalidInputPathException(GithubServiceException):
    """
    Invalid input path for GithubService
    """

class GithubServiceFileFetchException(GithubServiceException):
    """
    Error in fetching the file from Github
    """

class GithubServiceShaFetchException(GithubServiceException):
    """
    Error in fetching the sha from Github
    """

class GithubServiceBranchCreationException(GithubServiceException):
    """
    Error in creating the branch in Github
    """

class GithubServicePRCreationException(GithubServiceException):
    """
    Error in creating the PR in Github
    """

class GithubServiceFileUpdateException(GithubServiceException):
    """
    Error in updating the file in Github
    """

class GithubServiceInvalidResponseException(GithubServiceException):
    """
    Invalid response from Github
    """

class GithubServiceBranchNotFoundException(GithubServiceException):
    """
    Branch not found in Github
    """

class AWSServiceException(Exception):
    """
    High level exception for AWSService
    """

    def __init__(self, message="AWS Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class AWSServiceRoute53InvalidInputException(AWSServiceException):
    """
    Invalid input for Route53 Update TXT record
    """

class AWSServiceRoute53RecordNotFoundException(AWSServiceException):
    """
    Route53 record not found exception
    """

class AWSServiceRoute53ChangeResourceRecordSetsException(AWSServiceException):
    """
    Error in changing the resource record sets in Route53
    """

class CertificateServiceException(Exception):
    """
    High level exception for CertificateService
    """

    def __init__(self, message="Certificate Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class CertificateServiceInvalidCertException(CertificateServiceException):
    """
    Invalid input for CertificateService
    """

class CertificateServiceCSRGenerationException(CertificateServiceException):
    """
    Error in generating the CSR
    """
class CertificateServiceCFAPIException(CertificateServiceException):
    """
    Error in invoking Cloudflare API for cert management
    """

class MtlsServiceException(Exception):
    """
    Exceptions related to the mTLS Zero Trust Service
    """
    def __init__(self, message="mTLS Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class VenafiServiceException(Exception):
    """
    High level exception for VenafiService
    """

    def __init__(self, message="Venafi Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class CloudflareIAMServiceException(Exception):
    """
    High level exception for Cloudflare IAM Service
    """

    def __init__(self, message="Cloudflare IAM Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message


class AuthServiceException(Exception):
    """
    High level exception for Auth Service
    """

    def __init__(self, message="Auth Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message


class TextRecordServiceException(Exception):
    """
    High level exception for Text Record Service
    """

    def __init__(self, message="TXT Record Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class ValidateYAMLServiceException(Exception):
    """
    High level exception for Validate YAML Service
    """

    def __init__(self, message="Validate YAML Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class SnowServiceException(Exception):
    """
    High level exception for ServiceNow Service
    """

    def __init__(self, message="ServiceNow Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message
    
class SnowServiceAPICallException(SnowServiceException):
    """
    Exception for ServiceNow API call errors
    """

class SnowServiceValueError(SnowServiceException):
    """
    Exception for ServiceNow value errors
    """

class SnowServiceNotFoundError(SnowServiceException):
    """
    Exception for ServiceNow not found errors
    """

class APIConfigException(Exception):
    """
    High level exception for API configuration errors
    """

class NotificationServiceException(Exception):
    """
    High level exception for Notification Service
    """

    def __init__(self, message="Notification Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message

class HashicorpVaultServiceException(Exception):
    """
    High level exception for Hashicorp Vault Service
    """

    def __init__(self, message="Hashicorp Vault Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message
