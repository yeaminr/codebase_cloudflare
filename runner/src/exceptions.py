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

class CertificateServiceInvalidCSRException(CertificateServiceException):
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

class CertificateServiceInvalidCertException(CertificateServiceException):
    """
    Invalid certificate exception
    """

class VenafiServiceException(Exception):
    """
    High level exception for VenafiService
    """

    def __init__(self, message="Venafi Service Exception"):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return self.message
    
    