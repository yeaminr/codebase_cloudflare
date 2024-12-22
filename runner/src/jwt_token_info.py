import json

class JWTTokenInfo:
    """
    Represents information about a JWT token.

    Attributes:
        authorized (bool): Indicates whether the token is authorized.
        repo_name (str): The name of the repository.
        org_name (str): The name of the organization.
        branch_name (str): The name of the branch.
    """

    def __init__(
        self, authorized: bool, repo_name: str, org_name: str, branch_name: str
    ):
        self.authorized = authorized
        self.repo_name = repo_name
        self.org_name = org_name
        self.branch_name = branch_name

    def __str__(self) -> str:
        return json.dumps({"authorized": self.authorized, "repo_name": self.repo_name,"org_name": self.org_name, "branch_name": self.branch_name})
