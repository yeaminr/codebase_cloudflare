# Workflows

This readme explains the purpose of each workflow and how they interact to form the CICD development process. All workflows are yaml files stored within the `/.github/workflows` directory. 

## List of Workflows
| Workflow File Name | Type | Description |
|---------------------|----|-------------|
| cloudflare_all_config_deploy.yml | Re-usable workflow | To deploy all Cloudflare configuration yaml files (zone, app_list, security, cdn, cert, tls) to Cloudflare. It will be invoked from tenant repo in https://github.com/CBA-Edge-Security-Platform-RSTD org |
| cloudflare_config_deploy.yml | Re-usable workflow | To deploy chosen Cloudflare configuration yaml files (zone, app_list, security, cdn, cert, tls) to Cloudflare. It will be invoked from tenant repo in https://github.com/CBA-Edge-Security-Platform-RSTD org |
| cloudflare_plan_drift.yml | Re-usable workflow | To run on a schedule basis on all tenants repo to identify the drifts between terraform state and actual configuration |
| cloudflare_reusable_automation_testing.yml | TBF | TO BE FILLED BY TEST AUTOMATION TEAM |
| docker_release.yml | Self | To build and push ES runner docker image to artifactory |
| edgesecurity_api_test_workflow.yml | TBF | TO BE FILLED BY TEST AUTOMATION TEAM |
| repo_branch_naming_convention_check.yml | Self | To check if the branch name is following the naming convention |
| repo_codebase_tag_release.yml | Self | To create a tag release for the codebase for every push to main |
| repo_sonarqube_analysis.yml | Self | To run sonarqube analysis on the codebase for every push to main and PR |
| tenant_repo_naming_convention_check.yml | Re-usable workflow | To check if the tenant repo name is following the naming convention for branch and PR title |
