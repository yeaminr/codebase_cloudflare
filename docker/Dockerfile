# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.11
ARG BASE_IMAGE_SHA=b94af75d4ff65c50bf1b2119bca6d0ba707037bacd0cb75314801a6953c03241

# SETUP STAGE
# https://pages.github.source.internal.cba/ApplicationInfrastructure/public-docker-library/#librarypython
# https://docker.internal.cba/ui/native/applicationinfrastructure-public-docker-prod-local/library/python/
FROM applicationinfrastructure-public.docker.internal.cba/ca-certificates:2.0.0-20200817031039-14286ee AS certificates
FROM applicationinfrastructure-public.docker.internal.cba/repo-settings/debian:1.4.0-20230829033134-ca374f1 AS debian-settings

# BUILD STAGE
FROM hub.docker.internal.cba/python:${PYTHON_VERSION}-slim-buster@sha256:${BASE_IMAGE_SHA}

ARG ARTIFACTORY_SERVICE_USERNAME

# Set timezone to Sydney time
ENV TZ="Australia/Sydney"

# Copy standard CA and CBA certificates
COPY --from=certificates /internal/ /usr/local/share/ca-certificates/

# Set OS source package repository URLs and pip config
COPY --from=debian-settings debian/buster/etc/apt/sources.list /etc/apt/sources.list

# Set PyPi pip config
# Set up pip config to contact the private Cyberauto PyPi repository temporarily
# The index-url will be updated to point to the Edge Security PyPi repository once it's set up
RUN cat <<EOF > /etc/pip.conf
[global]
index-url = https://artifactory.internal.cba/api/pypi/digitalprotectiongroup-cyberauto-pypi/simple
trusted-host =  artifactory.internal.cba
                pypi.python.org
                pypi.org
                files.pythonhosted.org
EOF

# Install and update standard certificates
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists

# Create non-system user cyberauto
ARG UNAME=cyberauto
ARG UID=18732
ARG GID=1000
RUN groupadd -g $GID -o $UNAME \
    && useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME

# Set home directory path for cyberauto
ENV CYBERAUTO_HOME=/home/cyberauto

# Set ownership and permissions
RUN chown -R $UNAME:$UNAME $CYBERAUTO_HOME \
    && chmod -R 750 $CYBERAUTO_HOME

# Adding Python to PATH to suppress script not on PATH warning
ENV PATH=$PATH:$CYBERAUTO_HOME/.local/bin
RUN echo $PATH

# Set final working directory to /home/cyberauto
WORKDIR $CYBERAUTO_HOME

COPY docker/requirements requirements

# Update the package lists and install essential OS packages
RUN apt-get update \
    && apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install -fy --no-install-recommends \
    $(sed -e 's/#.*$//' ./requirements/ospkgs.txt) \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Terraform
RUN echo "--- INSTALLING TERRAFORM ---" \
    && export TERRAFORM_VERSION="$(cat ./requirements/terraform.txt)" \
    && curl --netrc-file /home/cyberauto/.netrc -fsSl https://artifactory.internal.cba/hashicorp-releases/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip -o terraform.zip \
    && unzip terraform.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/terraform \
    && unset TERRAFORM_VERSION \
    && rm terraform.zip

# Update and install PyPi packages
RUN echo "--- INSTALLING PYTHON PACKAGES ---" \
    pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --upgrade -r requirements/pypkgs.txt \
    && rm -rf requirements.txt

# Download cbacert python package
RUN echo "--- INSTALLING CBACERT PYTHON PACKAGE ---"
RUN --mount=type=secret,id=artifactory-service-password,env=ARTIFACTORY_SERVICE_PASSWORD \
    pip3 install cbacert --index-url="https://${ARTIFACTORY_SERVICE_USERNAME}:${ARTIFACTORY_SERVICE_PASSWORD}@artifactory.internal.cba/artifactory/api/pypi/cloudservices-cert-management-engineering-pypi/simple" --no-build-isolation

COPY runner/src runner/src
COPY ./docker/.terraformrc .terraformrc
COPY cf/terraform cf/terraform
COPY cf/python cf/python
COPY cf/accounts.yml cf/accounts.yml

# Make dir where the plugins will be stored
ENV TF_PLUGIN_CACHE_DIR=cf/terraform/terraform-plugins/registry.terraform.io
RUN mkdir -p ${TF_PLUGIN_CACHE_DIR}


# Install Terraform Cloudflare provider
RUN echo "--- INSTALLING TERRAFORM CLOUDFLARE PROVIDER ---" \
    && export CLOUDFLARE_PROVIDER_VERSION="$(cat ./requirements/tfplugins/terraform-cloudflare.txt)" \
    && cloudflare_package="terraform-provider-cloudflare_${CLOUDFLARE_PROVIDER_VERSION}_linux_amd64" \
    && curl -fsSL "https://artifactory.internal.cba/artifactory/com.github/cloudflare/terraform-provider-cloudflare/releases/download/v${CLOUDFLARE_PROVIDER_VERSION}/$cloudflare_package.zip" -o "$cloudflare_package.zip"  \
    && mkdir -p ${TF_PLUGIN_CACHE_DIR}/cloudflare/cloudflare \
    && mv $cloudflare_package.zip $TF_PLUGIN_CACHE_DIR/cloudflare/cloudflare

RUN echo "--- INSTALLING TERRAFORM LOCAL PROVIDER ---" \
    && export LOCAL_PROVIDER_VERSION="$(cat ./requirements/tfplugins/terraform-local.txt)" \
    && local_package="terraform-provider-local_${LOCAL_PROVIDER_VERSION}_linux_amd64" \
    && curl -fsSL "https://artifactory.internal.cba/artifactory/com.hashicorp.releases/terraform-provider-local/${LOCAL_PROVIDER_VERSION}/$local_package.zip" -o "$local_package.zip" \
    && mkdir -p ${TF_PLUGIN_CACHE_DIR}/hashicorp/local \
    && mv $local_package.zip $TF_PLUGIN_CACHE_DIR/hashicorp/local


EXPOSE 8000
ENV TF_CLI_CONFIG_FILE=/home/cyberauto/.terraformrc
ENV PYTHONPATH=.
# Set entry point
ENTRYPOINT []
CMD ["uvicorn", "runner.src.main:app", "--host", "0.0.0.0", "--port", "8000","--log-config","runner/src/log-config.yml"]
