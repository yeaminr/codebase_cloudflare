#!/usr/bin/env bash
#set -x
# usage: $0 "$(cat tfplugins.txt)"

HOME=${CYBERAUTO_HOME:-/home/cyberauto}
GITHUB_RELEASES=${GITHUB_RELEASES:-https://artifactory.internal.cba/artifactory/com.github}
OS=${OS:-linux}
ARCH=${ARCH:-amd64}
LOCAL_REGISTRY_PATH=${LOCAL_REGISTRY_PATH:-cloudflare/terraform/terraform-plugins/registry.terraform.io}

DOWNLOAD_DIR=$(mktemp -d)
function cleanup {
    rm -rf "${DOWNLOAD_DIR}"
}
trap cleanup EXIT

mkdir -p "${HOME}/${LOCAL_REGISTRY_PATH}"

args="$@"
for plugin in $args
do
    # e.g. plugin = hashicorp/local:2.5.2
    echo "plugin: $plugin"
    # e.g. name = hashicorp/local
    # e.g. version = 2.5.2
    IFS=':' read -r name version <<< "$plugin"
    echo "name: $name"
    echo "version: $version"
    # Split name using separator /
    # e.g. namespace = hashicorp
    # e.g. type = local
    IFS='/' read -r namespace type <<< "$name"
    # Remove newline from provider
    type="$(echo "${type//\r\n}")"
    echo "Namespace: $namespace, Provider: $type"

    echo "Creating ${name} provider plugins directory"
    PROVIDER_PLUGINS_DIR="${HOME}/${LOCAL_REGISTRY_PATH}/${name}/${version}/${OS}_${ARCH}"
    mkdir -p "${PROVIDER_PLUGINS_DIR}"
    echo "Provider plugin dir: ${PROVIDER_PLUGINS_DIR}"

    echo "Downloading ${GITHUB_RELEASES}/${namespace}/terraform-provider-${type}/releases/download/v${version}/terraform-provider-${type}_${version}_${OS}_${ARCH}.zip"
    echo "to ${DOWNLOAD_DIR}/terraform-provider-${type}.zip"
    curl -fsSl \
            -o "${DOWNLOAD_DIR}/terraform-provider-${type}.zip" \
            "${GITHUB_RELEASES}/${namespace}/terraform-provider-${type}/releases/download/v${version}/terraform-provider-${type}_${version}_${OS}_${ARCH}.zip"

    echo "Installing terraform provider ${name} v${version}"
    # unzip -d "${HOME}/${LOCAL_REGISTRY_PATH}/${name}/${version}/${OS}_${ARCH}" "${DOWNLOAD_DIR}/terraform-provider-${provider}.zip"
    unzip -d "${PROVIDER_PLUGINS_DIR}" "${DOWNLOAD_DIR}/terraform-provider-${type}.zip"

done

