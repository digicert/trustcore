#!/bin/bash

set -e

# Default configuration
TRUSTEDGE_DOWNLOAD_PATH="/tmp/trustedge_install"
TRUSTEDGE_ZIP_PATH="$TRUSTEDGE_DOWNLOAD_PATH/trustedge.zip"

# Include global configuration
source config/global_configuration.sh

# Include customer properties
source config/customer_properties.sh

# Include onboarding operations
source config/onboarding_operations.sh

function printInfoMessage() {
    echo "[INFO] $*"
}

function printDebugMessage() {
    if [ "$DEBUG" == "1" ]; then
        echo "[DEBUG] $*"
    fi
}

function printErrorMessage() {
    echo "[ERROR] $*" >&2
}

function run_command()
{
    if [ "$DEBUG" = "1" ]; then
        echo "[DEBUG] Running command: $*"
        "$@"
    else
        "$@" > /dev/null 2>&1
    fi
}

function is_installed()
{
    printDebugMessage "Checking if '$1' is installed..."
    if command -v "$1" >/dev/null 2>&1; then
        printDebugMessage "'$1' is installed."
        return 0
    else
        printDebugMessage "'$1' is NOT installed."
        return 1
    fi
}

function device_cleanup()
{
    printDebugMessage "CLEAN is set to '$CLEAN'"
    if [ "$CLEAN" == "1" ]; then
        printInfoMessage "Performing device cleanup..."
        if [ -d "$TRUSTEDGE_DOWNLOAD_PATH" ]; then
            printInfoMessage "Removing TrustEdge download directory..."
            run_command rm -rf "$TRUSTEDGE_DOWNLOAD_PATH" || printErrorMessage "Failed to remove TrustEdge download directory."
        fi
        if is_installed trustedge; then
            printInfoMessage "Uninstalling TrustEdge..."
            run_command sudo dpkg --purge trustedge || printErrorMessage "Failed to uninstall trustedge package."
        fi
        printInfoMessage "Device cleanup completed."
    fi
}

function handle_missing_dependency()
{
    if [ "$TRUSTEDGE_DEPENDENCY_INSTALLATION" == "1" ]; then
        printInfoMessage "Attempting to install missing dependency: $1"
        run_command sudo apt-get install -y "$1"
        if [ $? -ne 0 ]; then
            printErrorMessage "Failed to install dependency: $1"
            exit 1
        fi
    else
        printErrorMessage "Missing required dependency: $1. Set TRUSTEDGE_DEPENDENCY_INSTALLATION=1 to enable automatic installation."
        exit 1
    fi
}

function trustedge_install()
{
    printDebugMessage "TRUSTEDGE_INSTALLATION is set to '$TRUSTEDGE_INSTALLATION'"
    if [ "$TRUSTEDGE_INSTALLATION" == "1" ]; then
        printInfoMessage "Installing TrustEdge..."

        if is_installed trustedge; then
            printErrorMessage "'trustedge' is already installed. Aborting."
            exit 1
        fi

        # Check if required dependencies are installed
        is_installed curl || handle_missing_dependency "curl"
        is_installed unzip || handle_missing_dependency "unzip"
        is_installed gpg || handle_missing_dependency "gpg"
        is_installed dpkg-sig || handle_missing_dependency "dpkg-sig"

        # Platform architecture
        PLATFORM_ARCH=$(uname -m)
        printDebugMessage "Platform architecture: $PLATFORM_ARCH"

        if [ "$PLATFORM_ARCH" == "x86_64" ]; then
            TRUSTEDGE_PKG="trustedge-x64-deb.zip"
        else
            TRUSTEDGE_PKG="trustedge-\\$PLATFORM_ARCH\-deb.zip"
        fi

        printInfoMessage "Github URL: $TRUSTEDGE_GITHUB_URL"

        GITHUB_API_URL="${TRUSTEDGE_GITHUB_URL/github.com/api.github.com\/repos}/releases/latest"
        printDebugMessage "GitHub API URL: $GITHUB_API_URL"
        LATEST_RELEASE_JSON=$(curl -fsSL "$GITHUB_API_URL")

        # Extract the latest tag name for logging purposes
        LATEST_TAG=$(echo "$LATEST_RELEASE_JSON" | grep -oP '"tag_name":\s*"\K(.*?)(?=")')
        printInfoMessage "Latest release tag: $LATEST_TAG"

        TRUSTEDGE_DOWNLOAD_URL=$(echo "$LATEST_RELEASE_JSON" \
            | grep -oP '"browser_download_url":\s*"\K(.*?)(?=")' \
            | grep -E "$TRUSTEDGE_PKG" || true )

        if [[ -z "$TRUSTEDGE_DOWNLOAD_URL" ]]; then
            printErrorMessage "No assets found matching pattern '$TRUSTEDGE_PKG' in the latest release."
            exit 1
        fi

        if [ -d "$TRUSTEDGE_DOWNLOAD_PATH" ]; then
            run_command rm -rf "$TRUSTEDGE_DOWNLOAD_PATH"
        fi

        printDebugMessage "Creating TrustEdge download directory at '$TRUSTEDGE_DOWNLOAD_PATH'"
        run_command mkdir -p "$TRUSTEDGE_DOWNLOAD_PATH"

        # Download the TrustEdge DEB package
        printInfoMessage "Downloading TrustEdge package: $TRUSTEDGE_DOWNLOAD_URL"
        run_command curl -s -L "$TRUSTEDGE_DOWNLOAD_URL" -o "$TRUSTEDGE_ZIP_PATH"

        # Extract the DEB package from the downloaded archive
        printDebugMessage "Extracting TrustEdge package to '$TRUSTEDGE_DOWNLOAD_PATH'"
        run_command unzip -o "$TRUSTEDGE_ZIP_PATH" -d "$TRUSTEDGE_DOWNLOAD_PATH"

        # Determine the path to the DEB installer
        TRUSTEDGE_INSTALLER_PATH=$(find "$TRUSTEDGE_DOWNLOAD_PATH" -maxdepth 1 -type f -name "*.deb" | sort | head -n 1)
        if [[ -z "$TRUSTEDGE_INSTALLER_PATH" ]]; then
            printErrorMessage "Failed to locate the TrustEdge DEB package after extraction."
            exit 1
        fi
        printInfoMessage "TrustEdge installer path: $TRUSTEDGE_INSTALLER_PATH"

        # Import the GPG key for signature verification
        printInfoMessage "Verifying TrustEdge package signature..."
        if [[ ! -f "$TRUSTEDGE_PACKAGE_VERIFICATION_KEY" ]]; then
            printErrorMessage "GPG key file '$TRUSTEDGE_PACKAGE_VERIFICATION_KEY' does not exist."
            exit 1
        fi
        run_command gpg --import "$TRUSTEDGE_PACKAGE_VERIFICATION_KEY"
        if [[ $? -ne 0 ]]; then
            printErrorMessage "Failed to import GPG key from '$TRUSTEDGE_PACKAGE_VERIFICATION_KEY'. The file may be corrupted or invalid."
            exit 1
        fi

        # Verify the package signature
        printInfoMessage "Verifying package signature..."
        run_command dpkg-sig --verify "$TRUSTEDGE_INSTALLER_PATH" || { printErrorMessage "Package signature verification failed."; exit 1; }
        printInfoMessage "Package signature verified successfully."

        # Install the TrustEdge DEB package
        printInfoMessage "Installing TrustEdge DEB package"
        run_command sudo DIGICERT_EULA_ACCEPT=yes dpkg -i "$TRUSTEDGE_INSTALLER_PATH"

        # Copy files
        printInfoMessage "Copying device onboarding files..."

        if [ -d keystore ]; then
            run_command sudo cp -r keystore/* /etc/digicert/keystore/
        fi

        # Remove temporary download directory
        printDebugMessage "Removing TrustEdge download directory..."
        run_command rm -rf "$TRUSTEDGE_DOWNLOAD_PATH"

        printInfoMessage "TrustEdge installation completed successfully."

    else
        printInfoMessage "Skipping TrustEdge installation"

        is_installed trustedge || { printErrorMessage "'trustedge' is required but not installed."; exit 1; }
    fi
}

function trustedge_certificate_enrollment()
{
    printDebugMessage "TRUSTEDGE_CERTIFICATE_ENROLLMENT is set to '$TRUSTEDGE_CERTIFICATE_ENROLLMENT'"
    if [ "$TRUSTEDGE_CERTIFICATE_ENROLLMENT" == "1" ]; then
        printInfoMessage "Starting TrustEdge certificate enrollment..."
        printInfoMessage "Device Trust Manager: $DEVICETM_SERVER_NAME"
        printInfoMessage "Device Group ID: $DEVICETM_DEVICE_GROUP_ID"

        # Issue certificate(s) using EST
        for CERTIFICATE_POLICY in "${CERTIFICATE_POLICY_CONFIG[@]}"; do


            # Unset variables to avoid conflict with next block
            unset \
                POLICY_ID \
                POLICY_TYPE \
                ENROLLMENT_METHOD \
                EST_PASSWORD \
                EST_KEY_ALGORITHM \
                EST_KEY_SIZE \
                EST_KEY_ALIAS \
                EST_AUTHENTICATION_MODE \
                EST_KEY_GENERATION_SOURCE \
                EST_CSR \
                EST_USER \
                EST_MTLS_ALIAS

            # Evaluate the block to set the variables in the current shell
            eval "$CERTIFICATE_POLICY"

            # Now you can access the variables
            printInfoMessage "---- Certificate Policy Info -------"
            printInfoMessage "POLICY_ID: $POLICY_ID"
            printInfoMessage "POLICY_TYPE: $POLICY_TYPE"
            printInfoMessage "ENROLLMENT_METHOD: $ENROLLMENT_METHOD"
            printInfoMessage "EST_KEY_GENERATION_SOURCE: $EST_KEY_GENERATION_SOURCE"
            printInfoMessage "EST_KEY_ALGORITHM: $EST_KEY_ALGORITHM"
            printInfoMessage "EST_KEY_SIZE: $EST_KEY_SIZE"
            printInfoMessage "EST_KEY_ALIAS: $EST_KEY_ALIAS"
            printInfoMessage "EST_AUTHENTICATION_MODE: $EST_AUTHENTICATION_MODE"
            printInfoMessage "EST_USER: $EST_USER"
            printInfoMessage "EST_MTLS_ALIAS: $EST_MTLS_ALIAS"
            printInfoMessage "EST_CSR: $EST_CSR"
            printInfoMessage "------------------------------------"

            # Construct TrustEdge EST command
            TRUSTEDGE_CMD="trustedge certificate est \
                --estc-server-dn \"$DEVICETM_SERVER_NAME\""

            TRUSTEDGE_CACERTS_CMD="$TRUSTEDGE_CMD --estc-server-url \"/.well-known/est/devicetrustmanager/${POLICY_ID}/device-group/${DEVICETM_DEVICE_GROUP_ID}/cacerts\""

            if [ "$EST_KEY_GENERATION_SOURCE" == "Local" ]; then
                TRUSTEDGE_CMD+=" --estc-server-url \"/.well-known/est/devicetrustmanager/${POLICY_ID}/device-group/${DEVICETM_DEVICE_GROUP_ID}/simpleenroll\""
            elif [ "$EST_KEY_GENERATION_SOURCE" == "SKG" ]; then
                TRUSTEDGE_CMD+=" --estc-server-url \"/.well-known/est/devicetrustmanager/${POLICY_ID}/device-group/${DEVICETM_DEVICE_GROUP_ID}/serverkeygen\""
            else
                printErrorMessage "Invalid EST_KEY_GENERATION_SOURCE: $EST_KEY_GENERATION_SOURCE"
                exit 1
            fi

            TRUSTEDGE_CMD+=" --algorithm \"$EST_KEY_ALGORITHM\""

            if [ "$EST_KEY_ALGORITHM" == "RSA" ]; then
                TRUSTEDGE_CMD+=" --size \"$EST_KEY_SIZE\""
            elif [ "$EST_KEY_ALGORITHM" == "ECC" ]; then
                TRUSTEDGE_CMD+=" --curve \"$EST_KEY_SIZE\""
            elif [ "$EST_KEY_ALGORITHM" == "QS" ]; then
                TRUSTEDGE_CMD+=" --pq-alg \"$EST_KEY_SIZE\""
            else
                printErrorMessage "Invalid EST_KEY_ALGORITHM: $EST_KEY_ALGORITHM"
                exit 1
            fi

            TRUSTEDGE_CMD+=" --key-alias \"$EST_KEY_ALIAS\""

            if [ "$EST_AUTHENTICATION_MODE" != "" ]; then
                TRUSTEDGE_CMD+=" --estc-authentication-mode \"$EST_AUTHENTICATION_MODE\""
            fi

            if [ "$EST_USER" != "" ]; then
                TRUSTEDGE_CMD+=" --estc-user \"$EST_USER\""
            fi

            if [ "$EST_PASSWORD" != "" ]; then
                TRUSTEDGE_CMD+=" --estc-pass \"$EST_PASSWORD\""
            fi

            if [ "$EST_MTLS_ALIAS" != "" ]; then
                TRUSTEDGE_CMD+=" --estc-tls-cert \"$EST_MTLS_ALIAS\""
            fi

            TRUSTEDGE_CMD+=" --csr-conf \"$EST_CSR\""

            if [ "$DEBUG" == "1" ]; then
                TRUSTEDGE_CMD+=" --log-level VERBOSE"
                TRUSTEDGE_CACERTS_CMD+=" --log-level VERBOSE"
            else
                TRUSTEDGE_CMD+=" --log-level INFO"
                TRUSTEDGE_CACERTS_CMD+=" --log-level INFO"
            fi

            printInfoMessage "Fetching CA certificates with command:"
            printInfoMessage "$TRUSTEDGE_CACERTS_CMD"
            # Fetch CA certificates
            eval "$TRUSTEDGE_CACERTS_CMD"

            printInfoMessage "Performing TrustEdge certificate enrollment with command:"
            printInfoMessage "$TRUSTEDGE_CMD"
            # Execute the constructed command
            eval "$TRUSTEDGE_CMD"

            printInfoMessage "Certificate enrollment for policy '$POLICY_ID' completed successfully."
        done

    else
        printInfoMessage "Skipping TrustEdge certificate enrollment"
    fi
}

device_cleanup
trustedge_install
trustedge_certificate_enrollment

printInfoMessage "Device onboarding script completed."