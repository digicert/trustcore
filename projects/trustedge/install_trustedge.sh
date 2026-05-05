#!/bin/bash

TRUSTEDGE="trustedge"
BACKUP_DIR="/var/lib/trustedge"
ARTIFACT_DIR="/etc/digicert/conf/artifacts"
SVC="trustedge.service"
IS_NEW_DPKG_LATEST_VERSION=0
ARTIFACT_STATUS="Failed"
IS_DOWNGRADE_ALLOWED=0              # 0 : Downgrade is not allowed; 1 : downgrade is allowed
SUCCSS_INSTALL_STATUS="install ok installed"
OLD_INSTALLED_VERSION=""
BACKUP_FILE_VERSION=""
NEW_DPKG_VERSION=""
NEW_DPKG_FILE=""
OLD_DPKG_FILE=""
ARTIFACT_ID=""
ARTIFACT_FILE=""
STATUS=""
VERSION=""
SLEEP_TIME=5
NULL_FILE="/dev/null"
SERVICE_MODE="FALSE"

dbg_msg ()
{
    [ "$TE_DEBUG" = "1" ] && echo "DEBUG: $1" || true
}

replace_json_line_with()
{
    local IN_FILE="$1"
    local SEARCH_TERM="$2"
    local NEW_TERM="$3"

    if grep -q "$SEARCH_TERM" "$IN_FILE"; then
        sed -i "s|.*$SEARCH_TERM.*|$NEW_TERM|" "$IN_FILE"
    fi
}

update_artifact_status_file()
{
    local DATE_STR=
    local TIMESTAMP="\"timestamp\""
    local STATUS="\"status\""

    local NEW_STATUS="    \"status\":\"$ARTIFACT_STATUS\","
    replace_json_line_with "$1" "$STATUS" "$NEW_STATUS"

    DATE_STR=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local NEW_TIMESTAMP="    \"timestamp\":\"$DATE_STR\","
    replace_json_line_with "$1" "$TIMESTAMP" "$NEW_TIMESTAMP"
}

handle_artifact_status()
{
    if [ -n "$ARTIFACT_FILE" ]; then
        dbg_msg "artifact id path: $ARTIFACT_FILE"
        update_artifact_status_file "$ARTIFACT_FILE"
    else
        dbg_msg "ARTIFACT_FILE not provided"
    fi
}

cleanup_on_quit()
{
    dbg_msg "exiting with status $ARTIFACT_STATUS for $ARTIFACT_FILE"
    handle_artifact_status
}
trap "cleanup_on_quit" SIGHUP SIGINT SIGTERM EXIT

check_systemctl_command ()
{
    if [ "TRUE" = "$SERVICE_MODE" ]; then
        if ! command -v systemctl > /dev/null 2>&1 ; then
            echo "systemctl command does not exist"
            exit 1
        else
            echo "systemctl command exist"
        fi
    fi
}

start_service ()
{
    if [ "TRUE" = "$SERVICE_MODE" ]; then
        dbg_msg "Starting $SVC service"
        systemctl start $SVC
    fi
}

stop_service () {
    if [ "TRUE" = "$SERVICE_MODE" ]; then
        dbg_msg "Stopping $SVC service"
        systemctl stop $SVC
    fi
}

print_service_status ()
{
    if [ "TRUE" = "$SERVICE_MODE" ]; then
        if systemctl is-active --quiet $SVC; then
            dbg_msg "$SVC is running"
            return 0
        else
            dbg_msg "$SVC is not running"
            return 1
        fi
    fi
}

show_usage ()
{
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --help                 - Show help options"
    echo "  --dpkg <trustedge.deb> - trustedge debian file"
    echo "  --allow_downgrade      - allow trustedge to downgrade to older package"
    echo "  --service <TRUE/FALSE> - When TRUE stop/start service"
    echo "  --aId <artifactId>     - artifact Id"
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        exit 1
    fi
}

parse_cmd_args ()
{
    while test $# -gt 0
    do
        case "$1" in
            --help)
                show_usage
                exit 0
                ;;
            --dpkg)
                NEW_DPKG_FILE=$2
                shift
                ;;
            --aId)
                ARTIFACT_ID=$2
                ARTIFACT_FILE="${ARTIFACT_DIR}/${ARTIFACT_ID}"
                shift
                ;;
            --debug)
                TE_DEBUG="1"
                ;;
            --service)
                SERVICE_MODE="$2"
                shift
                ;;
            --allow_downgrade)
                IS_DOWNGRADE_ALLOWED=1
                ;;
            *)
                show_usage "Invalid option: $1"
                ;;
        esac
        shift
    done

    if [ -z "${NEW_DPKG_FILE}" ]; then
        if command -v find &> /dev/null; then
            found_files=$(find . -type f -name "*.deb")

            if [ -f "$found_files" ]; then
                NEW_DPKG_FILE="$found_files"
            fi
        fi
    fi

    if [ -z "${NEW_DPKG_FILE}" ]; then
        PATTERN="package/*.deb"
        NEW_DPKG_FILE=( $PATTERN )

        if [ ! -f "${NEW_DPKG_FILE}" ]; then
            NEW_DPKG_FILE=""
        fi
    fi

    if [ -z "${NEW_DPKG_FILE}" ]; then
        PATTERN="payload/package/*.deb"
        NEW_DPKG_FILE=( $PATTERN )

        if [ ! -f "${NEW_DPKG_FILE}" ]; then
            NEW_DPKG_FILE=""
        fi
    fi
}

# Function to compare two versions
compare_versions() {
    ver1=$1
    ver2=$2

    # Split the version into components (major, minor, patch, build)
    major1=$(echo "$ver1" | cut -d'.' -f1)
    minor1=$(echo "$ver1" | cut -d'.' -f2)
    patch1=$(echo "$ver1" | cut -d'.' -f3 | cut -d'-' -f1)
    build1=$(echo "$ver1" | cut -d'-' -f2)

    major2=$(echo "$ver2" | cut -d'.' -f1)
    minor2=$(echo "$ver2" | cut -d'.' -f2)
    patch2=$(echo "$ver2" | cut -d'.' -f3 | cut -d'-' -f1)
    build2=$(echo "$ver2" | cut -d'-' -f2)

    # Compare major versions
    if [ "$major1" -gt "$major2" ]; then
        dbg_msg "$ver1 is the latest version."
        IS_NEW_DPKG_LATEST_VERSION=1
        return
    elif [ "$major1" -lt "$major2" ]; then
        dbg_msg "$ver2 is the latest version."
        return
    fi

    # Compare minor versions
    if [ "$minor1" -gt "$minor2" ]; then
        dbg_msg "$ver1 is the latest version."
        IS_NEW_DPKG_LATEST_VERSION=1
        return
    elif [ "$minor1" -lt "$minor2" ]; then
        dbg_msg "$ver2 is the latest version."
        return
    fi

    # Compare patch versions
    if [ "$patch1" -gt "$patch2" ]; then
        dbg_msg "$ver1 is the latest version."
        IS_NEW_DPKG_LATEST_VERSION=1
        return
    elif [ "$patch1" -lt "$patch2" ]; then
        dbg_msg "$ver2 is the latest version."
        return
    fi

    # Compare build numbers
    if [ "$build1" -gt "$build2" ]; then
        dbg_msg "$ver1 is the latest version."
        IS_NEW_DPKG_LATEST_VERSION=1
    elif [ "$build1" -lt "$build2" ]; then
        dbg_msg "$ver2 is the latest version."
    else
        dbg_msg "Both versions are the same."
    fi
}

check_memory_avbl() {
    echo "Add check to ensure enough memory is available"
}

check_dependency () {
    echo "Add check to ensure dependencies are already installed"
}

get_installed_status ()
{
    text=$(sudo dpkg -s trustedge 2> $NULL_FILE)
    STATUS=$(echo "$text" | grep "Status" | awk '{print $2, $3, $4}')
    VERSION=$(echo "$text" | grep "^Version" | awk '{print $2}')
}

# Check sanity of installed package
# If installed package status is not "install ok installed" exit installation process
get_installed_version ()
{
    get_installed_status
    OLD_INSTALLED_VERSION=$VERSION

    if [ -z "$OLD_INSTALLED_VERSION" ] ; then
        dbg_msg "Trustedge is currently not installed."
    else
        if ! trustedge --version; then
            dbg_msg "Old trustedge not in properly install states."
            dbg_msg "Old trustedge installation status : $STATUS"
            dbg_msg "Exiting.."
            exit 1
        fi
    fi
}

# Limitation only one trustedge_*.deb should be in the backup directory
get_backup_version ()
{
    if [ -d "$BACKUP_DIR" ] ; then
        # Count the number of trustedge_*.deb files in the directory
        local FILE_COUNT=$(find "$BACKUP_DIR" -type f -name "trustedge_*.deb" | wc -l)

        # Check if there is exactly one trustedge_*.deb file
        if [ "$FILE_COUNT" -eq 1 ]; then
            echo "There is exactly one  file in the $BACKUP_DIR."
        else
            echo "There are $FILE_COUNT files in the $BACKUP_DIR."
            exit 1
        fi

        OLD_DPKG_FILE=$(ls "$BACKUP_DIR"/trustedge_*.deb 2> $NULL_FILE )
        if [ -z "$OLD_DPKG_FILE" ]; then
            dbg_msg "Backup file does not exist"
            rm -rf $BACKUP_DIR/* 2> $NULL_FILE
        else
            #dbg_msg "Backup dpkg file : $OLD_DPKG_FILE"
            text=$(sudo dpkg -I "$OLD_DPKG_FILE" 2> $NULL_FILE)
            BACKUP_FILE_VERSION=$(echo "$text" | grep "Version" | awk '{print $2}')
        fi
    else
        dbg_msg "$BACKUP_DIR does not exit."
    fi
}

#Get version of new dpkg package
get_new_dpkg_package_version ()
{
    if [ -z "$NEW_DPKG_FILE" ] ; then
        dbg_msg "Need --dpkg <trustedge deb filename> argument. Exiting.."
        show_usage
        exit 1
    fi
    text=$(sudo dpkg -I "$NEW_DPKG_FILE" 2> $NULL_FILE)
    package_name=$(echo "$text" | grep "Package:" | awk '{print $2}')
    if [ "$package_name" = "$TRUSTEDGE" ] ; then
        dbg_msg "$NEW_DPKG_FILE is a trustedge debian file"
    else
        dbg_msg "$NEW_DPKG_FILE is a not trustedge debian file."
        dbg_msg "Exiting.."
        exit 1
    fi
    NEW_DPKG_VERSION=$(echo "$text" | grep "Version" | awk '{print $2}')
    if [ -z "$NEW_DPKG_VERSION" ] ; then
        dbg_msg "New dpkg package version is empty. Exiting.."
        exit 1
    else
        dbg_msg "New dpkg version : $NEW_DPKG_VERSION"
    fi
}

check_new_dpkg_package ()
{
    echo "TODO: Perform health check on new trustedge binary"
}

dump_version_info ()
{
    dbg_msg "Old installed version    : $OLD_INSTALLED_VERSION"
    dbg_msg "Backup DPKG file name    : $OLD_DPKG_FILE"
    dbg_msg "Backup DPKG file version : $BACKUP_FILE_VERSION"
    dbg_msg "New DPKG file name       : $NEW_DPKG_FILE"
    dbg_msg "New DPKG version         : $NEW_DPKG_VERSION"
    dbg_msg "service                  : $SERVICE_MODE"
}

verify_installed_trustedge_health ()
{
    if [ "$OLD_INSTALLED_VERSION" = "$BACKUP_FILE_VERSION" ] ; then
        dbg_msg "Old installed version \"$OLD_INSTALLED_VERSION\" and backup file version \"$BACKUP_FILE_VERSION\" are matching. Proceed to installation.."
    else
        dbg_msg "Old installed version \"$OLD_INSTALLED_VERSION\" and backup file version \"$BACKUP_FILE_VERSION\" are not matching."
        dbg_msg "Exiting installation.."
        exit 1
    fi
}

check_new_dpkg_installation_allowed ()
{
    if [ -n "$OLD_INSTALLED_VERSION" ] && [ $IS_DOWNGRADE_ALLOWED -eq 0 ] ; then
        compare_versions "$NEW_DPKG_VERSION" "$OLD_INSTALLED_VERSION"
        if [ $IS_NEW_DPKG_LATEST_VERSION -eq 1 ] ; then
            dbg_msg "Dpkg file \"$NEW_DPKG_FILE\" has latest version : \"$NEW_DPKG_VERSION\"."
        else
            dbg_msg "Dpkg file \"$NEW_DPKG_FILE\" does not has latest version : \"$NEW_DPKG_VERSION\"."
            dbg_msg "Downgrading is not allowed, therefore, exiting.."
            exit 1
        fi
    fi
}

take_backup ()
{
    if [ -d "$BACKUP_DIR" ] ; then
        if [ -d "${BACKUP_DIR}_1" ]; then 
            sudo rm -rf "${BACKUP_DIR}_1"
        fi
        dbg_msg "Found an old backup \"${BACKUP_DIR}\", moving to \"${BACKUP_DIR}_1\""
        # TODO: add comment for  low disk space
        sudo mv "$BACKUP_DIR" "${BACKUP_DIR}_1"
    fi

    sudo mkdir $BACKUP_DIR
    if [ $? -ne 0 ] ; then
        dbg_msg "$BACKUP_DIR creation failed"
        exit 1
    fi

    sudo cp "$NEW_DPKG_FILE" $BACKUP_DIR
    if [ $? -ne 0 ] ; then
        dbg_msg "File $NEW_DPKG_FILE copy into $BACKUP_DIR failed"
        exit 1
    else
        dbg_msg "File $NEW_DPKG_FILE copied into $BACKUP_DIR"
    fi
}

#TODO: What if rollback fails
# rollback should terminate script immediately
rollback ()
{
    if sudo dpkg -i "$OLD_DPKG_FILE" ; then
        dbg_msg "Rollback to $OLD_INSTALLED_VERSION successful"
        start_service
    else
        dbg_msg "Rollback to $OLD_INSTALLED_VERSION failed"
    fi
    exit 1
}

post_fresh_installed_health ()
{
    get_installed_status
    if [ "$VERSION" != "$NEW_DPKG_VERSION" ] ; then 
        dbg_msg "Installed version : \"$VERSION\" does not match with new dpkg file version \"$NEW_DPKG_VERSION\". Exiting.."
        exit 1
    else
        if [ "$STATUS" = "$SUCCSS_INSTALL_STATUS" ] ; then
            dbg_msg "Fresh package $NEW_DPKG_FILE installation successful. Taking backup.."
            take_backup
        else
            dbg_msg "Package \"$NEW_DPKG_FILE\" not installed properly. Exiting.."
            exit 1
        fi
    fi
}

post_upgrade_installed_dpkg_health_check ()
{
    get_installed_status
    if [ "$VERSION" != "$NEW_DPKG_VERSION" ] ; then 
        dbg_msg "Installed version : \"$VERSION\" does not match with new dpkg file version \"$NEW_DPKG_VERSION\". Performing rollback.."
        rollback
    fi
    if [ "$STATUS" != "$SUCCSS_INSTALL_STATUS" ] ; then
        dbg_msg "Package \"$NEW_DPKG_FILE\" not installed properly. Performing rollback.."
        rollback
    fi

    dbg_msg "Installed version : \"$VERSION\" matches with new dpkg file version \"$NEW_DPKG_VERSION\"."
}

post_upgrade_trustedge_binary_health_check ()
{
    if ! trustedge --version; then
        dbg_msg "New trustedge not properly running. Performing rollback.."
        rollback
    fi

    text=$(trustedge --version 2> $NULL_FILE)
    VERSION=$(echo "$text" | grep "Version" | awk '{print $2}')
    if [ "$VERSION" != "$NEW_DPKG_VERSION" ] ; then
        dbg_msg "trustedge binary version : \"$VERSION\" does not match with new dpkg file version \"$NEW_DPKG_VERSION\". Performing rollback.."
        rollback
    fi
    dbg_msg "trustedge binary version : \"$VERSION\" matches with new dpkg file version \"$NEW_DPKG_VERSION\"."
}

post_upgrade_service_health_check ()
{
    if [ "TRUE" = "$SERVICE_MODE" ]; then
        start_service
        dbg_msg "Sleeping for $SLEEP_TIME seconds.."
        sleep "$SLEEP_TIME"
        if systemctl is-active --quiet $SVC; then
            dbg_msg "$SVC is running"
        else
            dbg_msg "$SVC is not running. Performing rollback.."
            rollback
        fi
    fi
}

post_upgrade_installed_health ()
{

    post_upgrade_installed_dpkg_health_check

    post_upgrade_trustedge_binary_health_check

    post_upgrade_service_health_check
}

post_upgrade_ops ()
{
    take_backup
}

package_installation ()
{
    dbg_msg "Installing trustedge dpkg package : $NEW_DPKG_FILE"
    # Fresh installation
    if [ -z "$OLD_INSTALLED_VERSION" ] ; then

        if sudo dpkg -i "$NEW_DPKG_FILE"; then
            # check post installation health
            post_fresh_installed_health
        else
            dbg_msg "Fresh package $NEW_DPKG_FILE installation failed"
            exit 1
        fi
    #Upgrade
    else
        #stop_service
        print_service_status
        if sudo dpkg -i "$NEW_DPKG_FILE"; then
            # check post installation health
            # continue checking post installation health
            post_upgrade_installed_health

            ARTIFACT_STATUS="Success"

            post_upgrade_ops
        else
            dbg_msg "Package $NEW_DPKG_FILE upgradation failed"
            rollback
        fi
    fi
}

parse_cmd_args "$@"

check_systemctl_command

print_service_status

get_new_dpkg_package_version

#TODO: health check on trustedge binary "--healthcheck"
check_new_dpkg_package

check_memory_avbl

check_dependency

get_installed_version

get_backup_version

dump_version_info

verify_installed_trustedge_health

check_new_dpkg_installation_allowed

package_installation

