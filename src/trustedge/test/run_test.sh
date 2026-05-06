#!/bin/bash

function health_check()
{

  if [ ! -f "../../../bin/trustedge_agent_generate_data" ]; then
    echo "could not find trustedge_agent_generate_data"
    exit 1
  fi
}

health_check

function sleep_delay()
{
  local SLEEP="$1"
  echo "sleep ${SLEEP}s.."
  sleep "${SLEEP}"
}

# update timestamp
function update_timestamp()
{
    local IN_FILE="$1"
    local NEW_FILE="$1_tmp"
    local DATE_STR=
    local PATTERN="timestamp"
    DATE_STR=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local REPLACE_STR="    \"timestamp\":\"$DATE_STR\","
    echo "$REPLACE_STR"

    cp $IN_FILE $NEW_FILE
    while IFS= read -r line; do
        # Check if the line contains the pattern "timestamp"
        if [[ "$line" == *"$PATTERN"* ]]; then
            # Replace the entire line with the replacement
            sed -i "s|.*$PATTERN.*|$REPLACE_STR|" "$NEW_FILE"
        fi
    done < "$IN_FILE"

    mv $NEW_FILE $IN_FILE
    head -n 10 $IN_FILE
}

DATA_PATH="data/fake_data/"

SMALL_SLEEP=40
LONG_SLEEP=40
SLEEP=3600

IP_ADDR=172.18.209.19
PORT_NUM=1883

ACCOUNT_ID="ddcef16b-891e-4b08-93c2-df6cac44f407"
DEVICE_ID="abd104cd-54c4-49a8-b9be-db7edc576789"

MQTT_CLIENT_ID="simulated-client"

while test $# -gt 0
do
     case "$1" in
        --ip)
            if [ -z "$2" ]; then
                show_usage "ERROR: IP address of MQTT broker is missing.."
            fi
            IP_ADDR="$2"
            shift
            ;;
        --port)
            if [ -z "$2" ]; then
                show_usage "ERROR: Port number of MQTT broker is missing.."
            fi
            PORT_NUM="$2"
            shift
            ;;
        --mqtt-client-id)
            if [ -z "$2" ]; then
                show_usage "ERROR: Missing MQTT client ID.."
            fi
            MQTT_CLIENT_ID="$2"
            shift
            ;;
        --account-id)
            if [ -z "$2" ]; then
                show_usage "ERROR: Missing account ID.."
            fi
            ACCOUNT_ID="$2"
            shift
            ;;
        --device-id)
            if [ -z "$2" ]; then
                show_usage "ERROR: Missing device ID.."
            fi
            DEVICE_ID="$2"
            shift
            ;;
        --data-dir)
            if [ -z "$2" ]; then
                show_usage "ERROR: Missing data directory.."
            fi

            if [ ! -d "$2" ]; then
              echo "$2 is not a valid directory"
              exit 1
            fi

            DATA_PATH="$2"
            shift
            ;;
        --sleep)
            if [ -z "$2" ]; then
                show_usage "ERROR: Missing sleep amount.."
            fi
            SLEEP="$2"
            ;;
        --help)
            show_usage
            ;;
        *)
            show_usage "ERROR: Invalid argument: $1"
            ;;
    esac
    shift
done

echo "data path: $DATA_PATH"
echo "sleep    : $SLEEP"

rm -rf output || true
mkdir output

# two policies, update policy priority over certificate
./../../../bin/trustedge_agent_generate_data --msg-uuid DeviceTM_Pending_Policies \
    --msg-body-file "${DATA_PATH}pending_policies_rsp_data.json" \
    --out-file output/pending_combined_policy_rsp1.pb

trustedge mqtt   \
    --mqtt_servername "${IP_ADDR}" \
    --mqtt_port ${PORT_NUM} \
    --mqtt_client_id "${MQTT_CLIENT_ID}" \
    --mqtt_pub_topic spBv1.0/${ACCOUNT_ID}/NCMD/${DEVICE_ID} \
    --mqtt_pub_file output/pending_combined_policy_rsp1.pb

sleep_delay ${SMALL_SLEEP}

update_timestamp "${DATA_PATH}artifact_list_rsp_data.json"
./../../../bin/trustedge_agent_generate_data --msg-uuid DeviceTM_Release_Artifact_List \
    --msg-body-file "${DATA_PATH}artifact_list_rsp_data.json" \
    --out-file output/release_artifact_list_rsp6.pb

trustedge mqtt \
  --mqtt_servername ${IP_ADDR} \
  --mqtt_port ${PORT_NUM} \
  --mqtt_client_id ${MQTT_CLIENT_ID} \
  --mqtt_pub_topic spBv1.0/${ACCOUNT_ID}/NCMD/${DEVICE_ID} \
  --mqtt_pub_file output/release_artifact_list_rsp6.pb

sleep_delay ${SMALL_SLEEP}

cp ${DATA_PATH}artifactA.bin output/artifactA.bin
trustedge mqtt \
  --mqtt_servername ${IP_ADDR} \
  --mqtt_port ${PORT_NUM} \
  --mqtt_client_id ${MQTT_CLIENT_ID} \
  --mqtt_pub_topic spBv1.0/${ACCOUNT_ID}/NCMD/${DEVICE_ID} \
  --mqtt_pub_file output/artifactA.bin

sleep_delay ${LONG_SLEEP}

cp ${DATA_PATH}artifactB.bin output/artifactB.bin
trustedge mqtt \
  --mqtt_servername ${IP_ADDR} \
  --mqtt_port ${PORT_NUM} \
  --mqtt_client_id ${MQTT_CLIENT_ID} \
  --mqtt_pub_topic spBv1.0/${ACCOUNT_ID}/NCMD/${DEVICE_ID} \
  --mqtt_pub_file output/artifactB.bin

sleep_delay ${SLEEP}

cp ${DATA_PATH}artifactC.bin output/artifactC.bin
trustedge mqtt \
  --mqtt_servername ${IP_ADDR} \
  --mqtt_port ${PORT_NUM} \
  --mqtt_client_id ${MQTT_CLIENT_ID} \
  --mqtt_pub_topic spBv1.0/${ACCOUNT_ID}/NCMD/${DEVICE_ID} \
  --mqtt_pub_file output/artifactC.bin

echo "##################"
echo "###### DONE ######"
echo "##################"
exit 0
### OLD SCRIPT BELOW HERE
