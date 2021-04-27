#!/bin/zsh
: # USER CONFIG ###############################################################################
CS_CLIENTID=""
CS_SECRET=""
CS_CID=""
CS_SENSOR_PKG="./falcon.pkg"
CS_URL="https://api.us-2.crowdstrike.com"
: ############################################################################## USER CONFIG #

: # Function to encode URL
function urlencode {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
        * )               printf -v o '%%%02x' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

: # GET
function callGET {
    local uri=$1
    local outfile=$2
    local i=0

    local CS_N_HEADERS=(`set | grep CS_HEADER | sed -n -e 's/=.*$//p'`)
    local CS_N_HEADERS_VALUES=()

    while [ $i -lt ${#CS_N_HEADERS[@]} ]
    do
        local CS_TMP=$(set | grep ${CS_N_HEADERS[@]:$i:1} | sed -n -e 's/^.*=//p' | head -1)
        CS_N_HEADERS_VALUES+=(${CS_TMP//\'/})
        i=$[$i+1]
    done

    if [ -z "$outfile" ]
    then
        CS_result=$(curl -X GET "${CS_N_HEADERS_VALUES[@]/#/-H}" "${CS_URL}${uri}" 2>> /dev/null)
    else
        CS_result=$(curl -X GET "${CS_N_HEADERS_VALUES[@]/#/-H}" "${CS_URL}${uri}" -o ${outfile} 2>> /dev/null)
    fi
}

: # POST
function callPOST {
    local uri=$1
    local data=$2
    local i=0

    local CS_N_HEADERS=(`set | grep CS_HEADER | sed -n -e 's/=.*$//p'`)
    local CS_N_HEADERS_VALUES=()

    while [ $i -lt ${#CS_N_HEADERS[@]} ]
    do
        local CS_TMP=$(set | grep ${CS_N_HEADERS[@]:$i:1} | sed -n -e 's/^.*=//p' | head -1)
        CS_N_HEADERS_VALUES+=(${CS_TMP//\'/})
        i=$[$i+1]
    done

    CS_result=`curl "${CS_N_HEADERS_VALUES[@]/#/-H}" -d "${data}" "${CS_URL}${uri}" 2> /dev/null`
}

: # get token
function getToken {
    CS_HEADER_CONTENT_TYPE="Content-Type: application/x-www-form-urlencoded"
    CS_HEADER_ACCEPT="Accept: application/json"
    callPOST "/oauth2/token" "client_id=${CS_CLIENTID}&client_secret=${CS_SECRET}"
    CS_Token=$(echo ${CS_result} | sed -n -e 's/^.*access_token": "//p' | cut -d'"' -f1)
}

: # get current sensor definied in default policy
function getUpdatePolicy {
    CS_HEADER_CONTENT_TYPE="Content-Type: application/json"
    CS_HEADER_ACCEPT="accept: application/json"
    CS_HEADER_AUTH="authorization: bearer ${CS_Token}"
    callGET "/policy/combined/sensor-update/v2?filter=$(urlencode 'platform_name:"Mac"+name:"platform_default"')"
    CS_UpdatePolicy=$(echo ${CS_result} | sed -n -e 's/^.*build": "//p' | cut -d'|' -f1)
}

: # get sensor hash from latest version
function getSensorHash {
    CS_HEADER_CONTENT_TYPE="Content-Type: application/json"
    CS_HEADER_ACCEPT="accept: application/json"
    CS_HEADER_AUTH="authorization: bearer ${CS_Token}"
    callGET "/sensors/combined/installers/v1?limit=1&filter=$(urlencode 'platform:"mac"')"
    CS_SensorHash=$(echo ${CS_result} | sed -n -e 's/^.*sha256": "//p' | cut -d'"' -f1)
}

: # download sensor
function getSensor {
    CS_HEADER_CONTENT_TYPE="Content-Type: application/json"
    CS_HEADER_ACCEPT="accept: application/json"
    CS_HEADER_AUTH="authorization: bearer ${CS_Token}"
    CS_Sensor="true"
    callGET "/sensors/entities/download-installer/v1?id=${CS_SensorHash}" "${CS_SENSOR_PKG}"
    if [ "$(shasum -a 256 ${CS_SENSOR_PKG} | cut -d' ' -f1)" != "${CS_SensorHash}" ]
    then
        CS_Sensor="false"
        echo "Sensor hash mismatch."
    fi
}

: # Install sensor
function installSensor {
    installer -verboseR -package "${CS_SENSOR_PKG}" -target /
    /Applications/Falcon.app/Contents/Resources/falconctl load
    /Applications/Falcon.app/Contents/Resources/falconctl license ${CS_CID}
}

: # Cleanup
function cleanup {
    rm -rf "${CS_SENSOR_PKG}"
}


: # Call Falcon installation
if [ -f /Library/CS/falconctl ]; then
    echo "Sensor is already installed"
elif [ -f /Applications/Falcon.app/Contents/Resources/falconctl ]; then
    echo "Sensor is already installed"
else
    if [ -f ${CS_SENSOR_PKG} ]
    then
        installSensor
        cleanup
    else
        getToken
        getSensorHash
        getSensor
        installSensor
        cleanup
    fi
fi