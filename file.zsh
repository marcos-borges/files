#!/bin/zsh
: # USER CONFIG ###############################################################################
CS_CLIENTID=""
CS_SECRET=""
CS_CID=""
CS_URL="https://api.crowdstrike.com"
: ############################################################################### USER CONFIG #

: # Version 5.X
if [ -f /Library/CS/falconctl ]; then
    CS_FALCONCTL="/Library/CS/falconctl"
fi

: # Version 6.X
if [ -f /Applications/Falcon.app/Contents/Resources/falconctl ]; then
    CS_FALCONCTL="/Applications/Falcon.app/Contents/Resources/falconctl"
fi

CS_AID=$(${CS_FALCONCTL} stats | sed -n -e 's/^.*agentID: //p' | tr -d - | tr '[:upper:]' '[:lower:]')

: # GET
function callGET {
    local uri=$1
    local outfile=$2
    local i=0

    local CS_N_HEADERS=($(set | grep CS_HEADER | sed -n -e 's/=.*$//p'))
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

    CS_result=$(curl "${CS_N_HEADERS_VALUES[@]/#/-H}" -d "${data}" "${CS_URL}${uri}" 2> /dev/null)
}

: # PUT
function callPUT {
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

    CS_result=$(curl -X PUT "${CS_N_HEADERS_VALUES[@]/#/-H}" -d ${data} "${CS_URL}${uri}" 2> /dev/null)
}

: # get token
function getToken {
    CS_HEADER_CONTENT_TYPE="Content-Type: application/x-www-form-urlencoded"
    CS_HEADER_ACCEPT="Accept: application/json"
    callPOST "/oauth2/token" "client_id=${CS_CLIENTID}&client_secret=${CS_SECRET}"
    CS_Token=$(echo ${CS_result} | sed -n -e 's/^.*access_token": "//p' | cut -d'"' -f1)
}

: # get Uninstall token
function getUninstall {
    CS_HEADER_CONTENT_TYPE="Content-Type: application/json"
    CS_HEADER_ACCEPT="accept: application/json"
    CS_HEADER_AUTH="authorization: bearer ${CS_Token}"
    callPOST "/policy/combined/reveal-uninstall-token/v1" '{ "audit_message": "ReplaceFalcon Real-Time Response script", "device_id": "'${CS_AID}'"}'
    CS_Uninstall=$(echo ${CS_result} | sed -n -e 's/^.*uninstall_token": "//p' | cut -d'"' -f1)
}

: # start Falcon migration
function cs_uninstall {
    CS_AID=$(${CS_FALCONCTL} stats | sed -n -e 's/^.*agentID: //p' | tr -d - | tr '[:upper:]' '[:lower:]')
    : # Version 5.X
    if [ -f /Library/CS/falconctl ]; then
        local CS_REGISTRY1="/Library/CS/registry.base"
        local CS_REGISTRY2="/Library/CS/Registry.bin"
        local CS_LICENSE="/Library/CS/License.bin"
    fi

    : # Version 6.X
    if [ -f /Applications/Falcon.app/Contents/Resources/falconctl ]; then
        local CS_REGISTRY1="/Library/Application\ Support/CrowdStrike/Falcon/registry.base"
        local CS_REGISTRY2="/Library/Application\ Support/CrowdStrike/Falcon/Registry.bin"
        local CS_LICENSE="/Library/Application\ Support/CrowdStrike/Falcon/License.bin"
    fi

    getToken
    [ -z "${CS_Token}" ] && echo "Error getting token." && return 0

    getUninstall
    [ -z "${CS_Uninstall}" ] && echo "Error getting uninstall token." && return 0

    yes ${CS_Uninstall} | ${CS_FALCONCTL} uninstall --maintenance-token >> /dev/null 2>&1
}

cs_uninstall &
