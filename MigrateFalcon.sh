#!/bin/bash
# USER CONFIG ###############################################################################
CS_DSTCLIENTID=""
CS_DSTSECRET=""
CS_SRCCLOUD=""
CS_DSTCLOUD=""
CS_CID=""
CS_INSTALLER="/tmp/falcon"
CS_ARGS=""
CS_HASH=""
CS_AUDIT="Real-Time Response script - sensor migration"
CS_PROXY=""
############################################################################### USER CONFIG #

#Set CID to set variable
for ARGUMENTS in "$@"
do
    KEY=$(echo $ARGUMENTS | cut -f1 -d=)
    VALUE=$(echo $ARGUMENTS | cut -f2 -d=)
    case "$KEY" in
        CS_SRCCLOUD) CS_SRCCLOUD=${VALUE} ;;
        CS_DSTCLOUD) CS_DSTCLOUD=${VALUE} ;;
        CS_DSTCLIENTID) CS_DSTCLIENTID=${VALUE} ;;
        CS_DSTSECRET) CS_DSTSECRET=${VALUE} ;;
        CS_CID) CS_CID=${VALUE} ;;
        CS_INSTALLER) CS_INSTALLER=${VALUE} ;;
        CS_ARGS) CS_ARGS=${VALUE} ;;
        CS_HASH) CS_HASH=${VALUE} ;;
        CS_AUDIT) CS_AUDIT=${VALUE} ;;
        CS_PROXY) CS_PROXY=${VALUE} ;;
        *)
    esac
done
