#! /bin/bash

LOGGER='logger'
ABSOLUTE_PATH=$(eval pwd)
LOGGER_SO_PATH='./hw2.so'
OUTPUT_TO_FILE='/dev/stderr'
READY_TO_RECEIVE_CMD="NO"
CMD=""
USAGE="usage: ./${LOGGER} [-o file] [-p sopath] [--] cmd [cmd args ...]
        -p: set the path to logger.so, default = ./logger.so
        -o: print output to file, print to \"stderr\" if no file specified
        --: separate the arguments for logger and for the command"

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    if [[ "$READY_TO_RECEIVE_CMD" == "NO" ]];
    then
        case $1 in
            -p|-P)
            LOGGER_SO_PATH="$2"
            shift # past argument
            shift # past value
            ;;
            -o|-O)
            OUTPUT_TO_FILE="$2"
            shift # past argument
            shift # past value
            ;;
            --)
            READY_TO_RECEIVE_CMD="YES"
            shift
            ;;
            *)
            if [[ $1 =~ ^- ]];
            then
                echo "${ABSOLUTE_PATH}/logger: invalid option -- '${1:1}'" # get the $1 position 1:end
                echo "$USAGE"
                exit 1
            else
            READY_TO_RECEIVE_CMD="YES"
            CMD+="$1"
            fi
            shift
            ;;
        esac
    else
        CMD+="$1 "
        shift
    fi
done

if [[ "$CMD" == "" ]];
then
    echo "no command given."
    exit 1
fi

if [[ ! -e ${OUTPUT_TO_FILE} ]]; then
    touch ${OUTPUT_TO_FILE}
else
    cat /dev/null > ${OUTPUT_TO_FILE}
fi


export LD_PRELOAD=${LOGGER_SO_PATH}
eval "$CMD" 2> ${OUTPUT_TO_FILE}
export LD_PRELOAD=""