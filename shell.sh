#!/bin/bash

function crn_req(){
    if [ "$#" -lt 2 ]; then
        echo "crn_req X Y"
        echo -e "\t where X and Y are the id of the manager and the patient respectively."
        echo -e "\t e.g. crn_req 1 2"
        return
    fi
    command="./crn-request -p manager-$1.pub -s manager-$1 -a manager-$1.access -m master.pub -P patient-$2.pub -I"
    echo "${command}"
    eval $command
    return $?
}

function crn_req_n(){
    if [ "$#" -lt 3 ]; then
        echo "crn_req_n X Y N"
        echo -e "\t where X and Y are the id of the manager and the patient respectively and N is the number of records to be inserted."
        echo -e "\t e.g. crn_req_n 1 2 3"
        echo -e "\t\t the above command will insert 3 records"
        echo -e "\t\t MXPY.1"
        echo -e "\t\t MXPY.2"
        echo -e "\t\t MXPY.3"
        return
    fi
    command="seq -f \"uM$1P$2.%1g\" 1 $3 | crn_req $1 $2"
    echo "${command}"
    eval $command
    return $?
}

function crn_req_rn(){
    if [ "$#" -lt 3 ]; then
        echo "crn_req_rn X Y N"
        echo -e "\t where X and Y are the number of managers and patients respectively and N is the number of records to be inserted."
        echo -e "\t e.g. crn_req_rn 3 3 3"
        echo -e "\t the above command will insert 3 records each associated with a random manager and a random patient"
        return
    fi
    for i in $(seq 1 $3)
    do
        x=`shuf -i 0-$1 -n1`
        y=`shuf -i 0-$2 -n1`
        command="echo M$x""P$y.$i | crn_req $x $y"
        echo "${command}"
        eval $command
    done
    return $?
}
