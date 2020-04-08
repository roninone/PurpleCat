#!/bin/bash

trap func exit 

function func () {

        echo "DELETING USER"
        userdel joshua_dial
        echo "USER DELETED" 

} 

useradd -M -N -r -s /bin/bash -c evil_account joshua_dial 

