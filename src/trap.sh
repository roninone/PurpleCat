#!/bin/bash

trap func exit 

function func () {
        userdel joshua_dial
} 

useradd -M -N -r -s /bin/bash -c evil_account joshua_dial 

