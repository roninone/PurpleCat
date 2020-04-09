#!/bin/bash

systemctl stop Tiger_King
systemctl disable Tiger_King
rm -rf /etc/systemd/system/Tiger_King.service
rm /tmp/Tiger_King-Systemd*
systemctl daemon-reload

