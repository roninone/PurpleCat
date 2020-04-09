#!/bin/bash

echo "[Unit]" > /etc/systemd/system/Tiger_King.service
echo "Description=Tiger King's Systemd Service" >> /etc/systemd/system/Tiger_King.service
echo "" >> /etc/systemd/system/Tiger_King.service
echo "[Service]" >> /etc/systemd/system/Tiger_King.service
echo "ExecStart=/bin/touch /tmp/Tiger_King-Systemd-Execstart-Marker" >> /etc/systemd/system/Tiger_King.service
echo "ExecStartPre=/bin/touch /tmp/Tiger_King-Systemd-Execstartpre-Marker" >> /etc/systemd/system/Tiger_King.service
echo "ExecStartPost=/bin/touch /tmp/Tiger_King-Systemd-Execstartpost-Marker" >> /etc/systemd/system/Tiger_King.service
echo "ExecReload=/bin/touch /tmp/Tiger_King-Systemd-Execreload-Marker" >> /etc/systemd/system/Tiger_King.service
echo "ExecStop=/bin/touch /tmp/Tiger_King-Systemd-Execstop-Marker" >> /etc/systemd/system/Tiger_King.service
echo "ExecStopPost=/bin/touch /tmp/Tiger_King-Systemd-Execstoppost-Marker" >> /etc/systemd/system/Tiger_King.service
echo "" >> /etc/systemd/system/Tiger_King.service
echo "[Install]" >> /etc/systemd/system/Tiger_King.service
echo "WantedBy=default.target" >> /etc/systemd/system/Tiger_King.service
systemctl daemon-reload
systemctl enable Tiger_King.service
systemctl start Tiger_King.service
