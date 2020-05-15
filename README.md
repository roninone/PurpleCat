![Interface](/src/PurpleCat.png)

Purple Cat is a python tool that was made to automate the enumeration of Red Canary Co's [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests in order to determine if the detection of the tests are possible and output the findings to an easy to read report. Purple Cat allows every security team to test their controls and systems by automating simple tests that exercise the same techniques used by adversaries, which are all mapped to the [MITRE ATT&CK](https://attack.mitre.org/) matrices. PurpleCat adds an element of detection by generating a report which indicates where in the system the anomalous action was either detected or undetected. 

# YouTube Presentation

<a href="http://www.youtube.com/watch?feature=player_embedded&v=AsBeQ7xuN9M" target="_blank"><img src=/src/PurpleCatYoutube.PNG width="240" height="180" border="10" /></a>

# Prerequisite
## T1215 Test:
To run the kernel test, must have Linux-headers installed to compile the kernel module.

### Instructions:
1. Run: `apt update -y && apt upgrade -y && apt dist-upgrade `
*Might take awhile to finish depending on your system.
2. reboot
3. Run: `apt-get install build-essential linux-headers-``uname -r``

# Installation
`cd /opt`

`git clone https://github.com/roninone/PurpleCat`

## Create a symbolic link
`cd /bin`

`ln -s /opt/PurpleCat/purplecat.py PurpleCat`
