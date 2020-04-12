#!/usr/bin/env python3

'''
Authors : Dawon Han, Daniel Lee and Kenny Masuda
Start Date : 2020-04-06

'''

import sys
import subprocess
import os
import time
from colorama import Fore

OS = subprocess.check_output("uname -s", shell=True).decode("ascii")

#ACTIONS TAKEN ON SYSTEM
REPORT_FIELD = ["ART TEST:", "DETECTION RESULT:", "MITRE ATT&CK TECHNIQUE:\"https://attack.mitre.org/techniques/"]
REPORT = ["MITRE ATT&CK FRAMEWORK TEST - PERSISTENCE\n"]

os.system("touch REPORT.txt")

def test_start(TEST):
    os.system(f"echo -n '{TEST} TEST IN PROGRESS.....'")
    os.system("sleep 3")

def test_complete(TEST):
    CM = '\N{check mark}'
    os.system(f"echo -e '\\r{CM} {TEST} Completed                      '")

def anylog_readlines(num, type):
    #num = number of lines to read
    #type = which log file in /var/log/
    f = open(f"/var/log/{type}", "r")
    list_f = f.readlines()
    lines = len(list_f) - num
    tail_lines = list_f[lines:]
    return tail_lines

def match_anylog(num, case_match, logfile):
	#logfile = file to read
    loglines = anylog_readlines(num, logfile)
    result = "NONE"
    for line in loglines:
        if case_match in line:
            result = line

    return result

def create_account():
    test_start("Create Account")
    user_add = "useradd -M -N -r -s /bin/bash -c evil_account joe_exotic"
    os.system(user_add)
    result = match_anylog(2, "useradd", "auth.log")
    REPORT.append(f"{REPORT_FIELD[0]} T1136: Create Account: Allows for persistence on the system.\n{REPORT_FIELD[1]} {result}{REPORT_FIELD[2]}T1136/\"\n")
    os.system("userdel joe_exotic")
    test_complete("Create Account")

def create_account_root():
    test_start("CREATE ACCOUNT ROOT")
    user_add = "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash carole_baskin"
    os.system(user_add)

    #result = match_log(2, "name=carole_baskin, UID=0, GID=0")
    result = match_anylog(2, "name=carole_baskin, UID=0, GID=0", "auth.log")
    REPORT.append(f"{REPORT_FIELD[0]} T1136: Create New User with Root UID and GID: Allows for persistence on the system.\n{REPORT_FIELD[1]} {result}{REPORT_FIELD[2]}T1136/\"\n")

    os.system("userdel -f carole_baskin > /dev/null 2>&1")
    test_complete("CREATE ACCOUNT ROOT")

def set_uid_gid():
    test_start("SET UID")
    set_uid = "sudo touch ./src/john_finlay"
    os.system(set_uid)
    change_own = "sudo chown root ./src/john_finlay"
    os.system(change_own)
    change_mod = "sudo chmod u+s ./src/john_finlay > /dev/null 2>&1" 
    os.system(change_mod)
    change_gid = "sudo chmod g+s ./src/john_finlay > /dev/null 2>&1"
    os.system(change_gid)

    result = match_anylog(10, "COMMAND=/usr/bin/chmod u+s ./src/john_finlay", "auth.log")
    result_2 = match_anylog(10, "COMMAND=/usr/bin/chmod g+s ./src/john_finlay", "auth.log") 

    REPORT.append(f"{REPORT_FIELD[0]} T1166: SetUID and SetGID: Allows for persistence on the system - Applications can be run with the privileges of the owning user or group respectively.\n{REPORT_FIELD[1]} {result}{REPORT_FIELD[2]}T1166/\"\n")
    os.system("sudo rm ./src/john_finlay > /dev/null 2>&1")
    test_complete("SET UID")

def create_hidden_stuff():
    # T1158 - Hidden Files and Directories
    test_start("CREATE HIDDEN STUFF")
    hidden_directory = "mkdir /var/tmp/.Bhagavan"
    hidden_file = 'echo "It’s not a job, it’s a lifestyle. -Bhagavan Doc Antle" > /var/tmp/.Bhagavan/.Doc_Antle'
    
    os.system(hidden_directory)    
    if os.path.exists('/var/tmp/.Bhagavan'):
        REPORT.append(f"{REPORT_FIELD[0]} T1158: Hidden Directory: Allows for persistence and evasion.\n{REPORT_FIELD[1]} Hidden directory .Bhagavan was successfully created and detected\n{REPORT_FIELD[2]}T1158/\"\n")
    else:
        REPORT.append(f"{REPORT_FIELD[0]} T1158: Hidden Directory: Allows for persistence and evasion.\n{REPORT_FIELD[1]} Hidden directory was not successfully created\n{REPORT_FIELD[2]}T1158/\"\n")
        
    os.system(hidden_file)
    if os.path.exists('/var/tmp/.Bhagavan/.Doc_Antle'):
        REPORT.append(f"{REPORT_FIELD[0]} T1158: Hidden Directory: Allows for persistence and evasion.\n{REPORT_FIELD[1]} Hidden file .Doc_Antle was successfully created and detected\n{REPORT_FIELD[2]}T1158/\"\n")
    else:
        REPORT.append(f"{REPORT_FIELD[0]} T1158: Hidden Directory: Allows for persistence and evasion.\n{REPORT_FIELD[1]} Hidden file .Doc_Antle was not successfully created\n{REPORT_FIELD[2]}T1158/\"\n")

    os.system('rm -rf /var/tmp/.Bhagavan/')
    test_complete("CREATE HIDDEN delete_file")

def issa_trap():
    #T1154 - Trap: Trap command allows programs and shells to specify commands that will be executed
    #upon receiving interrupt signals. 
    test_start("ISSA TRAP")
    os.system("chmod +x ./src/trap.sh")
    run_trap = "./src/trap.sh"
    os.system(run_trap)

    result = match_anylog(5, "delete user", "auth.log") 
    REPORT.append(f"{REPORT_FIELD[0]} T1154: TRAP: Allows for persistence on the system - Trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals.\n{REPORT_FIELD[1]} {result}{REPORT_FIELD[2]}T1154/\"\n") 
    test_complete("ISSA TRAP")

def t1215_test():
    test_start("t1215 TEST")
    os.system("echo 'Y' | apt-get install build-essential linux-headers-`uname -r` > /dev/null 2>&1")
    os.system("cd ./src/t1215_km && make > /dev/null 2>&1")
    os.system("cd ./src/t1215_km && sudo insmod t1215_test.ko")
    os.system("sudo rmmod t1215_test")
    run_log = match_anylog(4, "Hello, K3r#3L", "kern.log")
    exit_log = match_anylog(2, "Goodbye, k3RnE1", "kern.log").rstrip()
    REPORT.append(f"{REPORT_FIELD[0]} T1215:Kernel Modules and Extension\n{REPORT_FIELD[1]}\n{run_log}{exit_log}\n{REPORT_FIELD[2]}T1215/\"\n")

    os.system("cd ./src/t1215_km && sudo rm modules.order Module.symvers t1215_test.ko t1215_test.mod.c t1215_test.mod.o t1215_test.o")
    os.system("cd ./src/t1215_km && sudo rm -rf ./.* > /dev/null 2>&1")
    test_complete("t1215 TEST")

def systemd_service():
    # T1501 - Systemd Service
    test_start("SYSMTEMMDMD TEST")
    os.system("chmod +x ./src/tiger_king.sh")
    os.system("chmod +x ./src/kill_the_king.sh")
    systemd_create = './src/tiger_king.sh > /dev/null 2>&1'
    systemd_remove = './src/kill_the_king.sh > /dev/null 2>&1'
    os.system(systemd_create)
    os.system(systemd_remove)
    success_log = match_anylog(10, "Tiger King", "syslog")
    REPORT.append(f"{REPORT_FIELD[0]} T1501: Systemd Service: Allows for persistence on the system - Creating and/or modifying service unit files that cause systemd to execute malicious commands at recurring intervals.\n{REPORT_FIELD[1]} {success_log}{REPORT_FIELD[2]}T1501/\"\n")
    test_complete("SYSTEMD TEST")

def local_scheduling():
    test_start("LOCAL SCHED TEST")
    replace_crontab = "echo '* * * * * /tmp/evil.sh' > /tmp/persistevil && crontab /tmp/persistevil" 
    os.system(replace_crontab) 
    time.sleep(61)
    
    result = match_anylog(10, "(root) CMD (/tmp/evil.sh)", "syslog")
    REPORT.append(f"{REPORT_FIELD[0]} T1168: Local Job Scheduling: Allows for persistence on the system - Replace crontab with referenced file.\n{REPORT_FIELD[1]} {result}{REPORT_FIELD[2]}T1168/\"\n") 

    delete_file= "rm /tmp/persistevil" 
    os.system(delete_file) 

    delete_cron = "crontab -u root -l | grep -v '/tmp/evil.sh' | crontab -u root -" 
    os.system(delete_cron) 
    test_complete("SCHED TEST")

def purplecat_title():
    print(Fore.MAGENTA +
'''  
██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗     ██████╗ █████╗ ████████╗
██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝    ██╔════╝██╔══██╗╚══██╔══╝
██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗      ██║     ███████║   ██║   
██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝      ██║     ██╔══██║   ██║   
██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗    ╚██████╗██║  ██║   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝     ╚═════╝╚═╝  ╚═╝   ╚═╝   
    
'''
)

if __name__ == "__main__":
    purplecat_title()
    create_account()
    create_account_root()
    set_uid_gid()
    create_hidden_stuff()
    issa_trap()
    t1215_test()
    systemd_service()
    #local_scheduling()

    #PRINTING OUT THE RESULTS
    with open('REPORT.txt', 'w') as f:
        for item in REPORT:
            f.write(item+"\n")
    print("\nCheck results in REPORT.txt")
