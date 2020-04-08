#!/usr/bin/env python3
#RUN: ./<FILENAME> os=<OS>
import sys
import subprocess
import os
ppos = sys.argv[1]

#ACTIONS TAKEN ON SYSTEM
REPORT_FIELD = ["ART TEST:", "DETECTION RESULT:", "LOG:"]
REPORT = []

os.system("touch REPORT.txt")
def authlog_readlines(num):
	#num = number of lines to read
	f = open("/var/log/auth.log", "r")
	list_f = f.readlines()
	lines = len(list_f) - num
	tail_lines = list_f[lines:]
	return tail_lines

def match_log(num, case_match):
	loglines = authlog_readlines(num)
	print(loglines)
	result = "NONE"
	for line in loglines:
		if case_match in line:
			result = line
	return result

def create_account():
	user_add = "useradd -M -N -r -s /bin/bash -c evil_account joe_exotic"
	os.system(user_add)
	result = match_log(2, "useradd")
	REPORT.append(f"{REPORT_FIELD[0]} T1136\n{REPORT_FIELD[1]} {result}")
	os.system("userdel joe_exotic")

def create_account_root():
	user_add = "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash carole_baskin"
	#user_pass = "echo 'ikilledmyhusband' | passwd --stdin carole_baskin"
	os.system(user_add)
	result = match_log(2, "name=carole_baskin, UID=0, GID=0")
	REPORT.append(f"{REPORT_FIELD[0]} T1136\n{REPORT_FIELD[1]} {result}")


#	user_check = "cat /etc/passwd | tail -n1"
#	output = subprocess.Popen([user_check], stdout=subprocess.PIPE, shell=True)
#	result = output.stdout.read().decode("utf-8").split(":")
#	if result[0] == "carole_baskin":
#		print("Atomic Red Test, T1136(uid:0) - CREATE ACCOUNT: VULN")
#		FAILED.append("Atomic Red Test, T1136(uid:0) - CREATE ACCOUNT: VULN")
#	else:
#		print("Atomic Rest Test, T1136(uid:0) - CREATE ACCOUNT: PROTECTED")
#		PASSED.append("Atomic Red Test, T1136(uid:0) - CREATE ACCOUNT: PROTECTED")
	os.system("userdel -f carole_baskin > /dev/null 2>&1")

def set_uid_gid():
    set_uid = "sudo touch ./src/john_finlay"
    os.system(set_uid)

    change_own = "sudo chown root ./src/john_finlay"
    os.system(change_own)

    change_mod = "sudo chmod u+s ./src/john_finlay > /dev/null 2>&1" 
    os.system(change_mod)

    change_gid = "sudo chmod g+s ./src/john_finlay > /dev/null 2>&1"
    result = match_log(10, "COMMAND=/usr/bin/chmod u+s ./src/john_finlay")
    result_2 = match_log(10, "COMMAND=/usr/bin/chmod g+s ./src/john_finlay") 

    REPORT.append(f"{REPORT_FIELD[0]} T1166\n{REPORT_FIELD[1]} {result}")
    os.system("sudo rm ./src/john_finlay > /dev/null 2>&1")

def create_hidden_stuff():
    # T1158 - Hidden Files and Directories
    hidden_directory = "mkdir /var/tmp/.Bhagavan"
    hidden_file = 'echo "It’s not a job, it’s a lifestyle. -Bhagavan Doc Antle" > /var/tmp/.Bhagavan/.Doc_Antle'
    
    os.system(hidden_directory)    
    if os.path.exists('/var/tmp/.Bhagavan'):
        REPORT.append(f"{REPORT_FIELD[0]} T1158\n{REPORT_FIELD[1]} Hidden directory .Bhagavan was successfully created and detected\n")
    else:
        REPORT.append(f"{REPORT_FIELD[0]} T1158\n{REPORT_FIELD[1]} Hidden directory was not successfully created\n")
        
    os.system(hidden_file)
    if os.path.exists('/var/tmp/.Bhagavan/.Doc_Antle'):
        REPORT.append(f"{REPORT_FIELD[0]} T1158\n{REPORT_FIELD[1]} Hidden file .Doc_Antle was successfully created and detected\n")
    else:
        REPORT.append(f"{REPORT_FIELD[0]} T1158\n{REPORT_FIELD[1]} Hidden file .Doc_Antle was not successfully created\n")

    os.system('rm -rf /var/tmp/.Bhagavan/')

def issa_trap():
    #T1154 - Trap: Trap command allows programs and shells to specify commands that will be executed
    #upon receiving interrupt signals. 

    run_trap = "./src/trap.sh"
    os.system(run_trap)

    result = match_log(5, "delete user") 
    REPORT.append(f"{REPORT_FIELD[0]} T1554 0 TRAP\n{REPORT_FIELD[1]} {result}") 


if __name__ == "__main__":
	#ADD TEST FUNCTIONS HERE
	create_account()
	create_account_root()
	set_uid_gid()
	create_hidden_stuff()
	issa_trap()

	#PRINTING OUT THE RESULTS
	with open('REPORT.txt', 'w') as f:
		for item in REPORT:
			f.write(item+"\n")
