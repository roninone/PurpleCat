#!/usr/bin/env python3
#RUN: ./<FILENAME> os=<OS>
import sys
import subprocess
import os
ppos = sys.argv[1]

PASSED = ["SYSTEM PROTECTED AGAINST:"]
FAILED = ["SYSTEM VULNERABLE TO THREAT:"]

os.system("touch REPORT.txt")
#ddex = "dd of=./STATUS.txt if=./ow.txt"
#output = subprocess.Popen([ddex], stdin=subprocess.PIPE, shell=True)
#os.system("echo 'Your system is vulnerable to Mitre Att&ck: DD, data deletion.\n Best practice: disable 'dd'' >> STATUS.txt")
#print(output.stdout.read())
#define each test in a separate function
def create_account():
	user_add = "useradd -M -N -r -s /bin/bash -c evil_account joe_exotic"
	os.system(user_add)
	user_check = "cat /etc/passwd | tail -n1"
	output = subprocess.Popen([user_check], stdout=subprocess.PIPE, shell=True)
	result = output.stdout.read().decode("utf-8").split(":")
	if result[0] == "joe_exotic":
		print("Atomic Red Test, T1136 - CREATE ACCOUNT: VUL")
		FAILED.append("Atomic Red Test, T1136 - CREATE ACCOUNT: VUL")
	else:
		print("Atomic Rest Test, T1136 - CREATE ACCOUNT: PROTECTED")
		PASSED.append("Atomic Red Test, T1136 - CREATE ACCOUNT: PROTECTED")

	os.system("userdel joe_exotic")

def create_account_root():
	user_add = "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash carole_baskin"
	#user_pass = "echo 'ikilledmyhusband' | passwd --stdin carole_baskin"
	os.system(user_add)
	#os.system(user_pass)
	user_check = "cat /etc/passwd | tail -n1"
	output = subprocess.Popen([user_check], stdout=subprocess.PIPE, shell=True)
	result = output.stdout.read().decode("utf-8").split(":")
	if result[0] == "carole_baskin":
		print("Atomic Red Test, T1136(uid:0) - CREATE ACCOUNT: VULN")
		FAILED.append("Atomic Red Test, T1136(uid:0) - CREATE ACCOUNT: VULN")
	else:
		print("Atomic Rest Test, T1136(uid:0) - CREATE ACCOUNT: PROTECTED")
		PASSED.append("Atomic Red Test, T1136(uid:0) - CREATE ACCOUNT: PROTECTED")
	os.system("userdel -f carole_baskin > /dev/null 2>&1")

if __name__ == "__main__":
	#ADD TEST FUNCTIONS HERE
	create_account()
	create_account_root()

	#PRINTING OUT THE RESULTS
	with open('REPORT.txt', 'w') as f:
		for item in PASSED:
			f.write(item+"\n")
		for item in FAILED:
			f.write(item+"\n")
