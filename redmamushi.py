#!/usr/bin/env python3
#RUN: ./<FILENAME> os=<OS>
import sys
import subprocess
import os
ppos = sys.argv[1]

PASSED = ["LIST OF PASSED TESTS"]
FAILED = ["LIST OF FAILED TESTS"]

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
		print("Atomic Red Test, T1136 - CREATE ACCOUNT: FAILED")
		FAILED.append("Atomic Red Test, T1136 - CREATE ACCOUNT: FAILED")
	else:
		print("Atomic Rest Test, T1136 - CREATE ACCOUNT: PASS")
		PASSED.append("Atomic Red Test, T1136 - CREATE ACCOUNT: PASS")

	os.system("userdel joe_exotic")

if __name__ == "__main__":
	#ADD TEST FUNCTIONS HERE
	create_account()

	#PRINTING OUT THE RESULTS
	with open('REPORT.txt', 'w') as f:
		for item in PASSED:
			f.write(item+"\n")
		for item in FAILED:
			f.write(item+"\n")
