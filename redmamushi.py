#!/usr/bin/env python3
#RUN: ./<FILENAME> os=<OS>
import sys
import subprocess
import os
ppos = sys.argv[1]
os.system("touch STATUS.txt")
os.system("echo 'FAILED' > STATUS.txt")
os.system("touch ow.txt")
os.system("echo 'SUCCESS' > ow.txt")
ddex = "dd of=./STATUS.txt if=./ow.txt"
output = subprocess.Popen([ddex], stdout=subprocess.PIPE, shell=True)
os.system("echo 'Your system is vulnerable to Mitre Att&ck: DD, data deletion.\n Best practice: disable 'dd'' >> STATUS.txt")
print(output.stdout.read())
#define each test in a separate function
#def create_account():
	
