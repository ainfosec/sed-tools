#!/bin/bash

drive=$1

clear

#-----------
# Test Setup
#-----------

echo "----- [+] Initiating Drive ..."

./bin/sed_tools $drive --setup

if [ $? -ne 0 ]; then
	echo "\n\n----- [-] Failed to fully initialize hard drive"
	exit
fi

echo "----- [+] Drive Initialized"
echo "----- [+] Unlocking and Unshadowing drive"

#------------
# Test Lock
#------------

echo "----- [+] Locking Drive ..."

./bin/sed_tools $drive --default-account --lock-drive

if [ $? -ne 0 ]; then
		echo "\n\n----- [-] Failed to lock the drive"
		exit
fi

echo "----- [+] Successfully Locked the drive"

#------------
# Test Unlock
#------------

echo "----- [+] Unlocking Drive ..."

./bin/sed_tools $drive --default-account --unlock-drive

if [ $? -ne 0 ]; then
	echo "\n\n----- [-] Failed to unlock the drive"
	exit
fi

echo "----- [+] Drive Successfully Unlocked"
echo "----- [+] Verifying default accounts credentials"

#-----------
# Test Login
#-----------

echo "---- [+] Checking Account login information"

./bin/sed_tools $drive --default-account --test-login

if [ $? -ne 0 ]; then
	echo "\n\n----- [-] Failed to authenticate with default accounts"
	exit
fi

echo "----- [+] Accounts credentials verified"

#-----------------
# Revert the drive
#-----------------

echo "----- [+] Reverting the drive"

./bin/sed_tools $drive --revert dpassword

if [ $? -ne 0 ]; then
	echo "\n\n----- [-] Failed to revert the drive"
	exit
fi

echo "----- [+] Drive reverted"
echo "----- [+] Test completed successfully"
