#!/bin/sh
#
# Place this script in the same directory as rbl_check.php so you can use a cron call to run the php script.
# It is highly recommended that you set $showprogress = 0; in rbl_check.php as not doing so will output a lot of data.
#
# This sets the script directory to be the working directory. Do not modify.
cd "$(dirname "$0")"
# Run the RBL checker and send the results to an email address.
# Replace you@your_name.tld below with your email address.
php rbl_check.php | mail -s "RBL Checker Results" you@your_name.tld
