#!/usr/bin/env python3
import requests
import json
import urllib3
from urllib.parse import urlparse
import os
import argparse
import concurrent.futures


# SUPPRESS WARNINGS ############################################################
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# DOWNGRADE SSL ################################################################
from requests.packages.urllib3.contrib import pyopenssl
def downgrade_ssl():
    pyopenssl.DEFAULT_SSL_CIPHER_LIST = 'HIGH:RSA:!DH'
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'HIGH:RSA:!DH'


# CONSTANTS ####################################################################
OUTPUT_DIR = './output/'
RECOVER_LAST_BUILD_ONLY = False
RECOVER_FROM_FAILURE = False
DEBUG = False
BUILD_LIST = []
FORCE_SSL = False


# UTILS ########################################################################
def print_debug(data):
    if DEBUG is True:
        print(data)


def create_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


# SAVERS #######################################################################
def dump_to_disk(url, consoleText, envVars):

    # first, need to create dirs
    parsed_url = urlparse(url)
    folder = OUTPUT_DIR + '/' + parsed_url.path
    create_dir(folder)

    # then dump files
    with open(folder + 'consoleText', 'w+') as f:
        f.write(consoleText)

    with open(folder + 'envVars', 'w+') as f:
        f.write(envVars)


def job_was_dumped(url):
    folder = OUTPUT_DIR + url.replace(BASE_URL, '')
    return os.path.exists(folder)


# DUMPERS ######################################################################
# some retarded Jenkinses return 'localhost' or some other crap instead of a
# FQDN when queried via the API, so these have to be replaced each time
def sanitize_url(url):
    parsed_url = urlparse(url)
    parsed_original_url = urlparse(BASE_URL)
    if FORCE_SSL:
        sanitized = parsed_url._replace(netloc=parsed_original_url.netloc, scheme='https')
    else:
        sanitized = parsed_url._replace(netloc=parsed_original_url.netloc)
    return sanitized.geturl()


def dump_jobs(url):
    url = sanitize_url(url)

    try:
        r = SESSION.get(url + '/api/json/', verify=False, auth=AUTH, timeout=20)
    except requests.exceptions.SSLError as e:
        print('[ERROR] This server refused our key negociation, retry with -d to downgrade ciphers')
        exit(1)
    except requests.exceptions.ConnectTimeout:
        print('[ERROR] Connection to the server timed out. Is the server up?')
        exit(1)

    if 'Authentication required' in r.text:
        print('[ERROR] This Jenkins requires authentication')
        exit(1)
    if 'Invalid password/token' in r.text:
        print('[ERROR] Invalid password/token for user')
        exit(1)
    if 'missing the Overall/Read permission' in r.text:
        print('[ERROR] User has no read permission')
        exit(1)

    try:
        response = json.loads(r.text)
    except:
        print('[ERROR] Failed parsing server response for {}, try -f maybe or -v for debug'.format(url + '/api/json/'))
        if DEBUG:
            print(r.text)
        return

    if 'jobs' in response:
        for job in response['jobs']:
            if RECOVER_FROM_FAILURE and job_was_dumped(job['url']):
                continue
            try:
                dump_jobs(job['url'])
            except requests.exceptions.ReadTimeout:
                print('[ERROR] Gave up on job {} because of a timeout (server is probably busy)'.format(job['name']))

    if 'builds' in response:
        for build in response['builds']:
            BUILD_LIST.append(build['url'])
            if RECOVER_LAST_BUILD_ONLY == True:
                break


def dump_build(url):
    print_debug('    Dumping build {}'.format(url))
    url = sanitize_url(url)
    r = SESSION.get(url + '/consoleText', verify=False, auth=AUTH, timeout=20)
    consoleText = r.text
    r = SESSION.get(url + '/injectedEnvVars/api/json', verify=False, auth=AUTH, timeout=20)
    envVars = r.text

    dump_to_disk(url, consoleText, envVars)



# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Dump all available info from Jenkins')
parser.add_argument('url', nargs='+', type=str)
parser.add_argument('-u', '--user', type=str)
parser.add_argument('-p', '--password', type=str)
parser.add_argument('-o', '--output-dir', type=str)
parser.add_argument('-l', '--last', action='store_true', help='Dump only the last build of each job')
parser.add_argument('-r', '--recover_from_failure', action='store_true', help='Recover from server failure, skip all existing directories')
parser.add_argument('-d', '--downgrade_ssl', action='store_true', help='Downgrade SSL to use RSA (for legacy)')
parser.add_argument('-f', '--force-ssl', action='store_true', help='Force usage of SSL if API returns wrong HTTP-only links')
parser.add_argument('-s', '--no_use_session', action='store_true', help='Don\'t reuse the HTTP session, but create a new one for each request (for legacy)')
parser.add_argument('-v', '--verbose', action='store_true', help='Debug mode')

args = parser.parse_args()
if args.user and args.password:
    AUTH = (args.user, args.password)
else:
    AUTH = None
if args.output_dir:
    OUTPUT_DIR = args.output_dir + '/'
if args.downgrade_ssl:
    downgrade_ssl()
if args.force_ssl:
    FORCE_SSL = True
if args.last:
    RECOVER_LAST_BUILD_ONLY = True
if args.recover_from_failure:
    RECOVER_FROM_FAILURE = True
if args.verbose:
    DEBUG = True
if args.no_use_session:
    SESSION = requests
else:
    SESSION = requests.session()
BASE_URL = args.url[0]

print('[+] Getting a list of jobs and builds')
dump_jobs(BASE_URL)
print('    Got {} builds to dump'.format(len(BUILD_LIST)))
print('[+] Dumping gathered builds')
with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
    executor.map(dump_build, BUILD_LIST)
