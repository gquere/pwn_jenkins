#!/usr/bin/env python3
import requests
import json
import urllib3
import os
import argparse


# SUPPRESS WARNINGS ############################################################
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# DOWNGRADE SSL ################################################################
from requests.packages.urllib3.contrib import pyopenssl
def downgrade_ssl():
    pyopenssl.DEFAULT_SSL_CIPHER_LIST = 'HIGH:RSA:!DH'
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'HIGH:RSA:!DH'


# CONSTANTS ####################################################################
OUTPUT_DIR = './output'
RECOVER_LAST_BUILD_ONLY = True
DEBUG = False


# UTILS ########################################################################
def print_debug(data):
    if DEBUG is True:
        print(data)


def create_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


# SAVERS #######################################################################
def dump_to_disk(url, consoleText, envVars):
    # first, to create dirs
    folder = OUTPUT_DIR + url.replace(BASE_URL, '')
    create_dir(folder)

    # then dump files
    with open(folder + 'consoleText', 'w+') as f:
        f.write(consoleText)

    with open(folder + 'envVars', 'w+') as f:
        f.write(envVars)


# DUMPERS ######################################################################
def dump_jobs(url):
    r = requests.get(url + '/api/json/' + '?tree=jobs[name]', verify=False, auth=AUTH)
    if 'Authentication required' in r.text:
        print('[ERROR] This Jenkins needs authentication')
        exit(1)
    if 'Invalid password/token' in r.text:
        print('[ERROR] Invalid password/token for user')
        exit(1)
    if 'missing the Overall/Read permission' in r.text:
        print('[ERROR] User has no read permission')
        exit(1)

    response = json.loads(r.text)
    print_debug(response)
    parse_job(response, url)


def dump_builds(url):
    r = requests.get(url + '/api/json/' + '?tree=builds[number]', verify=False, auth=AUTH)
    response = json.loads(r.text)
    print_debug(response)
    parse_builds(response, url)


def dump_build(url):
    r = requests.get(url + '/consoleText', verify=False, auth=AUTH)
    consoleText = r.text
    r = requests.get(url + '/injectedEnvVars/api/json', verify=False, auth=AUTH)
    envVars = r.text

    dump_to_disk(url, consoleText, envVars)


# PARSERS ######################################################################
def parse_job(response, url):
    for job in response['jobs']:
        print_debug(job)
        if job['_class'] == 'com.cloudbees.hudson.plugins.folder.Folder':
            print("[+] Found folder {}".format(job['name']))
            dump_jobs(url + '/job/' + job['name'] + '/' )
        elif job['_class'] == 'org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject':
            print("[+] Found branch {}".format(job['name']))
            dump_jobs(url + '/job/' + job['name'] + '/' )
        elif job['_class'] == 'hudson.model.FreeStyleProject':
            print("[+] Found job {}".format(job['name']))
            dump_builds(url + '/job/' + job['name'] + '/')
        elif job['_class'] == 'org.jenkinsci.plugins.workflow.job.WorkflowJob':
            print("[+] Found job {}".format(job['name']))
            dump_builds(url + '/job/' + job['name'] + '/')
        elif job['_class'] == 'hudson.maven.MavenModuleSet':
            print("[+] Found job {}".format(job['name']))
            dump_builds(url + '/job/' + job['name'] + '/')
        elif job['_class'] == 'com.tikal.jenkins.plugins.multijob.MultiJobProject':
            print("[+] Found job {}".format(job['name']))
            dump_builds(url + '/job/' + job['name'] + '/')
        else:
            print("[ERROR] Unknown type {}".format(job['_class']))


def parse_builds(response, url):
    if len(response['builds']) == 0:
        return

    for i in range(len(response['builds'])):
        build_number = response['builds'][i]['number']
        print("[+] Found build number {}".format(build_number))
        dump_build(url + str(build_number) + '/')
        if RECOVER_LAST_BUILD_ONLY == True:
            break


# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Dump all available info from Jenkins')
parser.add_argument('-U', '--url', type=str, required=True)
parser.add_argument('-u', '--user', type=str)
parser.add_argument('-p', '--password', type=str)
parser.add_argument('-o', '--output-dir', type=str)
parser.add_argument('-d', '--downgrade_ssl', action='store_true', help='Downgrade SSL to use RSA')
parser.add_argument('-f', '--full', action='store_true', help='Dump all available builds')

args = parser.parse_args()
if args.user and args.password:
    AUTH = (args.user, args.password)
else:
    AUTH = None
BASE_URL = args.url
if args.output_dir:
    OUTPUT_DIR = args.output_dir
if args.downgrade_ssl:
    downgrade_ssl()
if args.full:
    RECOVER_LAST_BUILD_ONLY = False

dump_jobs(BASE_URL)
