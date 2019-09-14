#!/usr/bin/python
from form_function_provider import make_authentication_payload, make_callback_payload, extract_saml
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from os.path import expanduser
import xml.etree.ElementTree as ET
import requests
import json
import sys
import base64
import boto3
import configparser
import getpass
import argparse

SSL_VERIFY = True

AWS_CREDENTIALS_FILE = expanduser('~') + '/.aws/credentials'

# get login URL
parser = argparse.ArgumentParser()
parser.add_argument("--url", help="Login URL provided by Auth0", required=True)
args = parser.parse_args()

loginURL = args.url

# make URL strings
parsedurl = urlparse(loginURL)
tenant = parsedurl.netloc.split('.')[0]
clientId = parsedurl.path.split('/')[2]

# make credentials
with open('credentials_temp.json') as file:
    cred = json.load(file)

cred['client_id'] = clientId
cred['tenant'] = tenant

with open('/tmp/credentials.json','+w') as file:
    file.write(json.dumps(cred))


session = requests.Session()

# get form login
form_login_response = session.get(loginURL, verify=SSL_VERIFY)

# get username, password
print("Username:", end=' ')
username = input()
password = getpass.getpass("Password: ")

# authenticate request
authen_payload = make_authentication_payload(form_login_response.text, username, password)

authen_response = session.post(url='https://{tenant}.auth0.com/usernamepassword/login'.format(tenant=tenant), data=authen_payload, verify=SSL_VERIFY)

# callback request
callback_payload = make_callback_payload(authen_response.text)

session.headers.update({'content-type': 'application/x-www-form-urlencoded'})

callback_response = session.post('https://{tenant}.auth0.com/login/callback'.format(tenant=tenant), data=callback_payload, verify=SSL_VERIFY)

# assume role with saml
assertion = extract_saml(callback_response.text)

saml = base64.b64decode(assertion).decode('utf-8')

# extract roles
awsroles = []
root = ET.fromstring(saml)
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# reverse the role/provider order if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# promt role selection
print("")
if len(awsroles) > 1:
    i = 0
    print("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print('[', i, ']: ', awsrole.split(',')[0])
        i += 1
    print("Selection: ", end=' ')
    selectedroleindex = input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

client = boto3.client('sts')

response = client.assume_role_with_saml(
    RoleArn=role_arn,
    PrincipalArn=principal_arn,
    SAMLAssertion=assertion
)

print(json.dumps(response, indent=2, default=str)) # This is for debugging


# dumps to aws credentials file
config = configparser.RawConfigParser()
config.read(AWS_CREDENTIALS_FILE)

if not config.has_section('saml'):
	config.add_section('saml')

config.set('saml', 'aws_access_key_id', response['Credentials']['AccessKeyId'])
config.set('saml', 'aws_secret_access_key', response['Credentials']['SecretAccessKey'])
config.set('saml', 'aws_session_token', response['Credentials']['SessionToken'])
config.set('saml', 'aws_security_token', response['Credentials']['SessionToken'])
config.set('saml', 'x_principal_arn', response['AssumedRoleUser']['Arn'])
config.set('saml', 'x_security_token_expires', response['Credentials']['Expiration'])

with open(AWS_CREDENTIALS_FILE, 'w+') as configfile:
	config.write(configfile)