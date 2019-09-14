#!/usr/bin/python -W ignore
from bs4 import BeautifulSoup
import re
import urllib.parse
import json
import base64

def make_callback_payload(form_callback):
    bs_form = BeautifulSoup(form_callback, features="html.parser")

    payload = {}

    for inputtag in bs_form.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        
        if (value != 'Submit'):
            payload[name] = value
    
    return urllib.parse.urlencode(payload)

def make_authentication_payload(form_login, username, password):
    bs_form = BeautifulSoup(form_login, features="html.parser")
    
    scripts = bs_form.find_all(re.compile('(SCRIPT|script)'))
    login_script = scripts[1].contents[0]

    match = re.search('(?<=var authParams = JSON.parse\(decodeURIComponent\(escape\(window.atob\(\')(.+)(?=\'\)\)\)\);)',login_script)

    token = match.group()

    token_decoded = json.loads(base64.b64decode(token).decode('utf-8'))

    with open('/tmp/credentials.json') as credentials_file:
        credentials = json.load(credentials_file)

    credentials['username'] = username
    credentials['password'] = password

    for key in token_decoded.keys():
        credentials[key] = token_decoded[key]

    return credentials

def extract_saml(saml_response):
    bs_form = BeautifulSoup(saml_response, features="html.parser")

    for inputtag in bs_form.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')

        if (name == 'SAMLResponse'):
            return value
    
    return "No SAML response"

# Debug

# if __name__ == "__main__":
#     with open('saml_response.html') as saml_response_file:
#         print(extract_saml(saml_response_file))