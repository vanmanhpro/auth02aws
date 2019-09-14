# auth02aws

## Context
This tool is used for getting the temporary AWS Credentials for Auth0-integrated AWS accounts, something like this document:
https://auth0.com/docs/integrations/aws/sso

## Usage
```bash

./auth02aws.py --url 'login/url/from/auth0'

```

## FLow
Here's the diagram of the requests, response flow

![alt text](auth02aws.png?raw=True "auth02aws Flow")

## What I've learned
I've learned how to form HTTP requests by inspecting the browsers
I've learned the flow of Auth0 authentication and it's saml addons callback request
I know that I need to learn more about cookies and HTTP requests in general

## TO DO

### Make this a more convenient tool:
- Add more feature such as disable SSL verification to the argument
- Add a configure command and a configuration storage

### Refactor the code for security
- Add class for the credentials configuration instead of writing it down to file
