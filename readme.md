# Status

[![CircleCI](https://circleci.com/gh/Firesphere/silverstripe-graphql-jwt/tree/master.svg?style=svg)](https://circleci.com/gh/Firesphere/silverstripe-graphql-jwt/tree/master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Firesphere/silverstripe-graphql-jwt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Firesphere/silverstripe-graphql-jwt/?branch=master)


# GraphQL JSON Web Token authenticator

This module provides a JWT-interface for creating JSON Web Tokens for authentication.

## Installation

`composer require firesphere/silverstripe-graphql-jwt`

Currently, only dev-master is available, as it's in heavy development.

## Log in

To generate a JWT token, send a login request to the `createToken` mutator. E.g.:
```
mutation {
  createToken(Email: "admin", Password: "password") {
    Token, // Required, or you won't get a token back
    ID,
    FirstName,
    Surname
  }
}
```

## Validate token

If you have an app and want to validate your token, you can address the `validateToken` method. E.g.:
```
query {
    validateToken
}
```

It only needs to call the endpoint. The token should be in the header, via your middleware for the request, as a `Authorization: Bearer 1235'piue,,54fxdg5`

If the token is valid, you'll get a response like this:
```
data: {
  validateToken: true
}
```

And obviously the response is false when the token is invalid.


## Enable CORS

To use JWT, CORS needs to be enabled. This can be done by adding the following to your projects config:

```yaml
SilverStripe\GraphQL\Controller:
  cors:
    Enabled: true # Off by default
    Allow-Origin: '*' # Deny all by default
    Allow-Headers: 'Authorization, Content-Type'
    Allow-Methods:  'GET, POST, OPTIONS'
    Max-Age:  86400  # 86,400 seconds = 1 day.
```

## Usage

After logging in, you will receive a token which can be used for further requests. This token should be in the header of the request with the `Bearer` as signature, e.g.:
```
Authorization: Bearer 123456789ctmbxkjup.euidhtcgcfdiupyefuqdjihkdthdn
```
(That is not an actual valid token.)

## Security

Currently, the default method for encrypting the JWT is with Sha256.

JWT is signed with multiple factors, including the host, audience (app/remote user), a secret key and a timeframe within which the token is valid.

## Supported services

By default, JWT only supports login. As it's tokens can not be disabled, nor used for password changes or resets.

## Examples

A Postman collection can be found in the `extra` folder.

# License

This module is published under BSD 3-clause license, although these are not in the actual classes, the license does apply:

http://www.opensource.org/licenses/BSD-2-Clause

Copyright (c) 2012-NOW(), Simon "Sphere" Erkelens

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# Cow?

Of course!
```

               /( ,,,,, )\
              _\,;;;;;;;,/_
           .-"; ;;;;;;;;; ;"-.
           '.__/`_ / \ _`\__.'
              | (')| |(') |
              | .--' '--. |
              |/ o     o \|
              |           |
             / \ _..=.._ / \
            /:. '._____.'   \
           ;::'    / \      .;
           |     _|_ _|_   ::|
         .-|     '==o=='    '|-.
        /  |  . /       \    |  \
        |  | ::|         |   | .|
        |  (  ')         (.  )::|
        |: |   |;  U U  ;|:: | `|
        |' |   | \ U U / |'  |  |
        ##V|   |_/`"""`\_|   |V##
           ##V##         ##V##
```
