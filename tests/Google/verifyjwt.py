#!/usr/bin/env python
# -*- coding: utf-8 -*-


import json
import jwt
import requests

GOOGLE_CERTS_URI = 'https://www.googleapis.com/oauth2/v1/certs'


class GoogleIdToken(object):
    def __init__(self):
        self._certs = {}
        self._token = {}

    def getCerts(self):
        cert = requests.get(GOOGLE_CERTS_URI)
        if cert.status_code == 200:
            return json.loads(cert.content)

    def isValid(self, token, audience, clientId=None):
        self._certs = self.getCerts()
        for key in self._certs:
            try:
                token = jwt.decode(token, key=self._certs[key], verify=False)
                if 'email' in token and 'aud' in token:
                    if token['aud'] == audience and (clientId == token['cid'] if clientId is not None else True):
                        self._token = token
                        return True
            except Exception as e:
                print("Error decoding: %s" % e.message)
        return False