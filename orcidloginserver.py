#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This is demo server for testing Orcid authentication based on Tornado Web Server
# run this command to start web server on port 8888 : python orcidloginserver.py
# Code built by AVEbrahimi (vakilzadeh@gmail.com)

import os
import binascii
import pathlib
import functools
import requests
import json

import tornado.web
from tornado import gen
from tornado.escape import to_unicode

from orcidauth import OrcidOAuth2Mixin

from tornado.util import unicode_type, ArgReplacer, PY3
if PY3:
    import urllib.parse as urlparse
    import urllib.parse as urllib_parse
    long = int
else:
    import urlparse
    import urllib as urllib_parse

import urllib
import urllib2



class OrcidOAuth2App(tornado.web.Application):
    def __init__(self):
        settings = {
            'template_path': str(pathlib.Path(__file__).parent.resolve() / 'template'),
            'cookie_secret': 'secret',
            'xsrf_cookies': True,
            'debug': True,
            'orcid_oauth': {
                'client_id': 'APP-4KYTNK2K2QHQDANU',
                'client_secret': 'c16889a0-5dbe-4718-8bb8-d1fcdddc961f',
                'redirect_uri': 'http://localhost:8888/oauth2callback',
                'scope': ['/authenticate']
            }
        }

        handlers = [
            (r'/', MainHandler),
            (r'/oauth2callback', OrcidOAuth2LoginHandler),
        ]
        super(OrcidOAuth2App, self).__init__(handlers, **settings)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('index.html')


class OrcidOAuth2LoginHandler(tornado.web.RequestHandler, OrcidOAuth2Mixin):
    @gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            user = yield super(OrcidOAuth2LoginHandler, self).get_read_public_access(
                redirect_uri=self.settings['orcid_oauth']['redirect_uri'],
                code=self.get_argument('code'))
            # this is where we can read user information from Orcid
            # self.write(str(user))

            orcid="0000-0001-8319-9227"
            access_token=user.get('access_token')
            print(access_token)

            theurl = self._GET_USER_INFO + orcid + "/orcid-bio/"
            self.write(theurl + "<br/>")

            endpoint = theurl
            headers = {"Authorization": "Bearer " + access_token,
                       "Content-Type": "application/orcid+json"}

            # profile = requests.post(endpoint, headers=headers).json()
            # self.write("user profile : " + str(profile) + "<br/>")

            response = urllib2.urlopen(urllib2.Request(theurl, headers={
                'Content-Type': 'application/orcid+json',
                'Authorization': ' Bearer ' + access_token}))
            self.write(str(response.read()))

            if 1<0 and 'orcid' in user:
                orcid=user['orcid']
                access_token=user['access_token']
                self.write("user ORCID : " + orcid + "<br/>")
                self.write("user access_token : " + access_token + "<br/>")

                http = self.get_auth_http_client()
                body = urllib_parse.urlencode({
                    "access_token": access_token,
                })



                # self.write("tttoken : " + str(json_obj) + "<br/>")





                theurl=self._GET_USER_INFO + orcid+"/orcid-bio/"
                self.write(theurl + "<br/>")



                endpoint = theurl
                headers = {"Authorization": "Bearer " + access_token,
                           "Content-Type": "application/orcid+json"}

                profile=requests.post(endpoint,  headers=headers).json()
                # self.write("user profile : " + str(profile) + "<br/>")


                # self.write(str(response.info().getplist()))
            else:
                self.write("timeout, please login again")
                # self.redirect('/oauth2callback')
            return

        state = self._get_state()
        self.set_secure_cookie('openid_state', state)
        yield self.authorize_redirect(state)


    def get_authenticated_user(self):
        return super(OrcidOAuth2LoginHandler, self).get_authenticated_user(
            redirect_uri=self.settings['orcid_oauth']['redirect_uri'],
            code=self.get_argument('code'))

    def authorize_redirect(self, state):
        orcid_oauth = self.settings['orcid_oauth']
        return super(OrcidOAuth2LoginHandler, self).authorize_redirect(
            redirect_uri=orcid_oauth['redirect_uri'],
            client_id=orcid_oauth['client_id'],
            scope=orcid_oauth['scope'],
            response_type='code'
        )

    def _get_state(self):
        return to_unicode(binascii.hexlify(os.urandom(64)))


if __name__ == '__main__':
    # start web server on port 8888
    OrcidOAuth2App().listen(8888)
    tornado.ioloop.IOLoop.instance().start()