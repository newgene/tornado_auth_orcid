#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This is demo server for testing Orcid authentication based on Tornado Web Server
# run this command to start web server on port 8888 : python orcidloginserver.py
# Code built by AVEbrahimi (vakilzadeh@gmail.com)

import sys, os
import binascii
import pathlib
import functools
import requests
import json
from xml.etree.ElementTree import fromstring, ElementTree

import tornado.web
from tornado import gen
from tornado.escape import to_unicode
from tornado import template

from orcidauth import OrcidOAuth2Mixin

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/tests/Google")
from googleloginserver import GoogleOAuth2LoginHandler
import verifyjwt

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
        settings_google = {
            'template_path': str(pathlib.Path(__file__).parent.resolve() / 'template'),
            'cookie_secret': 'secret',
            'xsrf_cookies': True,
            'debug': True,
            'google_oauth': {
                'key': '925655400245-23vg1ci6i86p1tmi54q6rfvfg6bqsi9b.apps.googleusercontent.com',
                'secret': '2jTuyp4ORQKwasBZumAJiMyj',
                'redirect_uri': 'http://localhost:8888/oauth2callback',
                'scope': ['openid', 'email', 'profile']
            }
        }

        handlers = [
            (r'/', MainHandler),
            (r'/oauth2callback', OrcidOAuth2LoginHandler),
            (r'/oauth2callbackgoogle', GoogleOAuth2LoginHandler),
        ]
        super(OrcidOAuth2App, self).__init__(handlers, **settings)



class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('index.html')


class OrcidOAuth2LoginHandler(tornado.web.RequestHandler, OrcidOAuth2Mixin):
    @gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            print("####")
            print self.get_argument('code')
            user0 = yield super(OrcidOAuth2LoginHandler, self).get_authenticated_user(
                redirect_uri=self.settings['orcid_oauth']['redirect_uri'],
                code=self.get_argument('code'))
            # auth code is expired
            if 'errorDesc' in user0:
                state = self._get_state()
                self.set_secure_cookie('openid_state', state)
                yield self.authorize_redirect(state)
                return
            print("##@@" + str(user0))
            orcid=user0['orcid']



            user1 = yield super(OrcidOAuth2LoginHandler, self).get_read_public_access(
                redirect_uri=self.settings['orcid_oauth']['redirect_uri'],
                code=self.get_argument('code'))
            print user1

            access_token_string=str(user1['access_token'])
            print "@@@ user access token is : " + access_token_string
            user = yield super(OrcidOAuth2LoginHandler, self).get_user_bio(
                orcid_id=orcid,
                access_token=access_token_string)
            # this is where we can read user information from Orcid
            # self.write(str(user))
            print("##$$" + str(user1))
            print(user)

            access_token=user.get('access_token')
            # print(access_token)

            theurl = self._GET_USER_INFO + orcid + "/orcid-bio/"
            # self.write(theurl + "<br/>")

            # print(theurl)


            headers = {'Content-Type': 'application/orcid+json', 'Authorization': 'Bearer ' + access_token}
            req = urllib2.Request(theurl, None, headers)
            response = urllib2.urlopen(req)
            print response.read()


            # print("REPORT5:")
            # tree = ElementTree(fromstring(response.read()))
            # for node in tree.findall('.//path'):
            #     print node.tag
            # print("EREPORT5:")

            t_dict = {'username': 'jack'}
            t_dict['orcid'] = orcid
            self.render('loggedin.html', **t_dict)



            # if 1<0 and 'orcid' in user:
            #     orcid=user['orcid']
            #     access_token=user['access_token']
            #     self.write("user ORCID : " + orcid + "<br/>")
            #     self.write("user access_token : " + access_token + "<br/>")
            #
            #     http = self.get_auth_http_client()
            #     body = urllib_parse.urlencode({
            #         "access_token": access_token,
            #     })
            #
            #
            #
            #     # self.write("tttoken : " + str(json_obj) + "<br/>")
            #
            #
            #
            #
            #
            #     theurl=self._GET_USER_INFO + orcid+"/orcid-bio/"
            #     self.write(theurl + "<br/>")
            #
            #
            #
            #     endpoint = theurl
            #     headers = {"Authorization": "Bearer " + access_token,
            #                "Content-Type": "application/orcid+json"}
            #
            #     profile=requests.post(endpoint,  headers=headers).json()
            #     # self.write("user profile : " + str(profile) + "<br/>")
            #
            #
            #     # self.write(str(response.info().getplist()))
            # else:
            print("timeout, please login again")
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