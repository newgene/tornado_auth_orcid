#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
import binascii
import pathlib

import tornado.web
from tornado import gen
from tornado.auth import GoogleOAuth2Mixin
from tornado.escape import to_unicode

import verifyjwt  # https://github.com/yukirin/Tornado-Google-Login/blob/master/verifyjwt.py


class GoogleOAuth2App(tornado.web.Application):
    def __init__(self):
        settings = {
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
            (r'/oauth2callback', GoogleOAuth2LoginHandler),
        ]
        super(GoogleOAuth2App,self).__init__(handlers, **settings)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('index.html')


class GoogleOAuth2LoginHandler(tornado.web.RequestHandler, GoogleOAuth2Mixin):
    @gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            # state = to_unicode(self.get_secure_cookie('openid_state'))
            # if not state == self.get_argument('state', False):
            #     raise tornado.web.HTTPError(400, "Invalid state")

            user = yield self.get_authenticated_user()
            valid = 1

            if not valid: raise tornado.web.HTTPError(400, "Invalid ID Token")

            self.set_secure_cookie("google_access_token", user['access_token'])
            t_dict = {'google_access_token': user['access_token']}
            self.render('loggedin_google.html', **t_dict)

            return

        state = self._get_state()
        self.set_secure_cookie('openid_state', state)
        yield self.authorize_redirect(state)

    def get_authenticated_user(self):
        return super(GoogleOAuth2LoginHandler,self).get_authenticated_user(
            redirect_uri=self.settings['google_oauth']['redirect_uri'],
            code=self.get_argument('code'))

    def authorize_redirect(self, state):
        google_oauth = self.settings['google_oauth']
        return super(GoogleOAuth2LoginHandler,self).authorize_redirect(
            redirect_uri=google_oauth['redirect_uri'],
            client_id=google_oauth['key'],
            scope=google_oauth['scope'],
            response_type='code',
            extra_params={'state': state}
        )

    def _get_state(self):
        return to_unicode(binascii.hexlify(os.urandom(64)))


if __name__ == '__main__':
    GoogleOAuth2App().listen(8888)
    tornado.ioloop.IOLoop.instance().start()