#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This is demo server for testing Orcid authentication based on Tornado Web Server
# run this command to start web server on port 8888 : python orcidloginserver.py
# Code built by AVEbrahimi (vakilzadeh@gmail.com)

from config import *
import sys, os
import binascii
import pathlib
import json
from email.message import EmailMessage

import tornado.web
from tornado import gen
from tornado.escape import to_unicode
from tornado_smtp.client import TornadoSMTP


from orcidauth import OrcidOAuth2Mixin

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/tests/Google")
from googleloginserver import GoogleOAuth2LoginHandler
from user_manager import user_manager
from base_handler import BaseHandler
from api_keys_handler import ApiKeysHandler, ApiKeysActionHandler


class OrcidOAuth2App(tornado.web.Application):
    def __init__(self):
        settings = {
            'template_path': str(pathlib.Path(__file__).parent.resolve() / 'template'),
            'cookie_secret': 'secret',
            'xsrf_cookies': True,
            'debug': True,
            'orcid_oauth': {
                'client_id': ORCID_CLIENT_ID,
                'client_secret': ORCID_CLIENT_SECRET,
                'redirect_uri': 'http://localhost:8888/oauth2callback',
                'scope': ['/authenticate']
            },
            'google_oauth': {
                'key': GOOGLE_KEY,
                'secret': GOOGLE_SECRET,
                'redirect_uri': 'http://localhost:8888/oauth2callbackgoogle',
                'scope': ['openid', 'email', 'profile']
            },
            'login_url': '/',
            'server_address': 'http://localhost:8888'
        }

        handlers = [
            (r'/', MainHandler),
            (r'/oauth2callback', OrcidOAuth2LoginHandler),
            (r'/oauth2callbackgoogle', GoogleOAuth2LoginHandler),
            (r'/api_keys', ApiKeysHandler),
            (r'/api_keys/(\w+)/(\w+)', ApiKeysActionHandler),
            (r'/enteremail', EnterEmailHandler),
            (r'/emailsent', EmailSentHandler),
            (r'/verify', VerifyEmailHandler),
            (r'/logout', AuthLogoutHandler),
        ]
        super(OrcidOAuth2App, self).__init__(handlers, **settings)



class MainHandler(BaseHandler):
    def get(self):
        user_id = self.current_user
        if not user_id:
            self.render('index.html')
        else:
            user = self.get_user()
            profile = user['profile']
            name = '{} {}'.format(
                profile['orcid-bio']['personal-details'].get('given-names'),
                profile['orcid-bio']['personal-details'].get('family-name'),
            )
            t_dict = {
                'name': name,
                'orcid': user_id,
                'details': profile
            }
            self.render('loggedin.html', **t_dict)


class AuthLogoutHandler(BaseHandler):
    allow_nonactive = True

    @tornado.web.authenticated
    def get(self):
        self.clear_cookie("user")
        self.redirect("/")


class VerifyEmailHandler(tornado.web.RequestHandler):
    def get(self, *args, **kwargs):
        token = self.get_argument('token')
        result = user_manager.get_user_by_token(token)
        if result is None:
            self.send_error(404)
        else:
            user_id, user = result
            user_manager.set_user_active(user_id)
            self.set_secure_cookie('user', user_id)  # log in if user is not logged in
            self.redirect('/')


class EmailSentHandler(BaseHandler):
    allow_nonactive = True

    def get(self, *args, **kwargs):
        self.render("email_sent.html")


class EnterEmailHandler(BaseHandler):
    allow_nonactive = True

    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        self.render("enter_email.html")

    @gen.coroutine
    @tornado.web.authenticated
    def post(self, *args, **kwargs):
        self.check_xsrf_cookie()
        email = self.get_argument('email')
        user_id = self.current_user
        user_manager.set_user_email(user_id, email)
        token = self.get_verify_token()
        yield send_email(
            email,
            "Please verify your email",
            '<a href="{}">Click</a> to verify your email'.format(
                "{}/verify?token={}".format(self.settings['server_address'], token)
            )
        )
        user_manager.set_user_verify_token(user_id, token)
        self.redirect('emailsent')

    def get_verify_token(self):
        return to_unicode(binascii.hexlify(os.urandom(64)))


@gen.coroutine
def send_email(to_email, subject, html_body):
    smtp = TornadoSMTP(SMTP_SERVER, SMTP_PORT)
    if SMTP_USERNAME and SMTP_PASSWORD:
        yield smtp.login(SMTP_USERNAME, SMTP_PASSWORD)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['To'] = to_email
    msg['From'] = FROM_EMAIL
    msg.add_header('Content-Type', 'text/html')
    msg.set_payload(html_body)

    yield smtp.send_message(msg)


class OrcidOAuth2LoginHandler(tornado.web.RequestHandler, OrcidOAuth2Mixin):
    def _get_flattened_profile_doc(self, doc):
        result = {}
        for key, value in doc.items():
            if isinstance(value, dict):
                if 'value' in value:
                    value = value['value']
                else:
                    value = self._get_flattened_profile_doc(value)
            result[key] = value
        return result

    def get_profile(self, bio_response):
        profile = bio_response["orcid-profile"]
        return self._get_flattened_profile_doc(profile)

    def get_profile_email(self, profile):
        bio = profile.get('orcid-bio')
        if bio:
            contact = bio.get('contact-details')
            if contact:
                email = contact.get('email')
                if email:
                    return email[0].get("value")

    @gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            user0 = yield super(OrcidOAuth2LoginHandler, self).get_authenticated_user(
                redirect_uri=self.settings['orcid_oauth']['redirect_uri'],
                code=self.get_argument('code'))
            # auth code is expired
            if 'errorDesc' in user0:
                state = self._get_state()
                self.set_secure_cookie('openid_state', state)
                yield self.authorize_redirect(state)
                return

            orcid = user0['orcid']

            user1 = yield super(OrcidOAuth2LoginHandler, self).get_read_public_access(
                redirect_uri=self.settings['orcid_oauth']['redirect_uri'])

            access_token = user1['access_token']
            self.set_secure_cookie("orcid_access_token", access_token)
            bio = yield super(OrcidOAuth2LoginHandler, self).get_user_bio(
                orcid_id=orcid,
                access_token=access_token)
            # this is where we can read user information from Orcid
            # self.write(str(user))
            profile = json.loads(bio.decode('utf-8'))
            print(profile)
            profile = self.get_profile(profile)
            email = self.get_profile_email(profile)
            user = user_manager.get_user(orcid)
            active = True
            if user is None:
                active = bool(email)
                user_manager.store_user(orcid, email, active=active, profile=profile)
            self.set_secure_cookie('user', orcid)
            if not active:
                self.redirect('enteremail')
            else:
                self.redirect('/')

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