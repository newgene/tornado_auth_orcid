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

from elasticsearch import Elasticsearch
from elasticsearch import exceptions

import tornado.web
from tornado import gen
from tornado.escape import to_unicode

from orcidauth import OrcidOAuth2Mixin

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/tests/Google")
from googleloginserver import GoogleOAuth2LoginHandler


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
            'login_url': '/'
        }

        handlers = [
            (r'/', MainHandler),
            (r'/oauth2callback', OrcidOAuth2LoginHandler),
            (r'/oauth2callbackgoogle', GoogleOAuth2LoginHandler),
            (r'/enteremail', EnterEmailHandler),
            (r'/emailsent', EmailSentHandler),
            (r'/logout', AuthLogoutHandler),
        ]
        super(OrcidOAuth2App, self).__init__(handlers, **settings)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('index.html')


class BaseHandler(tornado.web.RequestHandler):
    allow_nonactive = False

    def get_current_user(self):
        user_id = self.get_secure_cookie('user')
        if user_id:
            user_id = user_id.decode()
        if self.allow_nonactive:
            return user_id
        user = user_manager.get_user(user_id)
        if not user or not user['active']:
            return
        return user_id


class AuthLogoutHandler(BaseHandler):
    allow_nonactive = True

    @tornado.web.authenticated
    def get(self):
        self.clear_cookie("user")
        self.redirect("/")


class LoggedInHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        # render loggedin with user data
        pass


class VerifyEmailHandler(BaseHandler):
    pass


class EmailSentHandler(BaseHandler):
    allow_nonactive = True

    def get(self, *args, **kwargs):
        self.render("email_sent.html")


class EnterEmailHandler(BaseHandler):
    allow_nonactive = True

    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        self.render("enter_email.html")

    @tornado.web.authenticated
    def post(self, *args, **kwargs):
        self.check_xsrf_cookie()
        email = self.get_argument('email')
        user_id = self.current_user
        user_manager.set_user_email(user_id, email)
        token = self.get_verify_token()
        # TODO send email here
        user_manager.set_user_verify_token(user_id, token)
        self.redirect('emailsent')

    def get_verify_token(self):
        return to_unicode(binascii.hexlify(os.urandom(64)))


class UserManager(object):
    index = 'users'

    def __init__(self, elasticsearch):
        self.elasticsearch = elasticsearch
        # TODO need to create index before making query

    def get_user(self, user_id):
        try:
            result = self.elasticsearch.get(self.index, user_id, realtime=False)
        except exceptions.NotFoundError:
            return None
        return result["_source"]

    def store_user(self, user_id, email, active, profile):
        doc = dict(email=email, active=active, profile=profile)
        self.elasticsearch.create(self.index, 'user', doc, id=user_id)

    def update_field(self, user_id, field, value):
        update_body = {"doc": {field: value}}
        self.elasticsearch.update(self.index, 'user', user_id, body=update_body)

    def set_user_email(self, user_id, email):
        self.update_field(user_id, 'email', email)

    def set_user_verify_token(self, user_id, token):
        self.update_field(user_id, 'verify_token', token)

    def get_user_by_token(self, token):
        pass

user_manager = UserManager(Elasticsearch())


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
                # TODO redirect to loggedin
                return
            # t_dict = {'username': 'jack'}
            # t_dict['orcid'] = orcid
            # t_dict['details'] = profile
            # self.render('loggedin.html', **t_dict)
            # self.redirect('enteremail')
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