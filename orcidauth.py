# This is OrcidOAuth2Mixin class which is used to authenticate on Orcid using OAuth2 method
# Code built by AVEbrahimi (vakilzadeh@gmail.com)

import functools


from tornado.auth import OAuth2Mixin
from tornado.auth import _auth_return_future
from tornado.util import unicode_type, ArgReplacer, PY3
from tornado import escape



if PY3:
    import urllib.parse as urlparse
    import urllib.parse as urllib_parse
    long = int
else:
    import urlparse
    import urllib as urllib_parse


class AuthError(Exception):
    pass

class OrcidOAuth2Mixin(OAuth2Mixin):

    _OAUTH_AUTHORIZE_URL = "https://orcid.org/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://orcid.org/oauth/token"
    _GET_USER_INFO = "https://pub.orcid.org/v1.2/"

    # _OAUTH_AUTHORIZE_URL = "https://sandbox.orcid.org/oauth/authorize"
    # _OAUTH_ACCESS_TOKEN_URL = "https://sandbox.orcid.org/oauth/token"
    # _GET_USER_INFO = "https://pub.sandbox.orcid.org/v1.2/"

    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'orcid_oauth'

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, code, callback):
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['client_id'],
            "response_type": "code",
            "scope": '/authenticate',
            "redirect_uri": redirect_uri
        })

        print(body)
        http.fetch(self._OAUTH_AUTHORIZE_URL,
                   functools.partial(self._on_access_token, callback),
                   method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)

    @_auth_return_future
    def get_read_public_access(self, redirect_uri, code, callback):
        print("entering get_read_public_access")
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['client_id'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['client_secret'],
            "grant_type": "client_credentials",
            # "code": code,
            "scope": '/read-public'
            # "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
        })
        # self.write(body)

        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token, callback),
                   method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)

    def _on_access_token(self, future, response):
        # theurl = self._GET_USER_INFO + orcid + "/orcid-bio/"
        # self.write(theurl + "<br/>")
        # response = urllib2.urlopen(urllib2.Request(theurl, headers={
        #     'Content-Type':'application/orcid+json',
        #     'Authorization': ' Bearer ' + access_token}))
        print ("entering _on_access_token")
        """Callback function for the exchange to the access token."""
        if response.error:
            future.set_exception(AuthError('Orcid auth error: %s' % str(response)))
            return
        print(response.body)
        print ("exiting _on_access_token")
        # self.write('<br/>')
        args = escape.json_decode(response.body)
        # access_token=str(args.get('access_token'))
        # self.write(access_token)

        # self.write('<br/>')
        future.set_result(args)

