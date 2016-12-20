import os
import binascii

import tornado.web
from tornado.escape import to_unicode
from base_handler import BaseHandler
from user_manager import user_manager


class ApiKeysHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        user = self.get_user()
        api_keys = user.get('api_keys', [])
        self.render("api_keys.html", api_keys=api_keys)

    @tornado.web.authenticated
    def post(self):
        user_id = self.current_user
        user = self.get_user()
        api_keys = user.get('api_keys', [])
        new_key = self.generate_api_key()
        api_keys.append({"api_key": new_key, "active": True})
        user_manager.update_field(user_id, 'api_keys', api_keys)
        self.redirect("/api_keys")

    def generate_api_key(self):
        return to_unicode(binascii.hexlify(os.urandom(42)))


class ApiKeysActionHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self, api_key, action):
        user_id = self.current_user
        user = self.get_user()
        api_keys = user.get('api_keys', [])
        if action in ('activate', 'deactivate'):
            for key in api_keys:
                if key["api_key"] == api_key:
                    key['active'] = action == 'activate'
                    break
        elif action == 'delete':
            keys = [k['api_key'] for k in api_keys]
            try:
                index = keys.index(api_key)
            except ValueError:
                pass
            else:
                api_keys.pop(index)
        else:
            self.send_error(400, reason="Invalid action")
            return
        user_manager.update_field(user_id, 'api_keys', api_keys)
        self.redirect("/api_keys")
