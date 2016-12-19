import tornado.web
from user_manager import user_manager


class BaseHandler(tornado.web.RequestHandler):
    allow_nonactive = False

    def get_current_user(self):
        user_id = self.get_secure_cookie('user')
        if user_id is None:
            return
        user_id = user_id.decode()
        if self.allow_nonactive:
            return user_id
        user = user_manager.get_user(user_id)
        if not user or not user['active']:
            return
        return user_id

    def get_user(self):
        user_id = self.current_user
        if user_id:
            return user_manager.get_user(user_id)
