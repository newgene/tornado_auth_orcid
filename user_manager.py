from elasticsearch import Elasticsearch
from elasticsearch import exceptions

from config import ELASTICSEARCH_HOST, ELASTICSEARCH_PORT


class UserManager(object):
    index = 'users'
    doc_type = 'user'

    def __init__(self, elasticsearch):
        self.elasticsearch = elasticsearch
        # TODO need to create index before making query

    def get_user(self, user_id):
        try:
            result = self.elasticsearch.get_source(self.index, self.doc_type, user_id)
        except exceptions.NotFoundError:
            return None
        return result

    def store_user(self, user_id, email, active, profile):
        doc = dict(email=email, active=active, profile=profile)
        self.elasticsearch.create(self.index, self.doc_type, doc, id=user_id)

    def update_field(self, user_id, field, value):
        update_body = {"doc": {field: value}}
        self.elasticsearch.update(self.index, self.doc_type, user_id, body=update_body)

    def set_user_email(self, user_id, email):
        self.update_field(user_id, 'email', email)

    def set_user_verify_token(self, user_id, token):
        self.update_field(user_id, 'verify_token', token)

    def set_user_active(self, user_id, active=True):
        self.update_field(user_id, 'active', active)

    def get_user_by_token(self, token):
        try:
            result = self.elasticsearch.search(
                self.index, self.doc_type,
                q='verify_token:{}'.format(token)
            )
        except exceptions.NotFoundError:
            return None
        else:
            hits = result['hits']['hits']
            if hits:
                hit = hits[0]
                return hit['_id'], hit['_source']

user_manager = UserManager(Elasticsearch([{"host": ELASTICSEARCH_HOST, "port": ELASTICSEARCH_PORT}]))
