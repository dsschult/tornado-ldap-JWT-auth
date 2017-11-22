"""
An example `Tornado <http://tornado.readthedocs.io>`_ server
with LDAP as the authorization backend, and
`JWT <https://jwt.io/>`_ for tokens.
"""

from functools import wraps

import tornado.ioloop
import tornado.web
from tornado.httpclient import HTTPError

import jwt
import ldap3

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, secret, ldap_uri, ldap_base):
        self.secret = secret
        self.ldap_uri = ldap_uri
        self.ldap_base = ldap_base

def auth_rpc(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            raise HTTPError(403)
        return func(self, *args,**kwargs)
    return wrapper

class RPCHandler(BaseHandler):
    """For non-human requests, use an Authorization header"""
    def check_xsrf_cookie(self):
        pass # disable the check

    def get_current_user(self):
        try:
            token = self.request.headers['Authorization']
            data = jwt.decode(token, self.secret, algorithm='HS256')
            return data['user']
        except Exception:
            pass
        return None

    @auth_rpc
    def get(self):
        self.write({'foo':'bar'})

class LoginHandler(BaseHandler):
    """Login page for humans"""
    def get(self):
        self.write('<html><body><form action="/login" method="post">'
                   'Username: <input type="text" name="name"><br>'
                   'Password: <input type="password" name="password"><br>'
                   '<input type="submit" value="Sign in">'
                   +self.xsrf_form_html()+
                   '</form></body></html>')

    def post(self):
        username = self.get_argument("name")
        password = self.get_argument("password")
        try:
            # will fail if invalid
            conn = ldap3.Connection(self.ldap_uri, 'uid={},{}'.format(username, self.ldap_base),
                                    password, auto_bind=True)
        except Exception:
            self.write('<html><body><p style="color:red">Username or password invalid!</p>'
                       '<form action="/login" method="post">'
                       'Username: <input type="text" name="name"><br>'
                       'Password: <input type="password" name="password"><br>'
                       '<input type="submit" value="Sign in">'
                       +self.xsrf_form_html()+
                       '</form></body></html>')

        else:
            # successful login
            token = jwt.encode({'user':username}, self.secret, algorithm='HS256')
            self.set_secure_cookie('token', token)
            self.redirect("/")

class MainHandler(BaseHandler):
    """For human requests, use secure cookies"""
    def get_current_user(self):
        try:
            token = self.get_secure_cookie('token')
            data = jwt.decode(token, self.secret, algorithm='HS256')
            return data['user']
        except Exception:
            pass
        return None

    @tornado.web.authenticated
    def get(self):
        self.write("Hello world")
        self.write("<br>token:"+self.get_secure_cookie('token'))

def main():
    app_settings = {
        'login_url': '/login',
        'xsrf_cookies': True,
        'cookie_secret': 'supersecret',
    }
    handler_settings = {
        'secret': 'secret',
        'ldap_uri': 'ldaps://ldap-1.icecube.wisc.edu',
        'ldap_base': 'ou=People,dc=icecube,dc=wisc,dc=edu',
    }
    app = tornado.web.Application([
        (r'/rpc', RPCHandler, handler_settings),
        (r'/login', LoginHandler, handler_settings),
        (r'/', MainHandler, handler_settings),
    ], **app_settings)
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()

if __name__ == '__main__':
    main()


