from tornado import gen
from tornado.web import HTTPError
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join
from urllib.parse import urlencode
from oic.oic import Client
from oic.oauth2 import rndstr
from oic.oic.message import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from traitlets import Unicode
import os

class OidcLoginHandler(BaseHandler):
    def get(self):
        provider_url = self.authenticator.oidc_provider_url
        redirect_uri = self.authenticator.oidc_callback_url
        self.log.info('oidc redirect: %r', redirect_uri)
        response_type = ['code']
        oclient = self.authenticator.oclient
        issuer_url = oclient.wf.discovery_query(provider_url)
        #issuer_url = provider_url
        self.log.info('issuer_url: %r', issuer_url)
        provider_info = oclient.provider_config(issuer_url)

        response_types = ["code", "id_token", "token"]
        response_types = ["code"]

        behaviour = {
            "scope": ["openid", "profile"],
            "acr_values": ["password"]
        }

        args = {
            "redirect_uris": [redirect_uri],
            "response_types": response_types
        }
        registration_endpoint = provider_info.to_dict().get("registration_endpoint", None)
        if registration_endpoint is not None:
            registration_response = oclient.register(provider_info["registration_endpoint"], **args)
            print("registration_response: %s" % registration_response)
        else:
            oclient.client_id = self.authenticator.client_id
            oclient.client_secret = self.authenticator.client_secret

        state = rndstr()
        nonce = rndstr()
        self.set_cookie("oidc_state", state)
        self.set_cookie("oidc_nonce", nonce)
        request_args = {
            "response_type": "code",
            "state": state,
            "nonce": nonce,
            "redirect_uri": redirect_uri,
            "client_id": oclient.client_id
        }

        request_args.update(behaviour)
        auth_req = oclient.construct_AuthorizationRequest(request_args=request_args)
        login_url = auth_req.request(oclient.authorization_endpoint)
        print("login_url:{}".format(login_url))
        self.redirect(login_url)

class OidcCallbackHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        username = yield self.authenticator.authenticate(self)
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            raise HTTPError(403)
        
class OidcAuthenticator(Authenticator):

    def __init__(self, *args, **kwargs):
        super(OidcAuthenticator, self).__init__()
        self.oclient = Client(client_authn_method=CLIENT_AUTHN_METHOD)

    login_service = 'override in subclass'
    oidc_provider_url = 'override in subclass'
    oidc_callback_url = 'override in subclass'

    client_id_env = 'OIDC_CLIENT_ID'
    client_id = Unicode(config=True)
    def _client_id_default(self):
        return os.getenv(self.client_id_env, '')
    
    client_secret_env = 'OIDC_CLIENT_SECRET'
    client_secret = Unicode(config=True)
    def _client_secret_default(self):
        return os.getenv(self.client_secret_env, '')
        
    login_handler = OidcLoginHandler
    callback_handler = OidcCallbackHandler

    def login_url(self, base_url):
        return url_path_join(base_url, 'oidc_login')

    def get_handlers(self, app):
        return [(r'/oidc_login', self.login_handler), (r'/oidc_callback', self.callback_handler)]

    @gen.coroutine
    def authenticate(self, handler):
        error = handler.get_argument("error", None)
        if error:
            desc = handler.get_argument("error_description", "")
            raise HTTPError(500, log_message="{}: {}".format(error, desc))

        qry = {}
        for k in handler.request.query_arguments:
            qry[k] = handler.get_query_argument(k)

        info  = urlencode(qry)
        print("info:%s" % info)
        oclient = self.oclient
        auth_response = oclient.parse_response(AuthorizationResponse, info=info, sformat="urlencoded")

        session_state = handler.get_cookie("oidc_state")
        session_nonce = handler.get_cookie("oidc_nonce")
        if auth_response["state"] != session_state:
            raise HTTPError(401, log_message="The OIDC state does not match.")

        if "id_token" in auth_response and auth_response["id_token"]["nonce"] != session_nonce:
            raise HTTPError(401, log_message="The OIDC nonce does not match.")

        auth_code = auth_response["code"]
        print("auth_code:%s" % auth_code)

        args = {
            "code": auth_code,
            "redirect_uri": self.oidc_callback_url,
            "client_id": oclient.client_id,
            "client_secret": oclient.client_secret
        }

        token_response = oclient.do_access_token_request(scope="openid", state=session_state, request_args=args, authn_method="client_secret_post")

        print("token_response:%s" % token_response)
        id_token = token_response["id_token"]
        userinfo = oclient.do_user_info_request(state=session_state)

        print("userinfo:%s" % userinfo)

        username = userinfo["name"]
        if self.whitelist and username not in self.whitelist:
            username = None
        return username
