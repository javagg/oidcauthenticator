from jupyterhub.auth import LocalAuthenticator
from .oidc import OidcAuthenticator
import os
from traitlets import Unicode
from tornado import gen

class MeQuantaOidcAuthenticator(OidcAuthenticator):
    login_service = "MeQuanta"
    oidc_provider_url = 'http://identity2.mequanta.com'
    oidc_callback_url = 'https://localhost:8000/hub/oidc_callback'
    client_id_env = 'MEQUANTA_CLIENT_ID'
    client_secret_env = 'MEQUANTA_CLIENT_SECRET'
    fixed_user_env = 'MEQUANTA_FIXED_USER'
    fixed_user = Unicode(config=True)
    def _fixed_user_default(self):
        return os.getenv(self.fixed_user_env, None)

    @gen.coroutine
    def authenticate(self, handler):
        username = super(MeQuantaOidcAuthenticator, self).authenticate(handler)
        if username is not None and self.fixed_user is not None:
            username = self.fixed_user
        return username

class LocalMeQuantaOidcAuthenticator(LocalAuthenticator, MeQuantaOidcAuthenticator):
    pass
    
