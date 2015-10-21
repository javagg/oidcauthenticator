from jupyterhub.auth import LocalAuthenticator
from .oidc import OidcAuthenticator

class MeQuantaOidcAuthenticator(OidcAuthenticator):
    login_service = "MeQuanta"
    oidc_provider_url = 'http://identity2.mequanta.com'
    oidc_callback_url = 'https://localhost:8000/hub/oidc_callback'
    client_id_env = 'MEQUANTA_CLIENT_ID'
    client_secret_env = 'MEQUANTA_CLIENT_SECRET'

class LocalMeQuantaOidcAuthenticator(LocalAuthenticator, MeQuantaOidcAuthenticator):
    pass
    
