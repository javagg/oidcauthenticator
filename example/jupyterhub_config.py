# Configuration file for jupyterhub.

#------------------------------------------------------------------------------
# Configurable configuration
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# SingletonConfigurable configuration
#------------------------------------------------------------------------------

# A configurable that only allows one instance.
# 
# This class is for classes that should only have one instance of itself or
# *any* subclass. To create and retrieve such a class use the
# :meth:`SingletonConfigurable.instance` method.

#------------------------------------------------------------------------------
# Application configuration
#------------------------------------------------------------------------------

# This is an application.

# Set the log level by value or name.
# c.Application.log_level = 30

# The date format used by logging formatters for %(asctime)s
# c.Application.log_datefmt = '%Y-%m-%d %H:%M:%S'

# The Logging format template
# c.Application.log_format = '[%(name)s]%(highlevel)s %(message)s'

#------------------------------------------------------------------------------
# JupyterHub configuration
#------------------------------------------------------------------------------

# An Application for starting a Multi-User Jupyter Notebook server.

# log all database transactions. This has A LOT of output
# c.JupyterHub.debug_db = False

# The base URL of the entire application
# c.JupyterHub.base_url = '/'

# The Proxy Auth token.
# 
# Loaded from the CONFIGPROXY_AUTH_TOKEN env variable by default.
# c.JupyterHub.proxy_auth_token = ''

# Number of days for a login cookie to be valid. Default is two weeks.
# c.JupyterHub.cookie_max_age_days = 14

# The class to use for spawning single-user servers.
# 
# Should be a subclass of Spawner.
# c.JupyterHub.spawner_class = <class 'jupyterhub.spawner.LocalProcessSpawner'>

# Generate default config file
# c.JupyterHub.generate_config = False

# The port for the proxy API handlers
# c.JupyterHub.proxy_api_port = 0

# The config file to load
# c.JupyterHub.config_file = 'jupyterhub_config.py'

# Set a logging.FileHandler on this file.
# c.JupyterHub.extra_log_file = ''

# Class for authenticating users.
# 
# This should be a class with the following form:
# 
# - constructor takes one kwarg: `config`, the IPython config object.
# 
# - is a tornado.gen.coroutine
# - returns username on success, None on failure
# - takes two arguments: (handler, data),
#   where `handler` is the calling web.RequestHandler,
#   and `data` is the POST form data from the login page.
# c.JupyterHub.authenticator_class = <class 'jupyterhub.auth.PAMAuthenticator'>

# Interval (in seconds) at which to check if the proxy is running.
# c.JupyterHub.proxy_check_interval = 30

# Paths to search for jinja templates.
# c.JupyterHub.template_paths = traitlets.Undefined

# Path to SSL certificate file for the public facing interface of the proxy
# 
# Use with ssl_key
# c.JupyterHub.ssl_cert = ''

# Whether to shutdown single-user servers when the Hub shuts down.
# 
# Disable if you want to be able to teardown the Hub while leaving the single-
# user servers running.
# 
# If both this and cleanup_proxy are False, sending SIGINT to the Hub will only
# shutdown the Hub, leaving everything else running.
# 
# The Hub should be able to resume from database state.
# c.JupyterHub.cleanup_servers = True

# DEPRECATED, use Authenticator.admin_users instead.
# c.JupyterHub.admin_users = traitlets.Undefined

# The location of jupyterhub data files (e.g. /usr/local/share/jupyter/hub)
# c.JupyterHub.data_files_path = '/usr/share/jupyter/hub'

# Path to SSL key file for the public facing interface of the proxy
# 
# Use with ssl_cert
# c.JupyterHub.ssl_key = ''

# The public facing port of the proxy
# c.JupyterHub.port = 8000

# The ip for this process
# c.JupyterHub.hub_ip = 'localhost'

# The ip for the proxy API handlers
# c.JupyterHub.proxy_api_ip = 'localhost'

# File to write PID Useful for daemonizing jupyterhub.
# c.JupyterHub.pid_file = ''

# show debug output in configurable-http-proxy
# c.JupyterHub.debug_proxy = False

# Answer yes to any questions (e.g. confirm overwrite)
# c.JupyterHub.answer_yes = False

# Supply extra arguments that will be passed to Jinja environment.
# c.JupyterHub.jinja_environment_options = traitlets.Undefined

# 
# c.JupyterHub.tornado_settings = traitlets.Undefined

# Include any kwargs to pass to the database connection. See
# sqlalchemy.create_engine for details.
# c.JupyterHub.db_kwargs = traitlets.Undefined

# The command to start the http proxy.
# 
# Only override if configurable-http-proxy is not on your PATH
# c.JupyterHub.proxy_cmd = traitlets.Undefined

# Extra log handlers to set on JupyterHub logger
# c.JupyterHub.extra_log_handlers = traitlets.Undefined

# Whether to shutdown the proxy when the Hub shuts down.
# 
# Disable if you want to be able to teardown the Hub while leaving the proxy
# running.
# 
# Only valid if the proxy was starting by the Hub process.
# 
# If both this and cleanup_servers are False, sending SIGINT to the Hub will
# only shutdown the Hub, leaving everything else running.
# 
# The Hub should be able to resume from database state.
# c.JupyterHub.cleanup_proxy = True

# The prefix for the hub server. Must not be '/'
# c.JupyterHub.hub_prefix = '/hub/'

# The public facing ip of the proxy
# c.JupyterHub.ip = ''

# Grant admin users permission to access single-user servers.
# 
# Users should be properly informed if this is enabled.
# c.JupyterHub.admin_access = False

# The cookie secret to use to encrypt cookies.
# 
# Loaded from the JPY_COOKIE_SECRET env variable by default.
# c.JupyterHub.cookie_secret = b''

# Purge and reset the database.
# c.JupyterHub.reset_db = False

# File in which to store the cookie secret.
# c.JupyterHub.cookie_secret_file = 'jupyterhub_cookie_secret'

# The port for this process
# c.JupyterHub.hub_port = 8081

# url for the database. e.g. `sqlite:///jupyterhub.sqlite`
# c.JupyterHub.db_url = 'sqlite:///jupyterhub.sqlite'

# Interval (in seconds) at which to update last-activity timestamps.
# c.JupyterHub.last_activity_interval = 300

#------------------------------------------------------------------------------
# LoggingConfigurable configuration
#------------------------------------------------------------------------------

# A parent class for Configurables that log.
# 
# Subclasses have a log trait, and the default behavior is to get the logger
# from the currently running Application.

#------------------------------------------------------------------------------
# Spawner configuration
#------------------------------------------------------------------------------

# Base class for spawning single-user notebook servers.
# 
# Subclass this, and override the following methods:
# 
# - load_state - get_state - start - stop - poll

# The notebook directory for the single-user server
# 
# `~` will be expanded to the user's home directory
# c.Spawner.notebook_dir = ''

# Extra arguments to be passed to the single-user server
# c.Spawner.args = traitlets.Undefined

# Interval (in seconds) on which to poll the spawner.
# c.Spawner.poll_interval = 30

# Enable debug-logging of the single-user server
# c.Spawner.debug = False

# Timeout (in seconds) before giving up on a spawned HTTP server
# 
# Once a server has successfully been spawned, this is the amount of time we
# wait before assuming that the server is unable to accept connections.
# c.Spawner.http_timeout = 30

# Timeout (in seconds) before giving up on the spawner.
# 
# This is the timeout for start to return, not the timeout for the server to
# respond. Callers of spawner.start will assume that startup has failed if it
# takes longer than this. start should return when the server process is started
# and its location is known.
# c.Spawner.start_timeout = 60

# Whitelist of environment variables for the subprocess to inherit
# c.Spawner.env_keep = traitlets.Undefined

# The command used for starting notebooks.
# c.Spawner.cmd = traitlets.Undefined

# The IP address (or hostname) the single-user server should listen on
# c.Spawner.ip = 'localhost'

#------------------------------------------------------------------------------
# LocalProcessSpawner configuration
#------------------------------------------------------------------------------

# A Spawner that just uses Popen to start local processes.

# Seconds to wait for process to halt after SIGKILL before giving up
# c.LocalProcessSpawner.KILL_TIMEOUT = 5

# Seconds to wait for process to halt after SIGTERM before proceeding to SIGKILL
# c.LocalProcessSpawner.TERM_TIMEOUT = 5

# Seconds to wait for process to halt after SIGINT before proceeding to SIGTERM
# c.LocalProcessSpawner.INTERRUPT_TIMEOUT = 10

#------------------------------------------------------------------------------
# Authenticator configuration
#------------------------------------------------------------------------------

# A class for authentication.
# 
# The API is one method, `authenticate`, a tornado gen.coroutine.

# Username whitelist.
# 
# Use this to restrict which users can login. If empty, allow any user to
# attempt login.
# c.Authenticator.whitelist = traitlets.Undefined

# set of usernames of admin users
# 
# If unspecified, only the user that launches the server will be admin.
# c.Authenticator.admin_users = traitlets.Undefined

#------------------------------------------------------------------------------
# LocalAuthenticator configuration
#------------------------------------------------------------------------------

# Base class for Authenticators that work with local *ix users
# 
# Checks for local users, and can attempt to create them if they exist.

# If a user is added that doesn't exist on the system, should I try to create
# the system user?
# c.LocalAuthenticator.create_system_users = False

# Automatically whitelist anyone in this group.
# c.LocalAuthenticator.group_whitelist = traitlets.Undefined

#------------------------------------------------------------------------------
# PAMAuthenticator configuration
#------------------------------------------------------------------------------

# Authenticate local *ix users with PAM

# The encoding to use for PAM
# c.PAMAuthenticator.encoding = 'utf8'

# The PAM service to use for authentication.
# c.PAMAuthenticator.service = 'login'

# Configuration file for Jupyter Hub

c = get_config()

c.JupyterHub.log_level = 10
c.JupyterHub.authenticator_class = 'oidcauthenticator.LocalMeQuantaOidcAuthenticator'
c.LocalMeQuantaOidcAuthenticator.create_system_users = True
c.Authenticator.whitelist = whitelist = set()
c.JupyterHub.admin_users = admin = set()

import os
import sys

join = os.path.join

here = os.path.dirname(__file__)
root = os.environ.get('OIDCAUTHENTICATOR_DIR', here)
sys.path.insert(0, root)

with open(join(root, 'userlist')) as f:
    for line in f:
        if not line:
            continue
        parts = line.split()
        name = parts[0]
        whitelist.add(name)
        if len(parts) > 1 and parts[1] == 'admin':
            admin.add(name)

# ssl config
ssl = join(root, 'ssl')
keyfile = join(ssl, 'localhost.key')
certfile = join(ssl, 'localhost.crt')
if os.path.exists(keyfile):
    c.JupyterHub.ssl_key = keyfile
if os.path.exists(certfile):
    c.JupyterHub.ssl_cert = certfile
    
