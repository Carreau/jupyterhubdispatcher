"""
A module containing a ProxyAuthenticator a

"""

import os
import atexit
import signal
import logging
import binascii
import threading

from datetime import datetime
from textwrap import dedent
from urllib.parse import urlparse

import jupyterhub

from jupyterhub.spawner import Spawner
from jupyterhub.utils import url_path_join
from jupyterhub.auth import Authenticator
from jupyterhub.auth import PAMAuthenticator

from tornado.web import gen
from tornado.ioloop import IOLoop
from tornado.log import app_log, access_log, gen_log
from tornado.httpclient import AsyncHTTPClient
from tornado import web
import tornado

from traitlets import Type, default, observe, Integer, Bytes, Instance, Bool, Any, Float
from traitlets import Dict, Unicode, List
from traitlets.config import Application, catch_config_error


from jupyterhub.traitlets import URLPrefix
from jupyterhub.user import UserDict
from jupyterhub.log import CoroutineLogFormatter, log_request
from jupyterhub.handlers.static import CacheControlStaticFilesHandler, LogoHandler
from jupyterhub.emptyclass import EmptyClass
from jupyterhub import handlers


from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import scoped_session

from jupyterhub import orm

from jinja2 import Environment, FileSystemLoader

from jupyterhub.objects import Hub





__version__ = "0.1.0"

from jupyterhub.app import HEX_RE, make_provider, COOKIE_SECRET_BYTES, DATA_FILES_PATH


class Whatever:

    def __init__(self, **kwargs):
        for k,v in kwargs.items():
            setattr(self, k, v)

def decorate_hub_redirect(HandlerClass):

    class DispatcherHandler(HandlerClass):
        """
        Dynamic subclassing of a request handler that extend set_login_cookie to
        inject more informations In particular set a cookie value telling the CHP
        to which hub to redirect given user.

        """

        def set_login_cookie(self, user):
            ret = super().set_login_cookie(user)
            self.set_secure_cookie('user-matthias', 'value-hub-56')
            self._set_user_cookie(
                Whatever(name='thias', cookie_id='dat-cook-id-hub-28'), 
                Whatever(cookie_name='hub-28', base_url='baseurl')
            )
            return ret

    return DispatcherHandler





class NoOpSpawner(Spawner):

    def __init__(self, *args, **kwargs):
        self.running = False

    @gen.coroutine
    def start(self):
        """Start the single-user server

        Returns:
          (str, int): the (ip, port) where the Hub can connect to the server.

        .. versionchanged:: 0.7
            Return ip, port instead of setting on self.user.server directly.
        """
        self.running = True
        return None, None

    @gen.coroutine
    def stop(self, now=False):
        """Stop the single-user server

        If `now` is False (default), shutdown the server as gracefully as possible,
        e.g. starting with SIGINT, then SIGTERM, then SIGKILL.
        If `now` is True, terminate the server immediately.

        The coroutine should return when the single-user server process is no longer running.

        Must be a coroutine.
        """
        self.running = False
        return

    @gen.coroutine
    def poll(self):
        """Check if the single-user process is running

        Returns:
          None if single-user process is running.
          Integer exit status (0 if unknown), if it is not running.

        State transitions, behavior, and return response:

        - If the Spawner has not been initialized (neither loaded state, nor called start),
          it should behave as if it is not running (status=0).
        - If the Spawner has not finished starting,
          it should behave as if it is running (status=None).

        Design assumptions about when `poll` may be called:

        - On Hub launch: `poll` may be called before `start` when state is loaded on Hub launch.
          `poll` should return exit status 0 (unknown) if the Spawner has not been initialized via
          `load_state` or `start`.
        - If `.start()` is async: `poll` may be called during any yielded portions of the `start`
          process. `poll` should return None when `start` is yielded, indicating that the `start`
          process has not yet completed.

        """
        if self.running:
            return None
        else:
            return 0



class ProxyAuthenticator(Authenticator):
    """
    Proxy authenticator to use when the login Hubs are differents from the
    spawning hubs This will wrap a given authenticator class (set via the
    `proxied_authenticator_class` configuration option.

    For example, to use a GitHubOAuthenticator set the configuration as follow:

    ```
    c.ProxyAuthenticator.proxied_authenticator_class = 'oauthenticator.GitHubOAuthenticator'
    c.JupyterHub.authenticator_class = 'jupyterhubdispatcher.ProxyAuthenticator'
    ```

    """

    proxied_authenticator_class = Type(default_value=PAMAuthenticator,
                                       help="""The authenticator class to wrap""")\
        .tag(config=True)

    def __init__(self, parent, db):
        self.authenticator = self.proxied_authenticator_class(
            parent=parent, db=db)
        super().__init__(parent=parent, db=db)

    async def authenticate(self, handler, data):
        return await self.authenticator.authenticate(handler, data)

    def get_handlers(self, app):
        """Return any custom handlers the authenticator needs to register

        """
        return [(route, decorate_hub_redirect(handler))
                   for route, handler
                   in self.authenticator.get_handlers(app)]


    def __getattrbute__(self, name):
        """For all non-existing forward to subauthenticator"""
        if name in ('__init__', 'authenticate', 'get_handlers'):
            return object.__getattribute__(self, name)

        return getattr(self.authenticator, name)



class JupyterHubDispatcher(Application):
    name = "jupyerhubdispatcher"
    version = "0.1.0"

    pid_file = Unicode('',
        help="""File to write PID
        Useful for daemonizing jupyterhub.
        """
    ).tag(config=True)


    load_groups = Dict(List(Unicode()),
        help="""Dict of 'group': ['usernames'] to load at startup.

        This strictly *adds* groups and users to groups.

        Loading one set of groups, then starting JupyterHub again with a different
        set will not remove users or groups from previous launches.
        That must be done through the API.
        """
    ).tag(config=True)

    config_file = Unicode('jupyterhub_config.py',
        help="The config file to load",
    ).tag(config=True)

    template_paths = List(
        help="Paths to search for jinja templates.",
    ).tag(config=True)

    @default('template_paths')
    def _template_paths_default(self):
        return [os.path.join(self.data_files_path, 'templates')]

    data_files_path = Unicode(DATA_FILES_PATH,
        help="The location of jupyterhub data files (e.g. /usr/local/share/jupyter/hub)"
    ).tag(config=True)


    port = Integer(8000,
        help="The public facing port of the proxy"
    ).tag(config=True)
    base_url = URLPrefix('/',
        help="The base URL of the entire application"
    ).tag(config=True)
    logo_file = Unicode('',
        help="Specify path to a logo image to override the Jupyter logo in the banner."
    ).tag(config=True)

    @default('logo_file')
    def _logo_file_default(self):
        return os.path.join(self.data_files_path, 'static', 'images', 'jupyter.png')

    jinja_environment_options = Dict(
        help="Supply extra arguments that will be passed to Jinja environment."
    ).tag(config=True)


    hub_port = Integer(8081,
        help="The port for the Hub process"
    ).tag(config=True)
    hub_ip = Unicode('127.0.0.1',
        help="""The ip address for the Hub process to *bind* to.

        See `hub_connect_ip` for cases where the bind and connect address should differ.
        """
    ).tag(config=True)
    
    @default('hub_prefix')
    def _hub_prefix_default(self):
        return url_path_join(self.base_url, '/hub/')

    @observe('base_url')
    def _update_hub_prefix(self, change):
        """add base URL to hub prefix"""
        base_url = change['new']
        self.hub_prefix = self._hub_prefix_default()

    cookie_secret = Bytes(
        help="""The cookie secret to use to encrypt cookies.

        Loaded from the JPY_COOKIE_SECRET env variable by default.
        
        Should be exactly 256 bits (32 bytes).
        """
    ).tag(
        config=True,
        env='JPY_COOKIE_SECRET',
    )
    @observe('cookie_secret')
    def _cookie_secret_check(self, change):
        secret = change.new
        if len(secret) > COOKIE_SECRET_BYTES:
            self.log.warning("Cookie secret is %i bytes.  It should be %i.",
                len(secret), COOKIE_SECRET_BYTES,
            )

    cookie_secret_file = Unicode('jupyterhub_cookie_secret',
        help="""File in which to store the cookie secret."""
    ).tag(config=True)


    authenticator_class = Type(PAMAuthenticator, Authenticator,
        help="""Class for authenticating users.

        This should be a class with the following form:

        - constructor takes one kwarg: `config`, the IPython config object.

        - is a tornado.gen.coroutine
        - returns username on success, None on failure
        - takes two arguments: (handler, data),
          where `handler` is the calling web.RequestHandler,
          and `data` is the POST form data from the login page.
        """
    ).tag(config=True)

    authenticator = Instance(Authenticator)

    @default('authenticator')
    def _authenticator_default(self):
        return self.authenticator_class(parent=self, db=self.db)


    db_url = Unicode('sqlite:///jupyterhub.sqlite',
        help="url for the database. e.g. `sqlite:///jupyterhub.sqlite`"
    ).tag(config=True)

    @observe('db_url')
    def _db_url_changed(self, change):
        new = change['new']
        if '://' not in new:
            # assume sqlite, if given as a plain filename
            self.db_url = 'sqlite:///%s' % new

    db_kwargs = Dict(
        help="""Include any kwargs to pass to the database connection.
        See sqlalchemy.create_engine for details.
        """
    ).tag(config=True)

    cookie_max_age_days = Float(14,
        help="""Number of days for a login cookie to be valid.
        Default is two weeks.
        """
    ).tag(config=True)


    reset_db = Bool(False,
        help="Purge and reset the database."
    ).tag(config=True)
    debug_db = Bool(False,
        help="log all database transactions. This has A LOT of output"
    ).tag(config=True)
    session_factory = Any()

    users = Instance(UserDict)

    @default('users')
    def _users_default(self):
        assert self.tornado_settings
        return UserDict(db_factory=lambda: self.db, settings=self.tornado_settings)


    tornado_settings = Dict(
        help="Extra settings overrides to pass to the tornado application."
    ).tag(config=True)

    statsd_host = Unicode(
        help="Host to send statsd metrics to"
    ).tag(config=True)

    statsd_port = Integer(
        8125,
        help="Port on which to send statsd metrics about the hub"
    ).tag(config=True)

    statsd_prefix = Unicode(
        'jupyterhub',
        help="Prefix to use for all metrics sent by jupyterhub to statsd"
    ).tag(config=True)

    handlers = List()

    _log_formatter_cls = CoroutineLogFormatter
    http_server = None
    io_loop = None

    hub_prefix = URLPrefix('/hub/',
        help="The prefix for the hub server.  Always /base_url/hub/"
    )


    @default('log_level')
    def _log_level_default(self):
        return logging.INFO

    @default('log_datefmt')
    def _log_datefmt_default(self):
        """Exclude date from default date format"""
        return "%Y-%m-%d %H:%M:%S"

    @default('log_format')
    def _log_format_default(self):
        """override default log format to include time"""
        return "%(color)s[%(levelname)1.1s %(asctime)s.%(msecs).03d %(name)s %(module)s:%(lineno)d]%(end_color)s %(message)s"

    extra_log_file = Unicode(
        help="""Send JupyterHub's logs to this file.

        This will *only* include the logs of the Hub itself,
        not the logs of the proxy or any single-user servers.
        """
    ).tag(config=True)
    extra_log_handlers = List(
        Instance(logging.Handler),
        help="Extra log handlers to set on JupyterHub logger",
    ).tag(config=True)

    statsd = Any(allow_none=False, help="The statsd client, if any. A mock will be used if we aren't using statsd")

    @default('statsd')
    def _statsd(self):
        if self.statsd_host:
            import statsd
            client = statsd.StatsClient(
                self.statsd_host,
                self.statsd_port,
                self.statsd_prefix
            )
            return client
        else:
            # return an empty mock object!
            return EmptyClass()

    def init_logging(self):
        # This prevents double log messages because tornado use a root logger that
        # self.log is a child of. The logging module dipatches log messages to a log
        # and all of its ancenstors until propagate is set to False.
        self.log.propagate = False

        if self.extra_log_file:
            self.extra_log_handlers.append(
                logging.FileHandler(self.extra_log_file)
            )

        _formatter = self._log_formatter_cls(
            fmt=self.log_format,
            datefmt=self.log_datefmt,
        )
        for handler in self.extra_log_handlers:
            if handler.formatter is None:
                handler.setFormatter(_formatter)
            self.log.addHandler(handler)

        # hook up tornado 3's loggers to our app handlers
        for log in (app_log, access_log, gen_log):
            # ensure all log statements identify the application they come from
            log.name = self.log.name
        logger = logging.getLogger('tornado')
        logger.propagate = True
        logger.parent = self.log
        logger.setLevel(self.log.level)

    def init_ports(self):
        if self.hub_port == self.port:
            raise TraitError("The hub and proxy cannot both listen on port %i" % self.port)

    @staticmethod
    def add_url_prefix(prefix, handlers):
        """add a url prefix to handlers"""
        for i, tup in enumerate(handlers):
            lis = list(tup)
            lis[0] = url_path_join(prefix, tup[0])
            handlers[i] = tuple(lis)
        return handlers


    def init_handlers(self):
        h = []
        # load handlers from the authenticator
        h.extend(self.authenticator.get_handlers(self))
        # set default handlers

        h.append((r'/logo', LogoHandler, {'path': self.logo_file}))
        self.handlers = self.add_url_prefix(self.hub_prefix, h)
        # some extra handlers, outside hub_prefix
        self.handlers.extend([
            (r"%s" % self.hub_prefix.rstrip('/'), web.RedirectHandler,
                {
                    "url": self.hub_prefix,
                    "permanent": False,
                }
            ),
            (r"(?!%s).*" % self.hub_prefix, handlers.PrefixRedirectHandler),
            (r'(.*)', handlers.Template404),
        ])
    
    def _check_db_path(self, path):
        """More informative log messages for failed filesystem access"""
        path = os.path.abspath(path)
        parent, fname = os.path.split(path)
        user = getuser()
        if not os.path.isdir(parent):
            self.log.error("Directory %s does not exist", parent)
        if os.path.exists(parent) and not os.access(parent, os.W_OK):
            self.log.error("%s cannot create files in %s", user, parent)
        if os.path.exists(path) and not os.access(path, os.W_OK):
            self.log.error("%s cannot edit %s", user, path)

    def init_secrets(self):
        trait_name = 'cookie_secret'
        trait = self.traits()[trait_name]
        env_name = trait.metadata.get('env')
        secret_file = os.path.abspath(
            os.path.expanduser(self.cookie_secret_file)
        )
        secret = self.cookie_secret
        secret_from = 'config'
        # load priority: 1. config, 2. env, 3. file
        secret_env = os.environ.get(env_name)
        if not secret and secret_env:
            secret_from = 'env'
            self.log.info("Loading %s from env[%s]", trait_name, env_name)
            secret = binascii.a2b_hex(secret_env)
        if not secret and os.path.exists(secret_file):
            secret_from = 'file'
            self.log.info("Loading %s from %s", trait_name, secret_file)
            try:
                perm = os.stat(secret_file).st_mode
                if perm & 0o07:
                    raise ValueError("cookie_secret_file can be read or written by anybody")
                with open(secret_file) as f:
                    text_secret = f.read().strip()
                if HEX_RE.match(text_secret):
                    # >= 0.8, use 32B hex
                    secret = binascii.a2b_hex(text_secret)
                else:
                    # old b64 secret with a bunch of ignored bytes
                    secret = binascii.a2b_base64(text_secret)
                    self.log.warning(dedent("""
                    Old base64 cookie-secret detected in {0}.

                    JupyterHub >= 0.8 expects 32B hex-encoded cookie secret
                    for tornado's sha256 cookie signing.

                    To generate a new secret:

                        openssl rand -hex 32 > "{0}"
                    """).format(secret_file))
            except Exception as e:
                self.log.error(
                    "Refusing to run JupyterHub with invalid cookie_secret_file. "
                    "%s error was: %s",
                    secret_file, e)
                self.exit(1)
        if not secret:
            secret_from = 'new'
            self.log.debug("Generating new %s", trait_name)
            secret = os.urandom(COOKIE_SECRET_BYTES)

        if secret_file and secret_from == 'new':
            # if we generated a new secret, store it in the secret_file
            self.log.info("Writing %s to %s", trait_name, secret_file)
            text_secret = binascii.b2a_hex(secret).decode('ascii')
            with open(secret_file, 'w') as f:
                f.write(text_secret)
                f.write('\n')
            try:
                os.chmod(secret_file, 0o600)
            except OSError:
                self.log.warning("Failed to set permissions on %s", secret_file)
        # store the loaded trait value
        self.cookie_secret = secret


    _local = Instance(threading.local, ())

    @property
    def db(self):
        if not hasattr(self._local, 'db'):
            self._local.db = scoped_session(self.session_factory)()
        return self._local.db

    def init_db(self):
        """Create the database connection"""
        self.log.debug("Connecting to db: %s", self.db_url)
        try:
            self.session_factory = orm.new_session_factory(
                self.db_url,
                reset=self.reset_db,
                echo=self.debug_db,
                **self.db_kwargs
            )
            # trigger constructing thread local db property
            _ = self.db
        except OperationalError as e:
            self.log.error("Failed to connect to db: %s", self.db_url)
            self.log.debug("Database error was:", exc_info=True)
            if self.db_url.startswith('sqlite:///'):
                self._check_db_path(self.db_url.split(':///', 1)[1])
            self.log.critical('\n'.join([
                "If you recently upgraded JupyterHub, try running",
                "    jupyterhub upgrade-db",
                "to upgrade your JupyterHub database schema",
            ]))
            self.exit(1)


    def init_oauth(self):
        base_url = self.base_url
        self.oauth_provider = make_provider(
            self.session_factory,
            url_prefix=url_path_join(base_url, 'api/oauth2'),
            login_url=url_path_join(base_url, 'login')
        )

    subdomain_host = Unicode('',
        help="""Run single-user servers on subdomains of this host.

        This should be the full https://hub.domain.tld[:port]

        Provides additional cross-site protections for javascript served by single-user servers.

        Requires <username>.hub.domain.tld to resolve to the same host as hub.domain.tld.

        In general, this is most easily achieved with wildcard DNS.

        When using SSL (i.e. always) this also requires a wildcard SSL certificate.
        """
    ).tag(config=True)

    def _subdomain_host_changed(self, name, old, new):
        if new and '://' not in new:
            # host should include '://'
            # if not specified, assume https: You have to be really explicit about HTTP!
            self.subdomain_host = 'https://' + new

    domain = Unicode(
        help="domain name, e.g. 'example.com' (excludes protocol, port)"
    )


    @default('domain')
    def _domain_default(self):
        if not self.subdomain_host:
            return ''
        return urlparse(self.subdomain_host).hostname


    def init_hub(self):
        """Load the Hub config into the database"""
        self.hub = Hub(
            ip=self.hub_ip,
            port=self.hub_port,
            base_url=self.hub_prefix,
            cookie_name='jupyter-hub-token',
            public_host=self.subdomain_host,
        )



    def init_tornado_settings(self):
        """Set up the tornado settings dict."""
        base_url = self.hub.base_url
        jinja_options = dict(
            autoescape=True,
        )
        jinja_options.update(self.jinja_environment_options)
        jinja_env = Environment(
            loader=FileSystemLoader(self.template_paths),
            **jinja_options
        )

        login_url = url_path_join(base_url, 'login')
        logout_url = self.authenticator.logout_url(base_url)

        # if running from git, disable caching of require.js
        # otherwise cache based on server start time
        parent = os.path.dirname(os.path.dirname('.'))
        if os.path.isdir(os.path.join(parent, '.git')):
            version_hash = ''
        else:
            version_hash = datetime.now().strftime("%Y%m%d%H%M%S"),

        settings = dict(
            log_function=log_request,
            config=self.config,
            log=self.log,
            hub=self.hub,
            db=self.db,
            authenticator=self.authenticator,
            base_url=self.base_url,
            spawner_class=NoOpSpawner,
            cookie_secret=self.cookie_secret,
            cookie_max_age_days=self.cookie_max_age_days,
            login_url=login_url,
            logout_url=logout_url,
            static_path=os.path.join(self.data_files_path, 'static'),
            static_url_prefix=url_path_join(self.base_url, 'static/'),
            static_handler_class=CacheControlStaticFilesHandler,
            template_path=self.template_paths,
            jinja2_env=jinja_env,
            version_hash=version_hash,
            statsd=self.statsd,
            oauth_provider=self.oauth_provider,
        )
        # allow configured settings to have priority
        settings.update(self.tornado_settings)
        self.tornado_settings = settings
        # constructing users requires access to tornado_settings
        self.tornado_settings['users'] = self.users


    def init_tornado_application(self):
        """Instantiate the tornado Application object"""
        self.tornado_application = web.Application(self.handlers, **self.tornado_settings)

    def init_pycurl(self):
        """Configure tornado to use pycurl by default, if available"""
        # use pycurl by default, if available:
        try:
            AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")
        except ImportError as e:
            self.log.debug("Could not load pycurl: %s\npycurl is recommended if you have a large number of users.", e)

    def write_pid_file(self):
        pid = os.getpid()
        if self.pid_file:
            self.log.debug("Writing PID %i to %s", pid, self.pid_file)
            with open(self.pid_file, 'w') as f:
                f.write('%i' % pid)

    @gen.coroutine
    @catch_config_error
    def initialize(self, *args, **kwargs):
        super().initialize(*args, **kwargs)
        self.load_config_file(self.config_file)
        self.init_logging()
        if 'JupyterHubApp' in self.config:
            self.log.warning("Use JupyterHub in config, not JupyterHubApp. Outdated config:\n%s",
                '\n'.join('JupyterHubApp.{key} = {value!r}'.format(key=key, value=value)
                    for key, value in self.config.JupyterHubApp.items()
                )
            )
            cfg = self.config.copy()
            cfg.JupyterHub.merge(cfg.JupyterHubApp)
            self.update_config(cfg)
        self.write_pid_file()
        self.init_pycurl()
        self.init_ports()
        self.init_secrets()
        self.init_db()
        self.init_hub()
        self.init_oauth()
        self.init_tornado_settings()
        self.init_handlers()
        self.init_tornado_application()


    @gen.coroutine
    def cleanup(self):
        """Shutdown managed services and various subprocesses. Cleanup runtime files."""

        if self.pid_file and os.path.exists(self.pid_file):
            self.log.info("Cleaning up PID file %s", self.pid_file)
            os.remove(self.pid_file)

        # finally stop the loop once we are all cleaned up
        self.log.info("...done")


    @gen.coroutine
    def start(self):
        """Start the whole thing"""
        self.io_loop =  IOLoop.current()

        # start the webserver
        self.http_server = tornado.httpserver.HTTPServer(self.tornado_application, xheaders=True)
        try:
            self.http_server.listen(self.hub_port, address=self.hub_ip)
        except Exception:
            self.log.error("Failed to bind hub to %s:%s", self.hub_ip, self.hub_port)
            raise
        else:
            self.log.info("Hub API listening on %s:%s", self.hub_ip, self.hub_port)

        # register cleanup on both TERM and INT
        atexit.register(self.atexit)
        self.init_signal()

    def init_signal(self):
        signal.signal(signal.SIGTERM, self.sigterm)

    def sigterm(self, signum, frame):
        self.log.critical("Received SIGTERM, shutting down")
        self.io_loop.stop()
        self.atexit()

    _atexit_ran = False

    def atexit(self):
        """atexit callback"""
        if self._atexit_ran:
            return
        self._atexit_ran = True
        # run the cleanup step (in a new loop, because the interrupted one is unclean)
        IOLoop.clear_current()
        loop = IOLoop()
        loop.make_current()
        loop.run_sync(self.cleanup)

    def stop(self):
        if not self.io_loop:
            return
        if self.http_server:
            if self.io_loop._running:
                self.io_loop.add_callback(self.http_server.stop)
            else:
                self.http_server.stop()
        self.io_loop.add_callback(self.io_loop.stop)

    @gen.coroutine
    def launch_instance_async(self, argv=None):
        try:
            yield self.initialize(argv)
            yield self.start()
        except Exception as e:
            self.log.exception("")
            self.exit(1)

    @classmethod
    def launch_instance(cls, argv=None):
        self = cls.instance()
        loop = IOLoop.current()
        loop.add_callback(self.launch_instance_async, argv)
        try:
            loop.start()
        except KeyboardInterrupt:
            print("\nInterrupted")



main = JupyterHubDispatcher.launch_instance

if __name__ == "__main__":
    main()
