# Copyright 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
TOKEN-BASED AUTH MIDDLEWARE

!!!!!!!!!!!!!!!!!!!!!!!!!!!

This auth token client is a modified keystone client, which does not verify incoming client requests. Instead, it only
collects and forwards identity information based on a token, which is assumed to be valid. This auth client is used in
permissive mode of Sahara.

!!!!!!!!!!!!!!!!!!!!!!!!!!!

This WSGI component:

* Verifies that incoming client requests have valid tokens by validating
  tokens with the auth service.
* Rejects unauthenticated requests UNLESS it is in 'delay_auth_decision'
  mode, which means the final decision is delegated to the downstream WSGI
  component (usually the OpenStack service)
* Collects and forwards identity information based on a valid token
  such as user name, tenant, etc

Refer to: http://docs.openstack.org/developer/python-keystoneclient/
middlewarearchitecture.html

HEADERS
-------

* Headers starting with HTTP\_ is a standard http header
* Headers starting with HTTP_X is an extended http header

Coming in from initial call from client or customer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTH_TOKEN
    The client token being passed in.

HTTP_X_STORAGE_TOKEN
    The client token being passed in (legacy Rackspace use) to support
    swift/cloud files

Used for communication between components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

WWW-Authenticate
    HTTP header returned to a user indicating which endpoint to use
    to retrieve a new token

What we add to the request for use by the OpenStack service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_IDENTITY_STATUS
    'Confirmed' or 'Invalid'
    The underlying service will only see a value of 'Invalid' if the Middleware
    is configured to run in 'delay_auth_decision' mode

HTTP_X_DOMAIN_ID
    Identity service managed unique identifier, string. Only present if
    this is a domain-scoped v3 token.

HTTP_X_DOMAIN_NAME
    Unique domain name, string. Only present if this is a domain-scoped
    v3 token.

HTTP_X_PROJECT_ID
    Identity service managed unique identifier, string. Only present if
    this is a project-scoped v3 token, or a tenant-scoped v2 token.

HTTP_X_PROJECT_NAME
    Project name, unique within owning domain, string. Only present if
    this is a project-scoped v3 token, or a tenant-scoped v2 token.

HTTP_X_PROJECT_DOMAIN_ID
    Identity service managed unique identifier of owning domain of
    project, string.  Only present if this is a project-scoped v3 token. If
    this variable is set, this indicates that the PROJECT_NAME can only
    be assumed to be unique within this domain.

HTTP_X_PROJECT_DOMAIN_NAME
    Name of owning domain of project, string. Only present if this is a
    project-scoped v3 token. If this variable is set, this indicates that
    the PROJECT_NAME can only be assumed to be unique within this domain.

HTTP_X_USER_ID
    Identity-service managed unique identifier, string

HTTP_X_USER_NAME
    User identifier, unique within owning domain, string

HTTP_X_USER_DOMAIN_ID
    Identity service managed unique identifier of owning domain of
    user, string. If this variable is set, this indicates that the USER_NAME
    can only be assumed to be unique within this domain.

HTTP_X_USER_DOMAIN_NAME
    Name of owning domain of user, string. If this variable is set, this
    indicates that the USER_NAME can only be assumed to be unique within
    this domain.

HTTP_X_ROLES
    Comma delimited list of case-sensitive role names

HTTP_X_SERVICE_CATALOG
    json encoded keystone service catalog (optional).
    For compatibility reasons this catalog will always be in the V2 catalog
    format even if it is a v3 token.

HTTP_X_TENANT_ID
    *Deprecated* in favor of HTTP_X_PROJECT_ID
    Identity service managed unique identifier, string. For v3 tokens, this
    will be set to the same value as HTTP_X_PROJECT_ID

HTTP_X_TENANT_NAME
    *Deprecated* in favor of HTTP_X_PROJECT_NAME
    Project identifier, unique within owning domain, string. For v3 tokens,
    this will be set to the same value as HTTP_X_PROJECT_NAME

HTTP_X_TENANT
    *Deprecated* in favor of HTTP_X_TENANT_ID and HTTP_X_TENANT_NAME
    Keystone-assigned unique identifier, string. For v3 tokens, this
    will be set to the same value as HTTP_X_PROJECT_ID

HTTP_X_USER
    *Deprecated* in favor of HTTP_X_USER_ID and HTTP_X_USER_NAME
    User name, unique within owning domain, string

HTTP_X_ROLE
    *Deprecated* in favor of HTTP_X_ROLES
    Will contain the same values as HTTP_X_ROLES.

OTHER ENVIRONMENT VARIABLES
---------------------------

keystone.token_info
    Information about the token discovered in the process of
    validation.  This may include extended information returned by the
    Keystone token validation call, as well as basic information about
    the tenant and user.

"""

import contextlib
import datetime
import logging
import os
import requests
import stat
import tempfile
import time

import netaddr
from oslo.config import cfg
import six
from six.moves import urllib

from keystoneclient import access
from keystoneclient.common import cms
from keystoneclient.middleware import memcache_crypt
from keystoneclient.openstack.common import jsonutils
from keystoneclient.openstack.common import memorycache
from keystoneclient.openstack.common import timeutils
import sahara.openstack.commons as commons


# alternative middleware configuration in the main application's
# configuration file e.g. in nova.conf
# [keystone_authtoken]
# auth_host = 127.0.0.1
# auth_port = 35357
# auth_protocol = http
# admin_tenant_name = admin
# admin_user = admin
# admin_password = badpassword

# when deploy Keystone auth_token middleware with Swift, user may elect
# to use Swift memcache instead of the local Keystone memcache. Swift memcache
# is passed in from the request environment and its identified by the
# 'swift.cache' key. However it could be different, depending on deployment.
# To use Swift memcache, you must set the 'cache' option to the environment
# key where the Swift cache object is stored.


# NOTE(jamielennox): A number of options below are deprecated however are left
# in the list and only mentioned as deprecated in the help string. This is
# because we have to provide the same deprecation functionality for arguments
# passed in via the conf in __init__ (from paste) and there is no way to test
# that the default value was set or not in CONF.
# Also if we were to remove the options from the CONF list (as typical CONF
# deprecation works) then other projects will not be able to override the
# options via CONF.

opts = [
    cfg.StrOpt('auth_admin_prefix',
               default='',
               help='Prefix to prepend at the beginning of the path. '
                    'Deprecated, use identity_uri.'),
    cfg.StrOpt('auth_host',
               default='127.0.0.1',
               help='Host providing the admin Identity API endpoint. '
                    'Deprecated, use identity_uri.'),
    cfg.IntOpt('auth_port',
               default=35357,
               help='Port of the admin Identity API endpoint. '
                    'Deprecated, use identity_uri.'),
    cfg.StrOpt('auth_protocol',
               default='https',
               help='Protocol of the admin Identity API endpoint '
                    '(http or https). Deprecated, use identity_uri.'),
    cfg.StrOpt('auth_uri',
               default=None,
               # FIXME(dolph): should be default='http://127.0.0.1:5000/v2.0/',
               # or (depending on client support) an unversioned, publicly
               # accessible identity endpoint (see bug 1207517)
               help='Complete public Identity API endpoint'),
    cfg.StrOpt('identity_uri',
               default=None,
               help='Complete admin Identity API endpoint. This should '
                    'specify the unversioned root endpoint '
                    'e.g. https://localhost:35357/'),
    cfg.StrOpt('auth_version',
               default=None,
               help='API version of the admin Identity API endpoint'),
    cfg.BoolOpt('delay_auth_decision',
                default=False,
                help='Do not handle authorization requests within the'
                     ' middleware, but delegate the authorization decision to'
                     ' downstream WSGI components'),
    cfg.BoolOpt('http_connect_timeout',
                default=None,
                help='Request timeout value for communicating with Identity'
                     ' API server.'),
    cfg.IntOpt('http_request_max_retries',
               default=3,
               help='How many times are we trying to reconnect when'
                    ' communicating with Identity API Server.'),
    cfg.StrOpt('admin_token',
               secret=True,
               help='This option is deprecated and may be removed in a future'
                    ' release. Single shared secret with the Keystone configuration'
                    ' used for bootstrapping a Keystone installation, or otherwise'
                    ' bypassing the normal authentication process. This option'
                    ' should not be used, use `admin_user` and `admin_password`'
                    ' instead.'),
    cfg.StrOpt('admin_user',
               help='Keystone account username'),
    cfg.StrOpt('admin_password',
               secret=True,
               help='Keystone account password'),
    cfg.StrOpt('admin_tenant_name',
               default='admin',
               help='Keystone service account tenant name to validate'
                    ' user tokens'),
    cfg.StrOpt('cache',
               default=None,
               help='Env key for the swift cache'),
    cfg.StrOpt('certfile',
               help='Required if Keystone server requires client certificate'),
    cfg.StrOpt('keyfile',
               help='Required if Keystone server requires client certificate'),
    cfg.StrOpt('cafile', default=None,
               help='A PEM encoded Certificate Authority to use when '
                    'verifying HTTPs connections. Defaults to system CAs.'),
    cfg.BoolOpt('insecure', default=False, help='Verify HTTPS connections.'),
    cfg.StrOpt('signing_dir',
               help='Directory used to cache files related to PKI tokens'),
    cfg.ListOpt('memcached_servers',
                deprecated_name='memcache_servers',
                help='Optionally specify a list of memcached server(s) to'
                     ' use for caching. If left undefined, tokens will instead be'
                     ' cached in-process.'),
    cfg.IntOpt('token_cache_time',
               default=300,
               help='In order to prevent excessive effort spent validating'
                    ' tokens, the middleware caches previously-seen tokens for a'
                    ' configurable duration (in seconds). Set to -1 to disable'
                    ' caching completely.'),
    cfg.IntOpt('revocation_cache_time',
               default=10,
               help='Determines the frequency at which the list of revoked'
                    ' tokens is retrieved from the Identity service (in seconds). A'
                    ' high number of revocation events combined with a low cache'
                    ' duration may significantly reduce performance.'),
    cfg.StrOpt('memcache_security_strategy',
               default=None,
               help='(optional) if defined, indicate whether token data'
                    ' should be authenticated or authenticated and encrypted.'
                    ' Acceptable values are MAC or ENCRYPT.  If MAC, token data is'
                    ' authenticated (with HMAC) in the cache. If ENCRYPT, token'
                    ' data is encrypted and authenticated in the cache. If the'
                    ' value is not one of these options or empty, auth_token will'
                    ' raise an exception on initialization.'),
    cfg.StrOpt('memcache_secret_key',
               default=None,
               secret=True,
               help='(optional, mandatory if memcache_security_strategy is'
                    ' defined) this string is used for key derivation.'),
    cfg.BoolOpt('include_service_catalog',
                default=True,
                help='(optional) indicate whether to set the X-Service-Catalog'
                     ' header. If False, middleware will not ask for service'
                     ' catalog on token validation and will not set the'
                     ' X-Service-Catalog header.'),
    cfg.StrOpt('enforce_token_bind',
               default='permissive',
               help='Used to control the use and type of token binding. Can'
                    ' be set to: "disabled" to not check token binding.'
                    ' "permissive" (default) to validate binding information if the'
                    ' bind type is of a form known to the server and ignore it if'
                    ' not. "strict" like "permissive" but if the bind type is'
                    ' unknown the token will be rejected. "required" any form of'
                    ' token binding is needed to be allowed. Finally the name of a'
                    ' binding method that must be present in tokens.'),
    cfg.BoolOpt('check_revocations_for_cached', default=False,
                help='If true, the revocation list will be checked for cached'
                     ' tokens. This requires that PKI tokens are configured on the'
                     ' Keystone server.'),
    cfg.ListOpt('hash_algorithms', default=['md5'],
                help='Hash algorithms to use for hashing PKI tokens. This may'
                     ' be a single algorithm or multiple. The algorithms are those'
                     ' supported by Python standard hashlib.new(). The hashes will'
                     ' be tried in the order given, so put the preferred one first'
                     ' for performance. The result of the first hash will be stored'
                     ' in the cache. This will typically be set to multiple values'
                     ' only while migrating from a less secure algorithm to a more'
                     ' secure one. Once all the old tokens are expired this option'
                     ' should be set to a single value for better performance.'),
    ]

CONF = cfg.CONF
CONF.register_opts(opts, group='keystone_authtoken')

LIST_OF_VERSIONS_TO_ATTEMPT = ['v2.0', 'v3.0']
CACHE_KEY_TEMPLATE = 'tokens/%s'


class BIND_MODE:
    DISABLED = 'disabled'
    PERMISSIVE = 'permissive'
    STRICT = 'strict'
    REQUIRED = 'required'
    KERBEROS = 'kerberos'


def will_expire_soon(expiry):
    """Determines if expiration is about to occur.

    :param expiry: a datetime of the expected expiration
    :returns: boolean : true if expiration is within 30 seconds
    """
    soon = (timeutils.utcnow() + datetime.timedelta(seconds=30))
    return expiry < soon


def _token_is_v2(token_info):
    return ('access' in token_info)


def _token_is_v3(token_info):
    return ('token' in token_info)


def confirm_token_not_expired(data):
    if not data:
        raise InvalidUserToken('Token authorization failed')
    if _token_is_v2(data):
        timestamp = data['access']['token']['expires']
    elif _token_is_v3(data):
        timestamp = data['token']['expires_at']
    else:
        raise InvalidUserToken('Token authorization failed')
    expires = timeutils.parse_isotime(timestamp)
    expires = timeutils.normalize_time(expires)
    utcnow = timeutils.utcnow()
    if utcnow >= expires:
        raise InvalidUserToken('Token authorization failed')
    return timeutils.isotime(at=expires, subsecond=True)


def _v3_to_v2_catalog(catalog):
    """Convert a catalog to v2 format.

    X_SERVICE_CATALOG must be specified in v2 format. If you get a token
    that is in v3 convert it.
    """
    v2_services = []
    for v3_service in catalog:
        # first copy over the entries we allow for the service
        v2_service = {'type': v3_service['type']}
        try:
            v2_service['name'] = v3_service['name']
        except KeyError:
            pass

        # now convert the endpoints. Because in v3 we specify region per
        # URL not per group we have to collect all the entries of the same
        # region together before adding it to the new service.
        regions = {}
        for v3_endpoint in v3_service.get('endpoints', []):
            region_name = v3_endpoint.get('region')
            try:
                region = regions[region_name]
            except KeyError:
                region = {'region': region_name} if region_name else {}
                regions[region_name] = region

            interface_name = v3_endpoint['interface'].lower() + 'URL'
            region[interface_name] = v3_endpoint['url']

        v2_service['endpoints'] = list(regions.values())
        v2_services.append(v2_service)

    return v2_services


def safe_quote(s):
    """URL-encode strings that are not already URL-encoded."""
    return urllib.parse.quote(s) if s == urllib.parse.unquote(s) else s


class InvalidUserToken(Exception):
    pass


class ServiceError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class NetworkError(Exception):
    pass


class MiniResp(object):
    def __init__(self, error_message, env, headers=[]):
        # The HEAD method is unique: it must never return a body, even if
        # it reports an error (RFC-2616 clause 9.4). We relieve callers
        # from varying the error responses depending on the method.
        if env['REQUEST_METHOD'] == 'HEAD':
            self.body = ['']
        else:
            self.body = [error_message]
        self.headers = list(headers)
        self.headers.append(('Content-type', 'text/plain'))


class AuthProtocol(object):
    """Auth Middleware that does not authenticate client calls. Instead, it only
collects and forwards identity information based on a token, which is assumed to be valid. """

    def __init__(self, app, conf):
        self.LOG = logging.getLogger(conf.get('log_name', __name__))
        self.LOG.info('Starting keystone permissive auth_token middleware')
        self.conf = conf
        self.app = app

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self.delay_auth_decision = (self._conf_get('delay_auth_decision') in
                                    (True, 'true', 't', '1', 'on', 'yes', 'y'))

        # where to find the auth service (we use this to validate tokens)
        self.identity_uri = self._conf_get('identity_uri')
        self.auth_uri = self._conf_get('auth_uri')

        # NOTE(jamielennox): it does appear here that our defaults arguments
        # are backwards. We need to do it this way so that we can handle the
        # same deprecation strategy for CONF and the conf variable.
        if not self.identity_uri:
            self.LOG.warning('Configuring admin URI using auth fragments. '
                             'This is deprecated, use \'identity_uri\''
                             ' instead.')

            auth_host = self._conf_get('auth_host')
            auth_port = int(self._conf_get('auth_port'))
            auth_protocol = self._conf_get('auth_protocol')
            auth_admin_prefix = self._conf_get('auth_admin_prefix')

            if netaddr.valid_ipv6(auth_host):
                # Note(dzyu) it is an IPv6 address, so it needs to be wrapped
                # with '[]' to generate a valid IPv6 URL, based on
                # http://www.ietf.org/rfc/rfc2732.txt
                auth_host = '[%s]' % auth_host

            self.identity_uri = '%s://%s:%s' % (auth_protocol, auth_host,
                                                auth_port)
            if auth_admin_prefix:
                self.identity_uri = '%s/%s' % (self.identity_uri,
                                               auth_admin_prefix.strip('/'))
        else:
            self.identity_uri = self.identity_uri.rstrip('/')

        if self.auth_uri is None:
            self.LOG.warning(
                'Configuring auth_uri to point to the public identity '
                'endpoint is required; clients may not be able to '
                'authenticate against an admin endpoint')

            # FIXME(dolph): drop support for this fallback behavior as
            # documented in bug 1207517.
            # NOTE(jamielennox): we urljoin '/' to get just the base URI as
            # this is the original behaviour.
            self.auth_uri = urllib.parse.urljoin(self.identity_uri, '/')
            self.auth_uri = self.auth_uri.rstrip('/')

        # SSL
        self.cert_file = self._conf_get('certfile')
        self.key_file = self._conf_get('keyfile')
        self.ssl_ca_file = self._conf_get('cafile')
        self.ssl_insecure = self._conf_get('insecure')

        # signing
        self.signing_dirname = self._conf_get('signing_dir')
        if self.signing_dirname is None:
            self.signing_dirname = tempfile.mkdtemp(prefix='keystone-signing-')
        self.LOG.info('Using %s as cache directory for signing certificate',
                      self.signing_dirname)
        self.verify_signing_dir()

        val = '%s/signing_cert.pem' % self.signing_dirname
        self.signing_cert_file_name = val
        val = '%s/cacert.pem' % self.signing_dirname
        self.signing_ca_file_name = val
        val = '%s/revoked.pem' % self.signing_dirname
        self.revoked_file_name = val

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = self._conf_get('admin_token')
        if self.admin_token:
            self.LOG.warning(
                "The admin_token option in the auth_token middleware is "
                "deprecated and should not be used. The admin_user and "
                "admin_password options should be used instead. The "
                "admin_token option may be removed in a future release.")
        self.admin_token_expiry = None
        self.admin_user = self._conf_get('admin_user')
        self.admin_password = self._conf_get('admin_password')
        self.admin_tenant_name = self._conf_get('admin_tenant_name')

        http_connect_timeout_cfg = self._conf_get('http_connect_timeout')
        self.http_connect_timeout = (http_connect_timeout_cfg and
                                     int(http_connect_timeout_cfg))
        self.auth_version = None
        self.http_request_max_retries = (
            self._conf_get('http_request_max_retries'))

        self.include_service_catalog = self._conf_get(
            'include_service_catalog')

    def _conf_get(self, name):
        # try config from paste-deploy first
        if name in self.conf:
            return self.conf[name]
        else:
            return CONF.keystone_authtoken[name]

    def _choose_api_version(self):
        """Determine the api version that we should use."""

        # If the configuration specifies an auth_version we will just
        # assume that is correct and use it.  We could, of course, check
        # that this version is supported by the server, but in case
        # there are some problems in the field, we want as little code
        # as possible in the way of letting auth_token talk to the
        # server.
        if self._conf_get('auth_version'):
            version_to_use = self._conf_get('auth_version')
            self.LOG.info('Auth Token proceeding with requested %s apis',
                          version_to_use)
        else:
            version_to_use = None
            versions_supported_by_server = self._get_supported_versions()
            if versions_supported_by_server:
                for version in LIST_OF_VERSIONS_TO_ATTEMPT:
                    if version in versions_supported_by_server:
                        version_to_use = version
                        break
            if version_to_use:
                self.LOG.info('Auth Token confirmed use of %s apis',
                              version_to_use)
            else:
                self.LOG.error(
                    'Attempted versions [%s] not in list supported by '
                    'server [%s]',
                    ', '.join(LIST_OF_VERSIONS_TO_ATTEMPT),
                    ', '.join(versions_supported_by_server))
                raise ServiceError('No compatible apis supported by server')
        return version_to_use

    def _get_supported_versions(self):
        versions = []
        response, data = self._json_request('GET', '/')
        if response.status_code == 501:
            self.LOG.warning('Old keystone installation found...assuming v2.0')
            versions.append('v2.0')
        elif response.status_code != 300:
            self.LOG.error('Unable to get version info from keystone: %s',
                           response.status_code)
            raise ServiceError('Unable to get version info from keystone')
        else:
            try:
                for version in data['versions']['values']:
                    versions.append(version['id'])
            except KeyError:
                self.LOG.error(
                    'Invalid version response format from server')
                raise ServiceError('Unable to parse version response '
                                   'from keystone')

        self.LOG.debug('Server reports support for api versions: %s',
                       ', '.join(versions))
        return versions

    def __call__(self, env, start_response):
        """Handle incoming request.

        Always authenticate and forward the request downstream

        """

        try:
            admin_tenant_name = self._get_admin_tenant_name(env)
            self.get_admin_token(admin_tenant_name)
            env['keystone.token_info'] = self.admin_token_data
            user_headers = self._build_user_headers(self.admin_token_data)
            self._add_headers(env, user_headers)
            return self.app(env, start_response)
        except ServiceError as e:
            self.LOG.critical('Unable to obtain admin token: %s', e)
            resp = MiniResp('Service unavailable', env)
            start_response('503 Service Unavailable', resp.headers)
            return resp.body

    def _get_admin_tenant_name(self, env):
        """Get admin tenant name from request environment or call keystone api to retrieve
        the first active tenant for the X-Auth-Token of this request

        :param env: wsgi request environment
        :return tenant name or None if no enabled tenants present for this token
        :raises InvalidUserToken if no token is provided in request

        """
        tenant_name_from_header = self._get_header(env, 'X-Tenant-Name', self._get_header(env, 'X-Project-Name'))

        if tenant_name_from_header:
            return tenant_name_from_header
        else:
            user_token_from_header = self._get_header(env, 'X-Auth-Token')
            if user_token_from_header is None:
                raise InvalidUserToken('No X-Auth-Token header present in the request')
            headers = {
                'X-Auth-Token': user_token_from_header
            }

            response, data = self._json_request('GET', '/v2.0/tenants', body=None, additional_headers=headers)
            active_tenants = [tenant for tenant in data['tenants'] if tenant['enabled']]
            if len(active_tenants) > 1:
                url_tenant_name = self._get_tenant_id_from_path(env, active_tenants)
                if url_tenant_name:
                    return url_tenant_name
                self.LOG.warning("More than one active tenant available for token. Choosing the first one.")
            return active_tenants[0]['name'] if len(active_tenants) > 0 else None

    def _get_tenant_id_from_path(self, env, active_tenants):
        path = env['PATH_INFO']
        if path != '/':
            version, url_tenant_id, rest = commons.split_path(path, 3, 3, True)
            if url_tenant_id:
                return [tenant['name'] for tenant in active_tenants if tenant['id'] == url_tenant_id][0]
        return None

    def get_admin_token(self, admin_tenant_name=None):
        """Return admin token, possibly fetching a new one.

        if self.admin_token_expiry is set from fetching an admin token, check
        it for expiration, and request a new token is the existing token
        is about to expire.

        :return admin token id
        :raise ServiceError when unable to retrieve token from keystone

        """
        if self.admin_token_expiry:
            if will_expire_soon(self.admin_token_expiry):
                self.LOG.debug('Token about to expire...')
                self.admin_token = None

        if (not self.admin_token) or self.admin_token_tenant['name'] != admin_tenant_name:
            self.LOG.debug('Requesting new admin token')
            (self.admin_token,
             self.admin_token_expiry, self.admin_token_data, self.admin_token_tenant) = self._request_admin_token(admin_tenant_name)

        return self.admin_token

    def _http_request(self, method, path, **kwargs):
        """HTTP request helper used to make unspecified content type requests.

        :param method: http method
        :param path: relative request url
        :return (http response object, response body)
        :raise ServerError when unable to communicate with keystone

        """
        url = '%s/%s' % (self.identity_uri, path.lstrip('/'))

        kwargs.setdefault('timeout', self.http_connect_timeout)
        if self.cert_file and self.key_file:
            kwargs['cert'] = (self.cert_file, self.key_file)
        elif self.cert_file or self.key_file:
            self.LOG.warn('Cannot use only a cert or key file. '
                          'Please provide both. Ignoring.')

        kwargs['verify'] = self.ssl_ca_file or True
        if self.ssl_insecure:
            kwargs['verify'] = False

        RETRIES = self.http_request_max_retries
        retry = 0
        while True:
            try:
                response = requests.request(method, url, **kwargs)
                break
            except Exception as e:
                if retry >= RETRIES:
                    self.LOG.error('HTTP connection exception: %s', e)
                    raise NetworkError('Unable to communicate with keystone')
                    # NOTE(vish): sleep 0.5, 1, 2
                self.LOG.warn('Retrying on HTTP connection exception: %s', e)
                time.sleep(2.0 ** retry / 2)
                retry += 1

        return response

    def _json_request(self, method, path, body=None, additional_headers=None):
        """HTTP request helper used to make json requests.

        :param method: http method
        :param path: relative request url
        :param body: dict to encode to json as request body. Optional.
        :param additional_headers: dict of additional headers to send with
                                   http request. Optional.
        :return (http response object, response body parsed as json)
        :raise ServerError when unable to communicate with keystone
		
        """

        kwargs = {
            'headers': {
                'Content-type': 'application/json',
                'Accept': 'application/json',
                },
            }

        if additional_headers:
            kwargs['headers'].update(additional_headers)

        if body:
            kwargs['data'] = jsonutils.dumps(body)

        self.LOG.debug("REQUEST DEBUG:\nmethod: %s\npath:%s\n**kwargs:%s" % (method, path, kwargs))

        response = self._http_request(method, path, **kwargs)

        self.LOG.debug("RESPONSE DEBUG: %s" % (response.text, ))

        try:
            data = jsonutils.loads(response.text)
        except ValueError:
            self.LOG.debug('Keystone did not return json-encoded body')
            data = {}

        return response, data

    def _request_admin_token(self, admin_tenant_name=None):
        """Retrieve new token as admin user from keystone.

        :return token id upon success
        :raises ServerError when unable to communicate with keystone

        Irrespective of the auth version we are going to use for the
        user token, for simplicity we always use a v2 admin token to
        validate the user token.

        """
        tenant_name = admin_tenant_name if admin_tenant_name is not None else self.admin_tenant_name
        params = {
            'auth': {
                'passwordCredentials': {
                    'username': self.admin_user,
                    'password': self.admin_password,
                    },
                'tenantName': tenant_name,
                }
        }

        response, data = self._json_request('POST',
                                            '/v2.0/tokens',
                                            body=params)

        try:
            token = data['access']['token']['id']
            expiry = data['access']['token']['expires']
            if not (token and expiry):
                raise AssertionError('invalid token or expire')
            datetime_expiry = timeutils.parse_isotime(expiry)
            return token, timeutils.normalize_time(datetime_expiry), data, data['access']['token']['tenant']
        except (AssertionError, KeyError):
            self.LOG.warn(
                'Unexpected response from keystone service: %s', data)
            raise ServiceError('invalid json response')
        except ValueError:
            data['access']['token']['id'] = '<SANITIZED>'
            self.LOG.warn(
                'Unable to parse expiration time from token: %s', data)
            raise ServiceError('invalid json response')

    def _build_user_headers(self, token_info):
        """Convert token object into headers.

        Build headers that represent authenticated user - see main
        doc info at start of file for details of headers to be defined.

        :param token_info: token object returned by keystone on authentication
        :raise InvalidUserToken when unable to parse token object

        """
        auth_ref = access.AccessInfo.factory(body=token_info)
        roles = ','.join(auth_ref.role_names)

        if _token_is_v2(token_info) and not auth_ref.project_id:
            raise InvalidUserToken('Unable to determine tenancy.')

        rval = {
            'X-Identity-Status': 'Confirmed',
            'X-Domain-Id': auth_ref.domain_id,
            'X-Domain-Name': auth_ref.domain_name,
            'X-Project-Id': auth_ref.project_id,
            'X-Project-Name': auth_ref.project_name,
            'X-Project-Domain-Id': auth_ref.project_domain_id,
            'X-Project-Domain-Name': auth_ref.project_domain_name,
            'X-User-Id': auth_ref.user_id,
            'X-User-Name': auth_ref.username,
            'X-User-Domain-Id': auth_ref.user_domain_id,
            'X-User-Domain-Name': auth_ref.user_domain_name,
            'X-Roles': roles,
            # Deprecated
            'X-User': auth_ref.username,
            'X-Tenant-Id': auth_ref.project_id,
            'X-Tenant-Name': auth_ref.project_name,
            'X-Tenant': auth_ref.project_name,
            'X-Role': roles,
            }

        if self.include_service_catalog and auth_ref.has_service_catalog():
            catalog = auth_ref.service_catalog.get_data()
            if _token_is_v3(token_info):
                catalog = _v3_to_v2_catalog(catalog)
            rval['X-Service-Catalog'] = jsonutils.dumps(catalog)

        return rval

    def _header_to_env_var(self, key):
        """Convert header to wsgi env variable.

        :param key: http header name (ex. 'X-Auth-Token')
        :return wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')

        """
        return 'HTTP_%s' % key.replace('-', '_').upper()

    def _add_headers(self, env, headers):
        """Add http headers to environment."""
        if headers is not None:
            for (k, v) in six.iteritems(headers):
                env_key = self._header_to_env_var(k)
                if env_key not in env:
                    env[env_key] = v

    def _get_header(self, env, key, default=None):
        """Get http header from environment."""
        env_key = self._header_to_env_var(key)
        return env.get(env_key, default)

    def verify_signing_dir(self):
        if os.path.exists(self.signing_dirname):
            if not os.access(self.signing_dirname, os.W_OK):
                raise ConfigurationError(
                    'unable to access signing_dir %s' % self.signing_dirname)
            uid = os.getuid()
            if os.stat(self.signing_dirname).st_uid != uid:
                self.LOG.warning(
                    'signing_dir is not owned by %s', uid)
            current_mode = stat.S_IMODE(os.stat(self.signing_dirname).st_mode)
            if current_mode != stat.S_IRWXU:
                self.LOG.warning(
                    'signing_dir mode is %s instead of %s',
                    oct(current_mode), oct(stat.S_IRWXU))
        else:
            os.makedirs(self.signing_dirname, stat.S_IRWXU)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthProtocol(app, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AuthProtocol(None, conf)


if __name__ == '__main__':
    """Run this module directly to start a protected echo service::

        $ python -m keystoneclient.middleware.auth_token

    When the ``auth_token`` module authenticates a request, the echo service
    will respond with all the environment variables presented to it by this
    module.

    """
    def echo_app(environ, start_response):
        """A WSGI application that echoes the CGI environment to the user."""
        start_response('200 OK', [('Content-Type', 'application/json')])
        environment = dict((k, v) for k, v in six.iteritems(environ)
                           if k.startswith('HTTP_X_'))
        yield jsonutils.dumps(environment)

    from wsgiref import simple_server

    # hardcode any non-default configuration here
    conf = {'auth_protocol': 'http', 'admin_token': 'ADMIN'}
    app = AuthProtocol(echo_app, conf)
    server = simple_server.make_server('', 8000, app)
    print('Serving on port 8000 (Ctrl+C to end)...')
    server.serve_forever()