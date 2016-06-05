import re
import logging

from twisted.internet import reactor as twisted_reactor, defer, protocol
from ldaptor.protocols.ldap import ldapclient, ldapconnector, ldapsyntax
from ldaptor.protocols.ldap import distinguishedname

try:
    from twisted.internet.utils import SRVConnector
except ImportError:
    from twisted.names.srvconnect import SRVConnector

from hashlib import md5, sha1

from mudsling.errors import Error as Error
from mudsling.objects import BasePlayer
from mudsling.extensibility import Plugin

logger = logging.getLogger('LDAP')
logger.info('Loading LDAP...')

#: :type: LDAPServer
server = None


class LDAPAuthPlugin(Plugin):
    def server_startup(self):
        global server
        server = LDAPServer(self.options)


class LDAPConnector(ldapconnector.LDAPConnector):
    """
    Override ldaptor's LDAPConnector in order to control timeouts.
    """
    def __init__(self, reactor, dn, factory,
                 overrides=None, bind_address=None, timeout=5):
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn = distinguishedname.DistinguishedName(stringValue=dn)
        if overrides is None:
            overrides = {}
        self.override = self._findOverRide(dn, overrides)
        domain = dn.getDomainName()
        SRVConnector.__init__(self, reactor,
                              'ldap', domain, factory,
                              connectFuncKwArgs={'bindAddress': bind_address,
                                                 'timeout': timeout})


class LDAPClientCreator(ldapconnector.LDAPClientCreator):
    """
    Override ldaptor's LDAPClientCreator in order to control timeouts.
    """
    # noinspection PyPep8Naming
    def connect(self, dn, overrides=None, bindAddress=None, timeout=5):
        d = defer.Deferred()
        # noinspection PyProtectedMember
        f = protocol._InstanceFactory(
            self.reactor, self.protocolClass(*self.args, **self.kwargs), d)
        c = LDAPConnector(self.reactor, dn, f, overrides=overrides,
                          bind_address=bindAddress, timeout=timeout)
        c.connect()
        return d


class LDAPServer(object):
    def __init__(self, config):
        self.config = config
        self.creator = LDAPClientCreator(twisted_reactor, ldapclient.LDAPClient)
        self.overrides = {config['base dn']: (config['server'],
                                              config['port'])}

    @defer.inlineCallbacks
    def _bind(self):
        timeout = self.config.getfloat('timeout')
        client = yield self.creator.connect(self.config['base dn'],
                                            overrides=self.overrides,
                                            timeout=timeout)
        if self.config.getboolean('tls'):
            client = yield client.startTLS()
        o = ldapsyntax.LDAPEntry(client, self.config['bind dn'])
        yield o.bind(self.config['bind pw'])
        defer.returnValue(client)

    @staticmethod
    def _disconnect(client):
        # noinspection PyBroadException
        try:
            client.unbind()
        except Exception:
            client.transport.loseConnection()

    @defer.inlineCallbacks
    def search(self, searchdn, search_filter='(objectClass=*)', attributes=None,
               callback=None):
        client = yield self._bind()
        o = ldapsyntax.LDAPEntry(client, searchdn)
        results = yield o.search(filterText=search_filter,
                                 attributes=attributes)
        self._disconnect(client)
        if callback is not None:
            callback(results)
        defer.returnValue(results)

    def get_user(self, uuid, callback=None):
        search_filter = '(%s=%s)' % (self.config['unique attr'], uuid)
        return self.search(self.config['user base dn'],
                           search_filter=search_filter,
                           attributes=(self.config['password attr'],),
                           callback=callback)


pw_hash_re = re.compile(r"^(?:\{(?P<type>.*?)\})?(?P<hash>.*)$")


def password_verify_plain(stored, provided):
    return stored == provided


def password_verify_md5(stored, provided):
    return stored == md5(provided).digest().encode('base64').strip('\n')


def password_verify_sha(stored, provided):
    return stored == sha1(provided).digest().encode('base64').strip('\n')


def password_verify_ssha(stored, provided):
    digest = stored.decode('base64')
    hashed = digest[:20]
    salt = digest[20:]
    verify = sha1(provided + salt)
    return hashed == verify.digest()

pw_verify_map = {
    'plain': password_verify_plain,
    'md5': password_verify_md5,
    'sha': password_verify_sha,
    'ssha': password_verify_ssha
}


class LDAPError(Error):
    pass


class LDAPPlayer(BasePlayer):
    ldap_uuid = None

    def __init__(self, **kw):
        super(LDAPPlayer, self).__init__(**kw)
        if 'ldap_uuid' in kw and kw['ldap_uuid'] is not None:
            self.ldap_uuid = kw['ldap_uuid']

    def authenticate(self, password, session=None):
        try:
            authenticated = self.ldap_authenticate(password)
        except LDAPError:
            if self.superuser:
                # Super users may connect when LDAP is down, misconfigured, etc
                logger.warn('Attempt native password auth for superuser')
                return super(LDAPPlayer, self).authenticate(password, session)
            return False
        return authenticated

    def ldap_authenticate(self, password):
        if self.ldap_uuid is None:
            logger.warn('%s (%d) has no LDAP UUID' % (self.name, self.obj_id))
            raise LDAPError()

        #: :type: twisted.internet.defer.Deferred
        d = server.get_user(self.ldap_uuid)
        d.addCallback(self._ldap_auth, password)
        if self.superuser:
            d.addErrback(self._ldap_superuser_fallback, password)
        d.addErrback(self._ldap_fail)
        return d

    def _ldap_auth(self, results, password):
        if len(results) == 0:
            logger.warn('No LDAP user matches %s (%d) UUID: %s'
                        % (self.name, self.obj_id, self.ldap_uuid))
            raise LDAPError()
        if len(results) > 1:
            logger.warn('Multiple LDAP users match UUID: %s' % self.ldap_uuid)
            raise LDAPError()
        stored_pass = list(results[0]['userPassword'])[0]
        pass_type, pass_hash = pw_hash_re.match(stored_pass).groups()
        if pass_type is None:
            pass_type = 'plain'
        else:
            pass_type = pass_type.lower()
        if pass_type in pw_verify_map:
            return pw_verify_map[pass_type](pass_hash, password)
        else:
            logger.warn('Unsupported LDAP password hash method: %s' % pass_type)
            raise LDAPError()

    def _ldap_superuser_fallback(self, error, password):
        # Super users may connect when LDAP is down, misconfigured, etc
        logger.warn('Attempt native password auth for superuser')
        if super(LDAPPlayer, self).authenticate(password):
            self._ldap_fail(error)
            return True
        raise error

    @staticmethod
    def _ldap_fail(error):
        logger.error('LDAP Error: ' + str(error.value))
