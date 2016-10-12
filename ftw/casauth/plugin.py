from AccessControl.requestmethod import postonly
from AccessControl.SecurityInfo import ClassSecurityInfo
from collections import OrderedDict
from ftw.casauth.cas import validate_ticket
from Products.CMFCore.permissions import ManagePortal
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from urllib import urlencode
from urlparse import parse_qsl
from urlparse import urlsplit
from urlparse import urlunsplit
from zope.interface import implements
import urllib


manage_addCASAuthenticationPlugin = PageTemplateFile(
    "www/addPlugin", globals(), __name__="manage_addCASAuthenticationPlugin")


def addCASAuthenticationPlugin(self, id_, title=None, cas_server_url=None,
                               REQUEST=None):
    """Add a CAS authentication plugin
    """
    plugin = CASAuthenticationPlugin(id_, title, cas_server_url)
    self._setObject(plugin.getId(), plugin)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect(
            "%s/manage_workspace"
            "?manage_tabs_message=CAS+authentication+plugin+added." %
            self.absolute_url()
        )


class CASAuthenticationPlugin(BasePlugin):
    """Plone PAS plugin for authentication against a CAS server.
    """
    implements(
        IAuthenticationPlugin,
        IChallengePlugin,
        IExtractionPlugin,
    )
    meta_type = "CAS Authentication Plugin"
    security = ClassSecurityInfo()

    # ZMI tab for configuration page
    manage_options = (
        ({'label': 'Configuration',
          'action': 'manage_config'},)
        + BasePlugin.manage_options
    )
    security.declareProtected(ManagePortal, 'manage_config')
    manage_config = PageTemplateFile('www/config', globals(),
                                     __name__='manage_config')

    def __init__(self, id_, title=None, cas_server_url=None):
        self._setId(id_)
        self.title = title
        if cas_server_url:
            cas_server_url = cas_server_url.rstrip('/')
        self.cas_server_url = cas_server_url

    security.declarePrivate('challenge')

    # Initiate a challenge to the user to provide credentials.
    def challenge(self, request, response, **kw):
        if 'ticket' in request.form:
            return False

        if not self.cas_server_url:
            return False

        response.redirect('%s/login?service=%s' % (
            self.cas_server_url,
            urllib.quote(self._service_url(request)),
        ), lock=True)
        return True

    security.declarePrivate('extractCredentials')

    # IExtractionPlugin implementation
    # Extracts a CAS service ticket from the request.
    def extractCredentials(self, request):
        if 'ticket' not in request.form:
            return None

        creds = {}
        creds['ticket'] = request.form.get('ticket')
        creds['service_url'] = self._service_url(request)

        # Avoid having the `ticket` query string param show up in the
        # user's browser's address bar by redirecting back to the
        # service_url, which should have the ticket stripped from it
        request.RESPONSE.redirect(creds['service_url'], lock=True)

        return creds

    security.declarePrivate('authenticateCredentials')

    # IAuthenticationPlugin implementation
    def authenticateCredentials(self, credentials):
        # Ignore credentials that are not from our extractor
        extractor = credentials.get('extractor')
        if extractor != self.getId():
            return None

        userid = validate_ticket(
            credentials['ticket'],
            self.cas_server_url,
            credentials['service_url'],
        )
        if not userid:
            return None

        pas = self._getPAS()
        info = pas._verifyUser(pas.plugins, user_id=userid)
        if info is None:
            return None
        pas.updateCredentials(self.REQUEST, self.REQUEST.RESPONSE, userid, '')

        return userid, userid

    security.declareProtected(ManagePortal, 'manage_updateConfig')

    @postonly
    def manage_updateConfig(self, REQUEST):
        """Update configuration of CAS Authentication Plugin.
        """
        response = REQUEST.response

        self.cas_server_url = REQUEST.form.get('cas_server_url', '').rstrip('/')

        response.redirect('%s/manage_config?manage_tabs_message=%s' %
                          (self.absolute_url(), 'Configuration+updated.'))

    def _service_url(self, request):
        url = request['ACTUAL_URL']
        if request['QUERY_STRING']:
            url = '%s?%s' % (url, request['QUERY_STRING'])
            url = self._strip_ticket(url)
        return url

    def _strip_ticket(self, url):
        """Drop the `ticket` query string parameter from a given URL,
        but preserve everything else.
        """
        scheme, netloc, path, query, fragment = urlsplit(url)
        # Using OrderedDict and parse_qsl here to preserve order
        qs_params = OrderedDict(parse_qsl(query))
        qs_params.pop('ticket', None)
        query = urlencode(qs_params)
        new_url = urlunsplit((scheme, netloc, path, query, fragment))
        return new_url
