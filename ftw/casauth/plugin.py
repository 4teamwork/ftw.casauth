from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.requestmethod import postonly
from Products.CMFCore.permissions import ManagePortal
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from zope.interface import implements
from ftw.casauth.cas import validate_ticket
import urllib


manage_addCASAuthenticationPlugin = PageTemplateFile(
    "www/addPlugin", globals(), __name__="manage_addCASAuthenticationPlugin")


def addCASAuthenticationPlugin(self, id_, title='', REQUEST=None):
    """Add a CAS authentication plugin
    """
    plugin = CASAuthenticationPlugin(id_, title)
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
        self.cas_server_url = cas_server_url

    security.declarePrivate('challenge')

    # Initiate a challenge to the user to provide credentials.
    def challenge(self, request, response, **kw):
        if 'ticket' in request.form:
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
        return url
