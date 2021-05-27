from AccessControl.requestmethod import postonly
from AccessControl.SecurityInfo import ClassSecurityInfo
from DateTime import DateTime
from ftw.casauth.cas import service_url
from ftw.casauth.cas import validate_ticket
from Products.CMFCore.permissions import ManagePortal
from Products.CMFCore.utils import getToolByName
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PlonePAS.events import UserInitialLoginInEvent
from Products.PlonePAS.events import UserLoggedInEvent
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin  # noqa
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from zope.component.hooks import getSite
from zope.event import notify
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
            urllib.quote(service_url(request)),
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
        creds['service_url'] = service_url(request)

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

        result = self.login_user(userid)
        if not result:
            return None

        return userid, userid

    def handle_login(self, userid):
        pas = self._getPAS()
        info = pas._verifyUser(pas.plugins, user_id=userid)
        if info is None:
            return None

        mtool = getToolByName(getSite(), 'portal_membership')
        member = mtool.getMemberById(userid)
        if member is None:
            return None

        first_login = self.set_login_times(member)
        self.fire_login_events(first_login, member)
        self.expire_clipboard()
        mtool.createMemberArea(member_id=userid)
        return member

    def login_user(self, userid):
        member = self.handle_login(userid)
        if not member:
            return None
        pas = self._getPAS()
        pas.updateCredentials(
            self.REQUEST, self.REQUEST.RESPONSE, member.getUserName(), '')
        return member

    def set_login_times(self, member):
        # The return value indicates if this is the first logged login time.

        first_login = False
        default = DateTime('2000/01/01')

        login_time = member.getProperty('login_time', default)
        if login_time == default:
            first_login = True
            login_time = DateTime()

        mtool = getToolByName(getSite(), 'portal_membership')
        member.setMemberProperties(dict(
            login_time=mtool.ZopeTime(),
            last_login_time=login_time))

        return first_login

    def fire_login_events(self, first_login, user):
        if first_login:
            notify(UserInitialLoginInEvent(user))
        else:
            notify(UserLoggedInEvent(user))

    def expire_clipboard(self):
        if self.REQUEST.get('__cp', None) is not None:
            self.REQUEST.RESPONSE.expireCookie('__cp', path='/')

    security.declareProtected(ManagePortal, 'manage_updateConfig')

    @postonly
    def manage_updateConfig(self, REQUEST):
        """Update configuration of CAS Authentication Plugin.
        """
        response = REQUEST.response

        self.cas_server_url = REQUEST.form.get('cas_server_url', '').rstrip('/')

        response.redirect('%s/manage_config?manage_tabs_message=%s' %
                          (self.absolute_url(), 'Configuration+updated.'))
