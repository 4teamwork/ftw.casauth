from plone.app.testing import FunctionalTesting
from plone.app.testing import IntegrationTesting
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import PloneSandboxLayer
from plone.testing import z2
from zope.configuration import xmlconfig
from ftw.casauth.plugin import CASAuthenticationPlugin


class FtwCasauthLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        # Load ZCML
        import ftw.casauth
        xmlconfig.file(
            'configure.zcml',
            ftw.casauth,
            context=configurationContext
        )
        z2.installProduct(app, 'ftw.casauth')

    def setUpPloneSite(self, portal):

        # Setup PAS plugin
        uf = portal.acl_users
        plugin = CASAuthenticationPlugin(
            'cas_auth', cas_server_url='https://cas.domain.net')
        uf._setObject(plugin.getId(), plugin)
        plugin = uf['cas_auth']
        plugin.manage_activateInterfaces([
            'IAuthenticationPlugin',
            'IChallengePlugin',
            'IExtractionPlugin',
        ])
        self['plugin'] = plugin

FTW_CASAUTH_FIXTURE = FtwCasauthLayer()
FTW_CASAUTH_INTEGRATION_TESTING = IntegrationTesting(
    bases=(FTW_CASAUTH_FIXTURE,),
    name="FtwcasauthLayer:Integration"
)
FTW_CASAUTH_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FTW_CASAUTH_FIXTURE, z2.ZSERVER_FIXTURE),
    name="FtwcasauthLayer:Functional"
)
