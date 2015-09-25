from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from ftw.casauth import plugin


def initialize(context):
    """Initializer called when used as a Zope 2 product."""
    registerMultiPlugin(plugin.CASAuthenticationPlugin.meta_type)
    context.registerClass(
        plugin.CASAuthenticationPlugin,
        permission=add_user_folders,
        constructors=(plugin.manage_addCASAuthenticationPlugin,
                      plugin.addCASAuthenticationPlugin),
        visibility=None,
    )
