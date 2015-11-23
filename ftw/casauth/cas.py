from ftw.casauth.config import USE_CUSTOM_HTTPS_HANDLER
import urllib
import urllib2
from logging import getLogger
from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError

if USE_CUSTOM_HTTPS_HANDLER:
    from ftw.casauth.https import HTTPSHandler
else:
    from urllib2 import HTTPSHandler

CAS_NS = "http://www.yale.edu/tp/cas"

logger = getLogger('ftw.casauth')


def validate_ticket(ticket, cas_server_url, service_url):
    """Validates a CAS service ticket and returns the authenticated userid.
    """
    validate_url = '%s/serviceValidate?service=%s&ticket=%s' % (
        cas_server_url,
        urllib.quote(service_url),
        ticket,
    )

    opener = urllib2.build_opener(HTTPSHandler)
    try:
        resp = opener.open(validate_url)
    except urllib2.HTTPError as e:
        logger.warning("Ticket validation failed. Could not open url %s. "
                       "Staus code: %s, reason: %s" % (validate_url, e.code,
                                                       e.reason))
        return False
    except urllib2.URLError as e:
        logger.warning("Ticket validation failed. Could not open url %s. "
                       "Reason: %s" % (validate_url, e.reason))
        return False
    except ValueError as e:  # backports.ssl_match_hostname CertificateError
        logger.warning("Ticket validation failed. Could not open url %s. "
                       "CertificateError: %s" % (validate_url, e.message))
        return False

    resp_data = resp.read()
    try:
        doc = parseString(resp_data)
    except ExpatError:
        return False
    auth_success = doc.getElementsByTagNameNS(CAS_NS,
                                              'authenticationSuccess')
    if not auth_success:
        auth_fail = doc.getElementsByTagNameNS(CAS_NS,
                                               'authenticationFailure')
        if auth_fail:
            logger.info(
                "Authentication failed: Service ticket validation returned"
                " '%s'." % auth_fail[0].getAttribute('code'))
        else:
            logger.info("Authentication failed: Could not validate service"
                        " ticket.")
        return False

    userid = auth_success[0].getElementsByTagNameNS(CAS_NS, 'user')
    if not userid:
        return False
    userid = userid[0].firstChild.data

    return userid
