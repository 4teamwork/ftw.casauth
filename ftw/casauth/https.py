"""SSL server certificate verification for `urllib2`.

Python's built-in HTTPS support does not verify certificates.
Thus we provide our own HTTPSHandler which *does* certificate validation.

Example usage::

    >>> opener = urllib2.build_opener(HTTPSHandler)
    >>> opener.open('https://example.com/').read()

"""
from backports.ssl_match_hostname import match_hostname, CertificateError
import httplib
import os
import socket
import ssl
import sys
import urllib2

CERT_FILE = os.path.join(os.path.dirname(__file__), 'cacert.pem')


if not hasattr(socket, 'create_connection'):  # for Python 2.4
    _GLOBAL_DEFAULT_TIMEOUT = getattr(socket,
                                      '_GLOBAL_DEFAULT_TIMEOUT', object())

    # copy-paste from stdlib's socket.py (py2.6)
    def create_connection(address, timeout=_GLOBAL_DEFAULT_TIMEOUT,
                          source_address=None):
        """Connect to *address* and return the socket object.

        Convenience function.  Connect to *address* (a 2-tuple ``(host,
        port)``) and return the socket object.  Passing the optional
        *timeout* parameter will set the timeout on the socket instance
        before attempting to connect.  If no *timeout* is supplied, the
        global default timeout setting returned by :func:`getdefaulttimeout`
        is used.
        """

        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock

            except socket.error:
                err = sys.exc_info()[1]
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        else:
            raise socket.error("getaddrinfo returns an empty list")

    # monkey-patch socket module
    socket.create_connection = create_connection


class HTTPSConnection(httplib.HTTPConnection):
    "This class allows communication via SSL."

    default_port = httplib.HTTPS_PORT

    def connect(self):
        "Connect to a host on a given (SSL) port."

        if not getattr(self, 'timeout', None):
            self.timeout = socket.getdefaulttimeout()

        args = [(self.host, self.port), self.timeout]
        if hasattr(self, 'source_address'):
            args.append(self.source_address)
        sock = socket.create_connection(*args)

        if getattr(self, '_tunnel_host', None):
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock,
                                    ssl_version=ssl.PROTOCOL_TLSv1,
                                    ca_certs=CERT_FILE,
                                    cert_reqs=ssl.CERT_REQUIRED)
        try:
            match_hostname(self.sock.getpeercert(), self.host)
        except CertificateError:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            raise


class HTTPSHandler(urllib2.HTTPSHandler):

    def https_open(self, req):
            return self.do_open(HTTPSConnection, req)
