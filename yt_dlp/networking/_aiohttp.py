#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Author  : side.wang
@File    : _aiohttp.py
@Time    : 2024/2/7 13:59
@Description :  用于 yt-dlp 的自定义异步请求处理器
"""
import aiohttp
import contextlib
import io
import logging
import warnings
import http.client

from .common import Features, RequestHandler, Response, register_preference
from ._requests import Urllib3PercentREOverride, urllib3_version, Urllib3LoggingHandler, Urllib3LoggingFilter
from ..utils import variadic
from ..dependencies import requests, urllib3
from ..networking._helper import add_accept_encoding_header, InstanceStoreMixin, select_proxy
from ..networking.common import register_rh, Request
from ..networking.exceptions import CertificateVerifyError, ProxyError, TransportError, RequestError, HTTPError, \
    SSLError, IncompleteRead
from ..utils import bug_reports_message

SUPPORTED_ENCODINGS = [
    'gzip', 'deflate'
]


"""
Override urllib3's behavior to not convert lower-case percent-encoded characters
to upper-case during url normalization process.

RFC3986 defines that the lower or upper case percent-encoded hexidecimal characters are equivalent
and normalizers should convert them to uppercase for consistency [1].

However, some sites may have an incorrect implementation where they provide
a percent-encoded url that is then compared case-sensitively.[2]

While this is a very rare case, since urllib does not do this normalization step, it
is best to avoid it in requests too for compatability reasons.

1: https://tools.ietf.org/html/rfc3986#section-2.1
2: https://github.com/streamlink/streamlink/pull/4003
"""



# urllib3 >= 1.25.8 uses subn:
# https://github.com/urllib3/urllib3/commit/a2697e7c6b275f05879b60f593c5854a816489f0
import urllib3.util.url  # noqa: E305

if hasattr(urllib3.util.url, 'PERCENT_RE'):
    urllib3.util.url.PERCENT_RE = Urllib3PercentREOverride(urllib3.util.url.PERCENT_RE)
elif hasattr(urllib3.util.url, '_PERCENT_RE'):  # urllib3 >= 2.0.0
    urllib3.util.url._PERCENT_RE = Urllib3PercentREOverride(urllib3.util.url._PERCENT_RE)
else:
    warnings.warn('Failed to patch PERCENT_RE in urllib3 (does the attribute exist?)' + bug_reports_message())


"""
Workaround for issue in urllib.util.ssl_.py: ssl_wrap_context does not pass
server_hostname to SSLContext.wrap_socket if server_hostname is an IP,
however this is an issue because we set check_hostname to True in our SSLContext.

Monkey-patching IS_SECURETRANSPORT forces ssl_wrap_context to pass server_hostname regardless.

This has been fixed in urllib3 2.0+.
See: https://github.com/urllib3/urllib3/issues/517
"""

if urllib3_version < (1, 26, 17):
    raise ImportError('Only urllib3 >= 1.26.17 is supported')

if urllib3_version < (2, 0, 0):
    with contextlib.suppress():
        urllib3.util.IS_SECURETRANSPORT = urllib3.util.ssl_.IS_SECURETRANSPORT = True


# Requests will not automatically handle no_proxy by default
# due to buggy no_proxy handling with proxy dict [1].
# 1. https://github.com/psf/requests/issues/5000
requests.adapters.select_proxy = select_proxy


class RequestsResponseAdapter(Response):
    def __init__(self, res: aiohttp.ClientResponse, res_content: bytes):
        super().__init__(
            fp=io.BytesIO(res_content), headers=res.headers, url=str(res.url),
            status=res.status, reason=res.reason)

        self._requests_response = res

    def read(self, amt: int = None):
        try:
            # Interact with urllib3 response directly.
            return self.fp.read(amt)

        # See urllib3.response.HTTPResponse.read() for exceptions raised on read
        except urllib3.exceptions.SSLError as e:
            raise SSLError(cause=e) from e

        except urllib3.exceptions.ProtocolError as e:
            # IncompleteRead is always contained within ProtocolError
            # See urllib3.response.HTTPResponse._error_catcher()
            ir_err = next(
                (err for err in (e.__context__, e.__cause__, *variadic(e.args))
                 if isinstance(err, http.client.IncompleteRead)), None)
            if ir_err is not None:
                # `urllib3.exceptions.IncompleteRead` is subclass of `http.client.IncompleteRead`
                # but uses an `int` for its `partial` property.
                partial = ir_err.partial if isinstance(ir_err.partial, int) else len(ir_err.partial)
                raise IncompleteRead(partial=partial, expected=ir_err.expected) from e
            raise TransportError(cause=e) from e

        except urllib3.exceptions.HTTPError as e:
            # catch-all for any other urllib3 response exceptions
            raise TransportError(cause=e) from e


@register_rh
class AiohttpRH(RequestHandler, InstanceStoreMixin):
    _SUPPORTED_URL_SCHEMES = ('http', 'https')
    _SUPPORTED_ENCODINGS = tuple(SUPPORTED_ENCODINGS)
    _SUPPORTED_PROXY_SCHEMES = ('http', 'https', 'socks4', 'socks4a', 'socks5', 'socks5h')
    _SUPPORTED_FEATURES = (Features.NO_PROXY, Features.ALL_PROXY)
    RH_NAME = 'aiohttp'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Forward urllib3 debug messages to our logger
        logger = logging.getLogger('urllib3')
        self.__logging_handler = Urllib3LoggingHandler(logger=self._logger)
        self.__logging_handler.setFormatter(logging.Formatter('aiohttp: %(message)s'))
        self.__logging_handler.addFilter(Urllib3LoggingFilter())
        logger.addHandler(self.__logging_handler)
        # TODO: Use a logger filter to suppress pool reuse warning instead
        logger.setLevel(logging.ERROR)

        if self.verbose:
            # Setting this globally is not ideal, but is easier than hacking with urllib3.
            # It could technically be problematic for scripts embedding yt-dlp.
            # However, it is unlikely debug traffic is used in that context in a way this will cause problems.
            urllib3.connection.HTTPConnection.debuglevel = 1
            logger.setLevel(logging.DEBUG)
        # this is expected if we are using --no-check-certificate
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _check_extensions(self, extensions):
        super()._check_extensions(extensions)
        extensions.pop('cookiejar', None)
        extensions.pop('timeout', None)

    async def _create_instance(self, cookiejar):
        connector = aiohttp.TCPConnector(ssl_context=self._make_sslcontext())
        return aiohttp.ClientSession(connector=connector, cookies=cookiejar._cookies, trust_env=False,
                                     headers=requests.models.CaseInsensitiveDict({'Connection': 'keep-alive'}))

    async def _send(self, request: Request):
        headers = self._merge_headers(request.headers)
        add_accept_encoding_header(headers, SUPPORTED_ENCODINGS)

        max_redirects_exceeded = False

        try:
            session: aiohttp.ClientSession = await self._get_instance(cookiejar=request.extensions.get('cookiejar') or self.cookiejar)
            async with session.request(method=request.method, url=request.url, data=request.data, headers=headers,
                                       timeout=float(request.extensions.get('timeout') or self.timeout),
                                       proxy=list((request.proxies or self.proxies).values())[0]) as requests_res:
                res_content = await requests_res.read()
                res = RequestsResponseAdapter(requests_res, res_content)
        except aiohttp.TooManyRedirects as e:
            max_redirects_exceeded = True
            res = e

        except aiohttp.ClientSSLError as e:
            if 'CERTIFICATE_VERIFY_FAILED' in str(e):
                raise CertificateVerifyError(cause=e) from e
            raise SSLError(cause=e) from e

        except (aiohttp.ClientHttpProxyError, aiohttp.ClientProxyConnectionError) as e:
            raise ProxyError(cause=e) from e

        except (aiohttp.ClientConnectionError, aiohttp.ClientTimeout) as e:
            raise TransportError(cause=e) from e

        except (aiohttp.ClientPayloadError, aiohttp.ClientError) as e:
            # Catch any urllib3 exceptions that may leak through
            raise RequestError(cause=e) from e

        except Exception as e:
            raise e

        if not 200 <= res.status < 300:
            raise HTTPError(res, redirect_loop=max_redirects_exceeded)
        return res

    def close(self):
        self._clear_instances()
        # Remove the logging handler that contains a reference to our logger
        # See: https://github.com/yt-dlp/yt-dlp/issues/8922
        logging.getLogger('urllib3').removeHandler(self.__logging_handler)


@register_preference(AiohttpRH)
def requests_preference(rh, request):
    return 50
