# flake8: noqa: F401
import warnings

from .common import (
    HEADRequest,
    PUTRequest,
    Request,
    RequestDirector,
    RequestHandler,
    Response,
)

# isort: split
# TODO: all request handlers should be safely imported
from . import _urllib
from ..utils import bug_reports_message

try:
    from . import _requests
except ImportError as e:
    warnings.warn(f'Failed to import "requests" request handler: {e}')
except Exception as e:
    warnings.warn(f'Failed to import "requests" request handler: {e}' + bug_reports_message())

try:
    from . import _aiohttp
except ImportError as e:
    warnings.warn(f'Failed to import "aiohttp" request handler: {e}')
except Exception as e:
    warnings.warn(f'Failed to import "aiohttp" request handler: {e}' + bug_reports_message())

try:
    from . import _websockets
except ImportError as e:
    warnings.warn(f'Failed to import "websockets" request handler: {e}')
except Exception as e:
    warnings.warn(f'Failed to import "websockets" request handler: {e}' + bug_reports_message())
