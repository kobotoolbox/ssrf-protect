# coding: utf-8
from __future__ import absolute_import, unicode_literals


class SSRFProtectException(Exception):
    """
    Basic exception to be raised when a URL is not allowed.
    """
