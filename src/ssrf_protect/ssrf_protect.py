# coding: utf-8
from __future__ import absolute_import, unicode_literals

import socket
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from ipaddress import ip_address
from six import text_type

from .exceptions import SSRFProtectException


class SSRFProtect(object):
    """
    This class exposes only one static method which validates URLs

    Inspired by https://github.com/robinhood/thorn/blob/master/thorn/validators.py
    and https://www.npmjs.com/package/request-filtering-agent
    """
    def __init__(self):
        pass

    @staticmethod
    def __is_internal_address(ip_address_):
        return any([
            ip_address_.is_private,
            ip_address_.is_reserved,
            ip_address_.is_loopback,
            ip_address_.is_multicast,
            ip_address_.is_link_local,
        ])

    @staticmethod
    def _get_ip_address(url):
        try:
            return ip_address(text_type(url))
        except ValueError:
            try:
                host = urlparse(url).hostname
                return ip_address(text_type(socket.gethostbyname(host)))
            except AttributeError:
                # `urlparse` receives an invalid parameter
                raise SSRFProtectException(
                    'Invalid url `{url}`'.format(url=url))
            except (ValueError, TypeError, socket.gaierror):
                # `TypeError`, `socket.gaierror: `socket.gethostbyname` receives an invalid parameter
                # `ValueError`: `ip_address` receives an invalid parameter
                raise SSRFProtectException(
                    'Cannot resolve ip address for `{host}`'.format(host=host))

    @classmethod
    def validate(cls, url, options={}):
        """
        Validates if url resolves to a private IP address.

        Args:
            url (str)
            options (dict): it excepts these any of these 2 properties:
                - allowed_ip_addresses
                - denied_ip_addresses
                Both are `list` of IP addresses

        Returns:
            None if `url` is valid. Otherwise raise an `SSRFProtectException` exception
        """

        ip_address_ = cls._get_ip_address(url)
        denied_ip_addresses = options.get('denied_ip_addresses', [])
        if len(denied_ip_addresses) > 0 and \
                text_type(ip_address_) in denied_ip_addresses:
            raise SSRFProtectException('URL {url} is not allowed because it resolves '
                                       'to a denied ip address'.format(url=url))

        allowed_ip_addresses = options.get('allowed_ip_addresses', [])
        if len(allowed_ip_addresses) > 0 and \
                text_type(ip_address_) in allowed_ip_addresses:
            return

        if cls.__is_internal_address(ip_address_):
            raise SSRFProtectException('URL {url} is not allowed because it resolves '
                                       'to a private IP address'.format(url=url))

        return
