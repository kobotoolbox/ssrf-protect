# coding: utf-8
import socket
from urllib.parse import urlparse

from ipaddress import ip_address

from .exceptions import SSRFProtectException


class SSRFProtect:

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
            return ip_address(str(url))
        except ValueError:
            host = urlparse(url).hostname
            return ip_address(str(socket.gethostbyname(host)))

    @classmethod
    def validate(cls, url, options={}):

        ip_address_ = cls._get_ip_address(url)
        allowed_ip_addresses = options.get('allowed_ip_addresses', [])
        if len(allowed_ip_addresses) > 0 and \
            str(ip_address_) in allowed_ip_addresses:
            return

        if cls.__is_internal_address(ip_address_):
            raise SSRFProtectException(f'URL {url} is not allowed because it resolves '
                                       'to a private IP address')

        denied_ip_addresses = options.get('denied_ip_addresses', [])
        if len(denied_ip_addresses) > 0 and \
                str(ip_address_) in denied_ip_addresses:
            raise SSRFProtectException(f'URL {url} is not allowed because it resolves '
                                       'to a denied ip address')

        return