# coding: utf-8
import socket
from typing import Union, Dict
from urllib.parse import urlparse

from ipaddress import ip_address, IPv4Address, IPv6Address

from .exceptions import SSRFProtectException


class SSRFProtect:
    """
    This class exposes only one static method which validates URLs

    Inspired by https://github.com/robinhood/thorn/blob/master/thorn/validators.py
    and https://www.npmjs.com/package/request-filtering-agent
    """
    def __init__(self):
        pass

    @staticmethod
    def __is_internal_address(
        ip_address_: Union[IPv4Address, IPv6Address]
    ) -> bool:
        return any([
            ip_address_.is_private,
            ip_address_.is_reserved,
            ip_address_.is_loopback,
            ip_address_.is_multicast,
            ip_address_.is_link_local,
        ])

    @staticmethod
    def _get_ip_address(url: str) -> Union[IPv4Address, IPv6Address]:
        try:
            return ip_address(url)
        except ValueError:
            try:
                host = urlparse(url).hostname
                return ip_address(str(socket.gethostbyname(host)))
            except AttributeError:
                # `urlparse` receives an invalid parameter
                raise SSRFProtectException(
                    'Invalid URL `{url}`'.format(url=url))
            except (ValueError, TypeError, socket.gaierror):
                # `TypeError`, `socket.gaierror: `socket.gethostbyname` receives an invalid parameter
                # `ValueError`: `ip_address` receives an invalid parameter
                raise SSRFProtectException(
                    'Cannot resolve IP address for `{host}`'.format(host=host))

    @classmethod
    def validate(cls, url: str, options: Dict = {}):
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
        if (
            len(denied_ip_addresses) > 0
            and str(ip_address_) in denied_ip_addresses
        ):
            raise SSRFProtectException('URL {url} is not allowed because it resolves '
                                       'to a denied IP address'.format(url=url))

        allowed_ip_addresses = options.get('allowed_ip_addresses', [])
        if (
            len(allowed_ip_addresses) > 0
            and str(ip_address_) in allowed_ip_addresses
        ):
            return

        if cls.__is_internal_address(ip_address_):
            raise SSRFProtectException('URL {url} is not allowed because it resolves '
                                       'to a private IP address'.format(url=url))

        return
