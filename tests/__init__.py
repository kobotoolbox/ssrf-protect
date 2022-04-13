# coding: utf-8
from ipaddress import ip_address


class MockSSRFProtect:

    @staticmethod
    def _get_ip_address(url):
        return ip_address('1.2.3.4')
