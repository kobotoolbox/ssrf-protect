# coding: utf-8
from __future__ import absolute_import, unicode_literals

from ipaddress import ip_address


class MockSSRFProtect(object):

    @staticmethod
    def _get_ip_address(url):
        return ip_address('1.2.3.4')



