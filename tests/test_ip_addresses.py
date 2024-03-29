# coding: utf-8
import pytest
from mock import patch

from ssrf_protect.ssrf_protect import SSRFProtect
from ssrf_protect.exceptions import SSRFProtectException

from . import MockSSRFProtect


def test_no_options():
    url = 'http://127.0.0.1/test'

    with pytest.raises(SSRFProtectException) as excinfo:
        SSRFProtect.validate(url)

    assert 'URL {url} is not allowed because it resolves to ' \
           'a private IP address'.format(url=url) == str(excinfo.value)


def test_allowed_ips():
    url = 'http://127.0.0.1/test'
    options = {
        'allowed_ip_addresses': ['127.0.0.1']
    }
    assert SSRFProtect.validate(url, options=options) is None


def test_allowed_and_denied_ips():
    # Because denial comes first, if an ip is allowed and denied
    # an exception should be raised
    url = 'http://127.0.0.1/test'
    options = {
        'denied_ip_addresses': ['127.0.0.1'],
        'allowed_ip_addresses': ['127.0.0.1']
    }

    with pytest.raises(SSRFProtectException) as excinfo:
        SSRFProtect.validate(url, options)

    assert 'URL {url} is not allowed because it resolves to ' \
           'a denied IP address'.format(url=url) == str(excinfo.value)


@patch('ssrf_protect.ssrf_protect.SSRFProtect._get_ip_address',
       new=MockSSRFProtect._get_ip_address)
def test_denied_ips():
    url = 'http://testserver/test'
    options = {
        'denied_ip_addresses': ['1.2.3.4']
    }

    with pytest.raises(SSRFProtectException) as excinfo:
        SSRFProtect.validate(url, options)

    assert 'URL {url} is not allowed because it resolves to ' \
           'a denied IP address'.format(url=url) == str(excinfo.value)
