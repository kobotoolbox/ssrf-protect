The purpose of this library is to make a basic validation on an URL.
It tries to make a DNS lookup to check whether the ip is allowed or not.
By default, these types are forbidden
- `private` 
- `reserved`
- `loopback`
- `multicast`
- `link-local`
  
See https://docs.python.org/3/library/ipaddress.html for more details

Usage:

### Trivial case
```python
import requests
from ssrf_protect.ssrf_protect import SSRFProtect


url = 'http://www.example.com'
SSRFProtect.validate(url)
requests.get(url)  # request is processed


url = 'http://localhost'
SSRFProtect.validate(url)  # Raise SSRFProtectException
requests.get(url)  # request is not processed
``` 

### Whitelisted IP addresses
```python
import requests
from ssrf_protect.ssrf_protect import SSRFProtect


url = 'http://localhost'
options = {
    'allowed_ip_addresses': ['127.0.0.1']
}
SSRFProtect.validate(url, options=options)
requests.get(url) # request is processed
``` 

### Blacklisted IP addresses
```python
import requests
from ssrf_protect.ssrf_protect import SSRFProtect


url = 'http://www.example.com'  # Resolves to 1.2.3.4`
options = {
    'denied_ip_addresses': ['1.2.3.4']
}
SSRFProtect.validate(url)  # Raise SSRFProtectException
requests.get(url)  # request is not processed
``` 

