#!/usr/bin/env python
# coding: utf-8
from setuptools import setup, find_packages


requirements = [
]

dep_links = [
]


setup(name='ssrf-protect',
      version='0.0.1',
      description='Basic library to validate URLs again SSRF attacks',
      author='the ssrf-protect contributors (https://github.com/kobotoolbox/ssrf-protect/graphs/contributors)',
      url='https://github.com/kobotoolbox/ssrf-protect/',
      packages=[str(pkg) for pkg in find_packages('src')],
      package_dir={'': 'src'},
      install_requires=requirements,
      dependency_links=dep_links,
      include_package_data=True,
      zip_safe=False,
      )
