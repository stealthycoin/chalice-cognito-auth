import os
import re
import sys
import codecs
from setuptools import setup, find_packages


here = os.path.abspath(os.path.dirname(__file__))
src_dir = os.path.join(here, "src")
sys.path.insert(0, src_dir)


def read(*parts):
    return codecs.open(os.path.join(here, *parts), 'r').read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(
        r"^__version__ = ['\"]([^'\"]*)['\"]",
        version_file, re.M,
    )
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


requires = [
    'python-jose[cryptography]<4.0.0',
    'boto3>=1.9,<2.0',
]


setup_options = dict(
    name='chalice-cognito-auth',
    version=find_version("src", "chalice_cognito_auth", "__init__.py"),
    description='Library for verifying cognito tokens.',
    url='https://github.com/stealthycoin/chalice-cognito-auth',
    long_description=read('README.rst'),
    author='John Carlyle',
    install_requires=requires,
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=['tests*']),
    license="Apache License 2.0",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
    ],
)


setup(**setup_options)
