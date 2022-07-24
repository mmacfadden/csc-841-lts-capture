from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='csc-841-lts-capture',
    version='0.1.0',
    description='DSU CSC-844 Final Project (LTS RTSP Utility)',
    long_description=readme,
    author='Michael MacFadden',
    author_email='michael@macfadden.org',
    url='https://github.com/mmacfadden/csc-844-lts-capture',
    license=license,
    packages=find_packages(exclude=('docs'))
)