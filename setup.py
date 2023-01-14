#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from setuptools import setup, find_packages

version = {}
with open('knowsmore/meta.py') as f:
    exec(f.read(), version)

setup(  name='knowsmore',
        version=version['__version__'],
        description='Active Directory, BloodHound, NTDS hashes and Password Cracks correlation tool',
        author='Hélvio Junior (M4v3r1ck)',
        author_email='helvio_junior@hotmail.com',
        url='https://github.com/helviojunior/knowsmore',
        packages=find_packages(),
        package_data={'knowsmore': ['resources/*']},
        install_requires=['bs4>=0.0.1',
                          'colorama',
                          'clint>=0.5.1',
                          'tabulate>=0.9.0',
                          'Levenshtein>=0.20.9',
                          'neo4j>=5.4.0'],
        readme="README.md",
        classifiers= [
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
        entry_points= { 'console_scripts': [
            'knowsmore=knowsmore.knowsmore:run',
            ]}
        )