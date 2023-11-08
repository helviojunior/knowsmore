#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import os, subprocess, socket, re, requests, errno, sys, time, json, signal, base64, hashlib, random
from pathlib import Path
from urllib.parse import urlparse

from .args import Arguments
from .util.color import Color
from .util.logger import Logger
from .util.database import Database
from .__meta__ import __version__
from .util.tools import Tools


class Configuration(object):
    ''' Stores configuration variables and functions for TKnowsMore. '''
    version = '0.0.0'
    name = ""

    initialized = False # Flag indicating config has been initialized
    verbose = 0
    module = None
    cmd_line = ''
    company = []

    @staticmethod
    def initialize():
        '''
            Sets up default initial configuration values.
            Also sets config values based on command-line arguments.
        '''

        Configuration.version = str(__version__)
        Configuration.name = str(__name__)

        # Only initialize this class once
        if Configuration.initialized:
            return

        Configuration.initialized = True

        Configuration.verbose = 0 # Verbosity level.
        Configuration.print_stack_traces = True

        # Overwrite config values with arguments (if defined)
        Configuration.load_from_arguments()


    @staticmethod
    def load_from_arguments():
        ''' Sets configuration values based on Argument.args object '''
        from .args import Arguments

        config_check = 0

        args = Arguments()

        a1 = sys.argv
        a1[0] = 'knowsmore'
        for a in a1:
            Configuration.cmd_line += "%s " % a

        module = args.get_module()

        if module is None:
            Configuration.mandatory()

        Configuration.verbose = args.args.v

        Color.pl('{+} {W}Startup parameters')
        Logger.pl('     {C}command line:{O} %s{W}' % Configuration.cmd_line)

        if Configuration.verbose > 0:
            Logger.pl('     {C}verbosity level:{O} %s{W}' % Configuration.verbose)

        Logger.pl('     {C}module:{O} %s{W}' % module.name)

        if args.args.company is not None and args.args.company.strip(' .,'):
            Configuration.company = [] + Tools.clear_string(args.args.company).split(',')

        if len(Configuration.company) > 0:
            for c in Configuration.company:
                if len(c.strip()) >= 8:
                    Color.pl('{!} {R}error: company name {O}%s{R} reached maximum name length. {G}The name must have up to 7 digits.{W}\r\n' % c)
                    exit(1)

        if len(Configuration.company) > 0:
            Logger.pl('     {C}company name:{O} %s{W}' % ', '.join(Configuration.company))

        if not module.load_from_arguments(args.args):
            Configuration.mandatory()

        Configuration.module = module

        if module.check_database:
            Configuration.module.open_db(args=args.args, check=True)

        db_name = os.path.abspath(args.args.dbfile.strip())
        Logger.pl('     {C}database file:{O} %s{W}' % db_name)

        print('  ')

    @staticmethod
    def mandatory():
        Logger.pl('{!} {R}error: missing a mandatory option, use -h help{W}\r\n')
        exit(1)

    @staticmethod
    def get_banner():
            Configuration.version = str(__version__)

            return '''\

{G}KnowsMore {D}v%s{W}{G} by Helvio Junior{W}
{W}{D}Active Directory, BloodHound, NTDS hashes and Password Cracks correlation tool{W}
{C}{D}https://github.com/helviojunior/knowsmore{W}
    ''' % Configuration.version


    @staticmethod
    def dump():
        ''' (Colorful) string representation of the configuration '''
        from .util.color import Color

        max_len = 20
        for key in Configuration.__dict__.keys():
            max_len = max(max_len, len(key))

        result  = Color.s('{W}%s  Value{W}\n' % 'Configuration Key'.ljust(max_len))
        result += Color.s('{W}%s------------------{W}\n' % ('-' * max_len))

        for (key,val) in sorted(Configuration.__dict__.items()):
            if key.startswith('__') or type(val) == staticmethod or val is None:
                continue
            result += Color.s("{G}%s {W} {C}%s{W}\n" % (key.ljust(max_len),val))
        return result
