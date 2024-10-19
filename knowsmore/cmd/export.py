import json
import os
import sqlite3
import time
import requests
import socket
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from binascii import hexlify
from enum import Enum
from urllib3.util import parse_url
from clint.textui import progress

from knowsmore.libs.exporterbase import ExporterBase
from knowsmore.util.tools import Tools

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class JsonExport(CmdBase):
    db = None
    url_base = None
    url_path = '/services/collector/event'
    token_base = None
    cracked_only = False
    include_password = False
    out_file = ''

    def __init__(self):
        super().__init__('export', 'Export data to JSON file')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--include-password',
                           action='store_true',
                           default=False,
                           dest=f'include_password',
                           help=Color.s('Include clear text passwords and his hashes. (default: False)'))

        flags.add_argument('--cracked-only',
                           action='store_true',
                           default=False,
                           dest=f'cracked_only',
                           help=Color.s('Integrate cracked data only. (default: False)'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('-o',
                          action='store',
                          metavar='[file name]',
                          type=str,
                          dest=f'out_file',
                          help=Color.s('File path to save'))

    def load_from_arguments(self, args: Namespace) -> bool:

        db_name = os.path.abspath(args.dbfile.strip())

        if not os.path.isfile(db_name):
            Color.pl('{!} {R}error: database file not found {O}%s{R}{W}\r\n' % db_name)
            exit(1)

        try:
            self.db = ExporterBase(auto_create=False, db_name=db_name)

            self.db.check_open()

        except sqlite3.OperationalError as e:
            print(e)
            Logger.pl(
                '{!} {R}error: the database file exists but is not an SQLite or table structure was not created. Use parameter {O}--create-db{R} command to create.{W}\r\n')
            exit(1)
        except Exception as e:
            raise e

        self.cracked_only = args.cracked_only
        self.include_password = args.include_password
        self.out_file = os.path.abspath(args.out_file.strip())

        Logger.pl('     {C}file:{O} %s{W}' % str(self.out_file))
        Logger.pl('     {C}cracked only:{O} %s{W}' % self.cracked_only)
        Logger.pl('     {C}include clear text passwords:{O} %s{W}' % self.include_password)

        return True

    def run(self):

        total = self.db.get_data_len(cracked_only=self.cracked_only)
        count = 0
        with open(str(self.out_file), 'wb') as f:
            f.write('['.encode("UTF-8"))
            with progress.Bar(label=" Exporting objects ", expected_size=total, every=5) as bar:
                try:
                    for entry in self.db.get_data(
                            export_password=self.include_password,
                            cracked_only=self.cracked_only):
                        count += 1

                        if count > total:
                            bar.expected_size = count
                        bar.show(count)

                        if count > 1:
                            f.write(','.encode("UTF-8"))

                        json_data = json.dumps(entry, default=Tools.json_serial)
                        f.write(json_data.encode("UTF-8"))

                except KeyboardInterrupt as e:
                    raise e
                finally:
                    bar.hide = True
                    Tools.clear_line()
            f.write(']'.encode("UTF-8"))

        Logger.pl('{+} {O}%s{W}{C} register(s) exported{W}' % count)

