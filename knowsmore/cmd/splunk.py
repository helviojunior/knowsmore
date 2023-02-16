import json
import os
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from binascii import hexlify
from enum import Enum
from urllib.parse import urlparse
from clint.textui import progress

from knowsmore.libs.exporterbase import ExporterBase
from knowsmore.util.tools import Tools

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger


class Splunk(CmdBase):
    db = None
    url_base = None
    cracked_only = False
    include_password = False

    def __init__(self):
        super().__init__('splunk', 'Export data to Splunk')

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
        cmds.add_argument('--token',
                          action='store',
                          metavar='[text]',
                          type=str,
                          dest=f'txt_token',
                          help=Color.s('API Token to integrate'))

        cmds.add_argument('--url',
                          action='store',
                          metavar='[text]',
                          type=str,
                          dest=f'txt_url',
                          help=Color.s('URL to Splunk'))

    def load_from_arguments(self, args: Namespace) -> bool:
        if (args.txt_url is not None and args.txt_url.strip() != '' \
            and args.txt_token is not None and args.txt_token.strip() != ''):

            url = urlparse(args.txt_url)

            #Adicionar aqui o caminho padrão da API do Splunk
            self.url_base = f'{url.scheme}://{url.netloc}/'

            # Passos s realizar aqui
            # 1 - Checar conexão com o Splunk
            # 2 - Outras checagens de segurança
            # 3 - Criação do índice

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

            Logger.pl('     {C}splunk:{O} %s{W}' % str(self.url_base))
            Logger.pl('     {C}cracked only:{O} %s{W}' % self.cracked_only)
            Logger.pl('     {C}include clear text passwords:{O} %s{W}' % self.include_password)

        return True

    def run(self):

        total = self.db.get_data_len(cracked_only=self.cracked_only)
        count = 0
        with progress.Bar(label=" Syncing objects ", expected_size=total, every=5) as bar:
            try:
                for entry in self.db.get_data(
                        export_password=self.include_password,
                        cracked_only=self.cracked_only):
                    count += 1

                    if count > total:
                        bar.expected_size = count
                    bar.show(count)

                    # Integrate with Splunk Here
                    txt_entry = json.dumps(entry)
                    #print(txt_entry)
                    #time.sleep(0.0300)

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

        Logger.pl('{+} {O}%s{W}{C} integrated{W}' % count)






