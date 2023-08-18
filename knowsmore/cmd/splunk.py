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


class Splunk(CmdBase):
    db = None
    url_base = None
    url_path = '/services/collector/event'
    token_base = None
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

            url = parse_url(args.txt_url)

            #Adicionar aqui o caminho padrão da API do Splunk
            self.url_base = f'{url.scheme}://{url.netloc}/'
            self.token_base = args.txt_token

            '''
            Splunk check connection
            '''
            try:
                socket.create_connection((url.hostname, url.port))
                Logger.pl('     {C}splunk connection:{O} %s{W}' % url.hostname)
            except Exception as e:
                Color.pl('{!} {R}error: Splunk server not found {O}%s{R}{W}\r\n' % e) 
                exit(1)
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

                    '''
                    Integration with Splunk
                    '''
                    url = self.url_base + self.url_path
                    headers = {
                            'Authorization': self.token_base,
                            'Content-Type': 'application/json'
                    }
                    dict_payload = dict(event=entry)
                    json_payload = json.dumps(dict_payload)
                    try:
                        response = requests.request("POST", url, headers=headers, data=json_payload, verify=False)
                        response.raise_for_status()
                    except requests.exceptions.HTTPError as error_http:
                        Color.pl('{!} {R}error: HTTP Error {O}%s{R}{W}\r\n' % error_http)
                        exit(1)
                    except requests.exceptions.ConnectionError as error_connection:
                        Color.pl('{!} {R}error: Connection Error {O}%s{R}{W}\r\n' % error_connection)
                        exit(1)
                    except requests.exceptions.Timeout as error_timeout:
                        Color.pl('{!} {R}error: Timeout Error {O}%s{R}{W}\r\n' % error_timeout)
                        exit(1)
                    except requests.exceptions.RequestException as error_all:
                        Color.pl('{!} {R}error: Generic Error {O}%s{R}{W}\r\n' % error_all)
                        exit(1)
                    time.sleep(0.0300)

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

        Logger.pl('{+} {O}%s{W}{C} integrated{W}' % count)






