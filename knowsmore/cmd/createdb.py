import os
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace

from knowsmore.cmdbase import CmdBase
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger


class CreateDb(CmdBase):
    db_name = ''
    force = False
    check_database = False

    def __init__(self):
        super().__init__('create-db', 'Create an empty database')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--force',
                           action='store_true',
                           default=False,
                           dest=f'force',
                           help=Color.s('Force overwrite SQLite local database'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.dbfile is None or args.dbfile.strip() == '':
            Logger.pl('{!} {R}error: filename is invalid {O}%s{R} {W}\r\n' % (
                args.db))
            exit(1)

        self.db_name = os.path.abspath(args.dbfile.strip())
        self.force = args.force

        if os.path.isfile(self.db_name) and not self.force:
            try:
                db = KnowsMoreDB(auto_create=False,
                                 db_name=self.db_name)

                if db.has_data():
                    Logger.pl('{!} {R}error: database already has data, use parameter {O}--force{R} if you want to replace all data {W}\r\n')
                    exit(1)
            except sqlite3.OperationalError as e:
                print(e)
                Logger.pl(
                    '{!} {R}error: the database file exists but is not an SQLite or table structure was not created. Use parameter {O}--force{R} if you want to replace all data {W}\r\n')
                exit(1)
            except Exception as e:
                raise e

        return True

    def run(self):
        if os.path.isfile(self.db_name) and self.force:
            Color.pl(
                '{!} {W}Database exists (you have 10 seconds to abort...) to prevent overwriting.')
            time.sleep(10)

            os.remove(self.db_name)

        KnowsMoreDB(auto_create=True,
                    db_name=self.db_name)

        Logger.pl('{+} {C}Database created {O}%s{W}' % self.db_name)

