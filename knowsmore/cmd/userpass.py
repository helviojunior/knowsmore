import errno
import os
import re
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from enum import Enum
from clint.textui import progress

from knowsmore.cmdbase import CmdBase
from knowsmore.config import Configuration
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools


class UserPass(CmdBase):
    db = None
    password = None
    username = None

    def __init__(self):
        super().__init__('user-pass', 'Add user password')

    def add_flags(self, flags: _ArgumentGroup):
        pass

    def add_commands(self, cmds: _ArgumentGroup):

        cmds.add_argument('--username',
                          action='store',
                          metavar='[username]',
                          type=str,
                          default='',
                          dest=f'username',
                          help=Color.s('Username'))

        cmds.add_argument('--password',
                          action='store',
                          metavar='[clear text password]',
                          type=str,
                          default='',
                          dest=f'password',
                          help=Color.s('Clear text password'))

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.password.strip() == '' or args.username.strip() == '':
            Tools.mandatory()

        self.username = args.username.strip().lower()

        self.password = Password(
            ntlm_hash='',
            clear_text=args.password
        )

        self.db = self.open_db(args)

        return True

    def run(self):

        sql = (
            'select c.credential_id, c.name, c.type from credentials as c '
            ' where c.name like ? '
            ' order by c.name'
        )
        args = [f'%{self.username}%']

        rows = self.db.select_raw(
            sql=sql,
            args=args
        )

        if len(rows) == 0:
            Logger.pl('{!} {O}User "{G}%s{O}" not found{W}\r\n' % self.username)
            exit(0)

        if len(rows) > 1:
            Logger.pl('{!} {O}More than one User found with this text. Please adjust your query{W}\r\n')
            print(Tools.get_tabulated(rows))
            exit(0)

        credential_id = rows[0]['credential_id']

        sql = (
            'select c.* from credentials as c '
            ' where c.credential_id == ?'
        )

        rows = self.db.select_raw(
            sql=sql,
            args=[credential_id]
        )

        pdata = {}

        if len(Configuration.company) > 0:
            pdata['company_similarity'] = sorted(
                        [self.password.calc_ratio(n1) for n1 in Configuration.company]
                    )[-1]
            Logger.pl('{+} {C}Calculated company name similarity: {O}%s{W}' % pdata['company_similarity'])

        self.db.insert_or_update_credential(
            domain=rows[0]['domain_id'],
            username=rows[0]['name'],
            ntlm_hash=self.password.ntlm_hash,
            type='U',
        )

        self.db.insert_password_manually(self.password, **pdata)
        Logger.pl('{+} {C}Password inserted/updated{W}')

        print(' ')
        Color.pl('{?} {W}{D}Password data:{W}')
        print(self.password)

        Color.pl('{?} {W}{D}Looking for other users with the same password...{W}')

        sql = (
            'select c.credential_id, c.name, c.type, c.object_identifier, c.dn, d.domain_id, d.name as domain_name, d.object_identifier as domain_object_identifier, '
            'd.dn as domain_dn, p.password, p.ntlm_hash, p.md5_hash, p.sha1_hash, p.sha256_hash, p.sha512_hash '
            'from credentials as c '
            'inner join passwords as p '
            'on c.password_id = p.password_id '
            'inner join domains as d '
            'on c.domain_id = d.domain_id '
            ' where p.ntlm_hash like ? and c.credential_id != ?'
            ' order by c.name'
        )
        args = [self.password.ntlm_hash, credential_id]

        rows = self.db.select_raw(
            sql=sql,
            args=args
        )

        if len(rows) == 0:
            Logger.pl('{?} {G}Password/hash inserted but did not find other user with this password{W}\r\n')
            exit(0)

        print(Tools.get_tabulated(rows))

        Logger.pl('{+} {O}%s{W}{C} register found{W}' % len(rows))