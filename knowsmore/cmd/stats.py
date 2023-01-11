import json
import os
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from tabulate import _table_formats, tabulate
from binascii import hexlify
from enum import Enum

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger


class Stats(CmdBase):
    db = None
    out_file = None

    def __init__(self):
        super().__init__('stats', 'Generate password and hashes statistics')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--save-to',
                           action='store',
                           default='',
                           dest=f'out_file',
                           help=Color.s(
                               'Output file to save JSON data'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.out_file is not None and args.out_file.strip() != '':
            self.out_file = Path(args.out_file).absolute()

        if self.out_file is not None:
            if os.path.exists(self.out_file):
                Logger.pl('{!} {R}error: out file ({O}%s{R}) already exists {W}\r\n' % (
                    self.out_file))
                exit(1)

        self.db = self.open_db(args)

        return True

    def run(self):

        data = []

        # General Stats
        stats1 = self.db.select_raw(
            sql='select 1 as top, "Total Users" as description, (select count(*) from credentials) as qty '
                'union '
                'select 2 as top, "Unique Hashes" as description, (select count(distinct ntlm_hash) from passwords) as qty '
                'union '
                'select 3 as top, "Cracked Hashes" as description, (select count(distinct ntlm_hash) from passwords where length > 0) as qty '
                'union '
                'select 4 as top, "Cracked Users" as description, (select count(distinct c.credential_id) from credentials as c inner join passwords as p on c.password_id = p.password_id where p.length > 0) as qty ',
            args=[]
        )
        data.append({
            'type': 'general_stats',
            'domain': 'all',
            'description': 'General Statistics',
            'rows': stats1
        })

        # General Top 10
        rows_general = self.db.select_raw(
            sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS top, p.password, count(distinct c.credential_id) as qty '
                'from credentials as c '
                'inner join passwords as p '
                'on c.password_id = p.password_id '
                'where p.password <> "" '
                'group by p.password '
                'order by qty desc '
                'LIMIT 10',
            args=[]
        )

        if len(rows_general) > 0:
            data.append({
                'type': 'top10',
                'domain': 'all',
                'description': 'General Top 10 passwords',
                'rows': rows_general
            })

        # Company variation
        rows_v1 = self.db.select_raw(
            sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS top, p.password, round(count(distinct c.credential_id) * log(p.company_similarity, 2)) as score, p.company_similarity, count(distinct c.credential_id) as qty '
                'from credentials as c '
                'inner join passwords as p '
                'on c.password_id = p.password_id '
                'where p.password <> "" '
                'and p.company_similarity >= (select ifnull(avg(p1.company_similarity),0) as v1 from passwords as p1 where p1.company_similarity > 0) '
                'group by p.password, p.company_similarity '
                'order by score desc '
                'LIMIT 10',
            args=[]
        )
        if len(rows_v1) > 0:
            data.append({
                'type': 'top10_by_company_name_similarity',
                'domain': 'all',
                'description': 'Top 10 weak passwords by company name similarity',
                'rows': rows_v1
            })

        # General Top 10 Weaks
        rows_weak = self.db.select_raw(
            sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS top, p.password, count(distinct c.credential_id) as qty '
                'from credentials as c '
                'inner join passwords as p '
                'on c.password_id = p.password_id '
                'where p.password <> "" and strength <= 33 '
                'group by p.password '
                'order by qty desc '
                'LIMIT 10',
            args=[]
        )

        if len(rows_weak) > 0:
            data.append({
                'type': 'top10_weak',
                'domain': 'all',
                'description': 'General Top 10 weak passwords',
                'rows': rows_weak
            })

        domains = self.db.select('domains')
        for r in domains:

            # Domain Top 10
            rows = self.db.select_raw(
                sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS top, p.password, count(distinct c.credential_id) as qty '
                    'from credentials as c '
                    'inner join passwords as p '
                    'on c.password_id = p.password_id '
                    'where p.password <> "" and c.domain_id = ?'
                    'group by p.password '
                    'order by qty desc '
                    'LIMIT 10',
                args=[r['domain_id']]
            )

            if len(rows) > 0:
                data.append({
                    'type': 'top10',
                    'domain': r['name'],
                    'description': 'Top 10 passwords for %s' % r['name'],
                    'rows': rows
                })

        if self.out_file is None:

            for d in data:
                Color.pl('{?} {W}{D}%s{W}' % d['description'])
                headers = d['rows'][0].keys()
                data = [item.values() for item in d['rows']]
                print(tabulate(data, headers, tablefmt='psql'))
                print(' ')

        else:
            with open(self.out_file, "a", encoding="UTF-8") as text_file:
                text_file.write(json.dumps(
                    {
                        'data': data,
                        'meta': {
                            'type': 'stats',
                            'count': len(data),
                            'version': 1
                        }
                    }
                ))






