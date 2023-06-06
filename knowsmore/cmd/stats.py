import json
import os
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path

from ansi2image.ansi2image import Ansi2Image
from binascii import hexlify
from enum import Enum

from knowsmore.util.tools import Tools

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger


class Stats(CmdBase):
    db = None
    out_file = None
    out_path = None

    def __init__(self):
        super().__init__('stats', 'Generate password and hashes statistics')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--save-to',
                           action='store',
                           default='',
                           dest=f'out_file',
                           help=Color.s(
                               'Output file to save JSON data'))

        flags.add_argument('--save-to-img',
                           action='store',
                           default='',
                           dest=f'out_path',
                           help=Color.s(
                               'Output path to save PNG files'))

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

        if args.out_path is not None and args.out_path.strip() != '':
            self.out_path = Path(args.out_path).absolute()

        if self.out_path is not None:
            if not os.path.isdir(self.out_path):
                Logger.pl('{!} {R}error: output path ({O}%s{R}) does not exists {W}\r\n' % (
                    self.out_path))
                exit(1)

        self.db = self.open_db(args)

        return True

    def run(self):

        data = []

        # General Stats
        stats1 = self.db.select_raw(
            sql='select 1 as __line, "Total Users" as description, (select count(*) from credentials where type = "U") as qty '
                'union '
                'select 2 as __line, "Total Machines" as description, (select count(*) from credentials where type = "M") as qty '
                'union '
                'select 3 as __line, "Unique Hashes" as description, (select count(distinct ntlm_hash) from passwords) as qty '
                'union '
                'select 4 as __line, "Cracked Hashes" as description, (select count(distinct ntlm_hash) from passwords where length > 0) as qty '
                'union '
                'select 5 as __line, "Cracked Users" as description, (select count(distinct c.credential_id) from credentials as c inner join passwords as p on c.password_id = p.password_id where p.length > 0 and c.type = "U") as qty '
                'union '
                'select 6 as __line, "Cracked Machines credentials" as description, (select count(distinct c.credential_id) from credentials as c inner join passwords as p on c.password_id = p.password_id where p.length > 0 and c.type = "M") as qty',
            args=[]
        )
        data.append({
            'type': 'general_stats',
            'domain': 'all',
            'description': 'General Statistics',
            'rows': stats1
        })

        # BloodHound

        bloodhound = self.db.select_raw(
            sql='select row_number() OVER (ORDER BY o.object_label ASC) AS __line, o.object_label as Type, '
                'count(o.object_id) as qty '
                'from bloodhound_objects as o '
                'group by o.object_label '
                'order by o.object_label',
            args=[])

        if len(bloodhound) > 0:
            data.append({
                'type': 'bloodhound',
                'domain': 'all',
                'description': 'BloodHound Objects',
                'rows': bloodhound
            })

        # Users/Machines by domain
        rows_uc = self.db.select_raw(
            sql='select row_number() OVER (ORDER BY (ifnull(sum(u.users),0) + ifnull(sum(m.machines),0)) DESC) AS __line, d.name, ifnull(sum(u.users),0) as users, ifnull(sum(m.machines),0) as machines '
                'from domains as d '
                'left join ( '
                '	select d.domain_id, count(distinct c1.credential_id) as users '
                '	from domains as d '
                '	inner join credentials as c1 '
                '	on c1.domain_id = d.domain_id and c1.type = "U" '
                '	group by d.domain_id '
                '	order by users desc  '
                ') as u on d.domain_id = u.domain_id '
                'left join ( '
                '	select d.domain_id, d.name, count(distinct c2.credential_id) as machines '
                '	from domains as d '
                '	inner join credentials as c2 '
                '	on c2.domain_id = d.domain_id and c2.type = "M" '
                '	group by d.domain_id, d.name  '
                '	order by machines desc  '
                ') as m on d.domain_id = m.domain_id '
                'group by d.name '
                'order by ifnull(sum(u.users),0) + ifnull(sum(m.machines),0) desc '
                'LIMIT 10 ',
            args=[]
        )

        if len(rows_uc) > 0:
            data.append({
                'type': 'users_and_computers',
                'domain': 'all',
                'description': 'Top 10 domains by users and computers',
                'rows': rows_uc
            })

        # General Top 10
        rows_general = self.db.select_raw(
            sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS __line, p.password, count(distinct c.credential_id) as qty '
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
            sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS __line, p.password, round(count(distinct c.credential_id) * log(p.company_similarity, 2)) as score, p.company_similarity, count(distinct c.credential_id) as qty '
                'from credentials as c '
                'inner join passwords as p '
                'on c.password_id = p.password_id '
                'where p.length > 0 and p.company_similarity > 40 '
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
            sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS __line, p.password, count(distinct c.credential_id) as qty '
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
                sql='select row_number() OVER (ORDER BY count(distinct c.credential_id) DESC) AS __line, p.password, count(distinct c.credential_id) as qty '
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

        if self.out_file is not None:
            Color.pl('{?} {W}{D}Statistics saved at {W}{C}%s{W}{D}{W}' % self.out_file)

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

        elif self.out_path is not None:

            for i, d in enumerate(data):
                name = f"{i:03}_{Tools.sanitize_filename(d['description'])}"
                file_data = ' \033[38;5;52m=\033[38;5;88m=\033[38;5;124m=\033[38;5;160m=\033[38;5;196m> ' + Color.s(
                    '{W}{G}%s{W}\n' % d['description'])

                file_data += ''.join([
                    '%s─' % c for k, c in sorted(Color.gray_scale.items(), key=lambda x: x[0], reverse=True)
                ]) + Color.s('{W}\n')

                Color.pl('{?} {W}{D}Saving %s...{W}' % d['description'])

                if len(data) == 0:
                    file_data += Color.s(
                        '\n  {R}ATTENTION!!!{O} \n  %s{W}\n' % 'Table is empty')
                else:
                    file_data += Tools.get_ansi_tabulated(d['rows'])

                o = Ansi2Image(0, 0, font_name=Ansi2Image.get_default_font_name(), font_size=13)
                o.loads(file_data)
                o.min_margin = 10
                o.max_margin = 30
                o.calc_size(margin=0.01)
                o.save_image(os.path.join(self.out_path, f'{name}.png'), format='PNG')

                #with open(os.path.join(self.out_path, f'{name}.ansi.txt'), 'wb') as f:
                #    f.write(file_data.encode('utf-8', 'ignore'))

        else:

            for d in data:
                Color.pl('{?} {W}{D}%s{W}' % d['description'])
                print(Tools.get_tabulated(d['rows']))
                print(' ')






