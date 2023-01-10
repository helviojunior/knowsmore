import errno
import json
import os
import re
import shutil
import sqlite3
import time
import mimetypes
import tempfile
from pathlib import Path
from zipfile import ZipFile
from argparse import _ArgumentGroup, Namespace

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools


class Bloodhound(CmdBase):
    filename = ''
    db = None

    def __init__(self):
        super().__init__('bloodhound', 'Import BloodHound files')

    def add_flags(self, flags: _ArgumentGroup):
        pass

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--import-data',
                          action='store',
                          metavar='[bloodhound file]',
                          type=str,
                          dest=f'bhfile',
                          help=Color.s('BloodHound file. Available parses: {G}.zip{W} and {G}.json{W}'))

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.bhfile is None or args.bhfile.strip() == '' or not os.path.isfile(args.bhfile):
            Logger.pl('{!} {R}error: BloodHound filename is invalid {O}%s{R} {W}\r\n' % (
                args.bhfile))
            Tools.exit_gracefully(1)

        try:
            with open(args.bhfile, 'r') as f:
                # file opened for writing. write to it here
                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl('{!} {R}error: could not open BloodHound file {O}permission denied{R}{W}\r\n')
                Tools.exit_gracefully(1)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open BloodHound file {O}it is an directory{R}{W}\r\n')
                Tools.exit_gracefully(1)
            else:
                Logger.pl('{!} {R}error: could not open BloodHound file {W}\r\n')
                Tools.exit_gracefully(1)

        self.filename = args.bhfile

        self.db = self.open_db(args)

        return True

    def run(self):

        count = 0
        try:
            # Check file type
            mime = mimetypes.MimeTypes().guess_type(self.filename)[0]
            if mime == "application/zip":
                # extract files
                Color.pl('{?} {W}{D}BloodHound ZIP File identified, extracting...{W}')

                with self.get_temp_directory() as tmpdirname:
                    try:
                        with ZipFile(self.filename, 'r') as zObject:
                            zObject.extractall(tmpdirname)

                        # Just to arrange import order
                        files = ['', '', '']
                        for f in self.get_files(tmpdirname):
                            p = Path(f)
                            if '_domains' in p.stem:
                                files[0] = f
                            elif '_groups' in p.stem:
                                files[1] = f
                            elif '_users' in p.stem:
                                files[2] = f

                        for f in files:
                            self.parse_file(str(f))

                    finally:
                        shutil.rmtree(tmpdirname)
            else:
                self.parse_file(self.filename)

        except KeyboardInterrupt as e:
            Tools.clear_line()
            print((" " * 180), end='\r', flush=True)
            Logger.pl("{!} {C}Interrupted by user{W}")
            raise e

    def parse_file(self, filename):
        count = 0
        try:

            with open(filename, 'r', encoding="UTF-8", errors="surrogateescape") as f:
                json_data = json.load(f)

                meta = json_data.get('meta', {})
                type = meta.get('type', None)
                qty = meta.get('count', None)
                version = meta.get('version', None)

                if type is None or version is None:
                    Logger.pl('{!} {R}error: BloodHound filename is invalid {O}%s{R} {W}\r\n' % (
                        filename))
                    Tools.exit_gracefully(1)

                # Domains
                if type.lower() == "domains":
                    if str(version) == "4":
                        Color.pl('{?} {W}{D}importing domains...{W}')
                        data = json_data.get('data', [])
                        for dd in data:
                            count += 1
                            Tools.clear_line()
                            print(("Processing [%d]" % count), end='\r', flush=True)

                            oid = dd.get('ObjectIdentifier', None)
                            properties = dd.get('Properties', None)

                            if oid is None or properties is None:
                                raise Exception('Unable to parse domain data')

                            name = properties.get('name', None)
                            domain = properties.get('domain', None)
                            dn = properties.get('distinguishedname', None)

                            if name is None or domain is None or dn is None:
                                raise Exception('Unable to parse domain data')

                            self.db.insert_or_get_domain(
                                domain=domain,
                                dn=dn,
                                object_identifier=oid)

                    else:
                        raise Exception('Unsupported BloodHound Version')

                # groups
                elif type.lower() == "groups111":
                    groups = {}

                    if str(version) == "4":
                        Color.pl('{?} {W}{D}importing groups...{W}')
                        data = json_data.get('data', [])
                        for didx, dd in enumerate(data):
                            p = int(((didx + 1) / qty) * 100)
                            Tools.clear_line()
                            print(("Processing [%s/%s => %s%%]" % (didx + 1, qty, p)), end='\r', flush=True)

                            gid = dd.get('ObjectIdentifier', None)
                            properties = dd.get('Properties', None)

                            if gid is None or properties is None:
                                raise Exception('Unable to parse domain data')

                            name = properties.get('name', '@').split('@')[0]
                            dn = properties.get('distinguishedname', None)

                            domain_id = self.get_domain(properties)

                            groups[gid] = {
                                "name": name,
                                "domain_id": domain_id,
                                "object_identifier": gid,
                                "dn": dn,
                                "json_members": dd.get('Members', []),
                                "members": [],
                                "membership": []
                            }

                            # Step 1
                            members = dd.get('Members', [])
                            for g in members:
                                t = g.get('ObjectType', None)
                                oid = g['ObjectIdentifier']
                                if t == "Group":
                                    groups[gid]['members'].append(oid)


                    else:
                        raise Exception('Unsupported BloodHound Version')

                    if len(groups) > 0:
                        def get_group_chain(groupId, chain):

                            if groupId in chain:
                                return []

                            grp = []
                            grp.append(groupId)

                            for g in groups:
                                members = groups[g].get('members', [])
                                if groupId in members:
                                    if g not in grp:
                                        grp.append(g)
                                        tmp = get_group_chain(g, chain + grp)
                                        for t in tmp:
                                            if t not in grp:
                                                grp.append(t)
                            return grp

                        Color.pl('{?} {W}{D}calculating group chain...{W}' + ' ' * 50)
                        cnt = len(groups)
                        for idx, g in enumerate(groups):
                            p = int(((idx + 1) / cnt) * 100)

                            Tools.clear_line()
                            print(("Processing [%s/%s => %s%%]" % (idx + 1, cnt, p)), end='\r', flush=True)
                            groups[g]['membership'] = get_group_chain(g, [])

                        Color.pl('{?} {W}{D}inserting groups...{W}' + ' ' * 50)
                        for idx, g in enumerate(groups):
                            p = int(((idx + 1) / cnt) * 100)
                            Tools.clear_line()
                            print(("Inserting [%s/%s => %s%%]" % (idx + 1, cnt, p)), end='\r', flush=True)
                            self.db.insert_group(
                                domain=groups[g]['domain_id'],
                                object_identifier=groups[g]['object_identifier'],
                                name=groups[g]['name'],
                                dn=groups[g]['dn'],
                                members=json.dumps(groups[g]['json_members']),
                                membership=','.join(groups[g]['membership'])
                            )

                #Users
                elif type.lower() == "users":
                    if str(version) == "4":

                        Color.pl('{?} {W}{D}loading groups from db...{W}' + ' ' * 50)
                        user_groups = {}
                        groups = {}
                        conn = self.db.get_connection()
                        cursor = conn.cursor()
                        cursor.execute("""
                                select object_identifier, members, membership, name from [groups];
                                """)
                        data = cursor.fetchall()
                        if data:
                            for row in data:
                                gid = row[0]
                                members = json.loads(row[1])
                                for g in members:
                                    t = g['ObjectType']
                                    oid = g['ObjectIdentifier']
                                    if t == "User":
                                        ug = user_groups.get(oid, [])
                                        ug.append(gid)
                                        user_groups[oid] = ug

                                groups[gid] = {
                                    'name':  row[3],
                                    'membership': row[2].split(',')
                                }

                        conn.close()

                        def get_user_groups(userId):
                            ug = user_groups.get(userId, [])
                            gids = []
                            for g in ug:
                                tmp = groups[g]['membership']
                                for t in tmp:
                                    if t not in gids:
                                        gids.append(t)

                            group_names = []
                            for g in gids:
                                gname = groups.get(g, {}).get("name", None)
                                if gname is not None:
                                    group_names.append(gname)

                            return ', '.join(group_names)

                        Color.pl('{?} {W}{D}importing users...{W}' + ' ' * 50)
                        data = json_data.get('data', [])
                        for didx, dd in enumerate(data):
                            p = int(((didx + 1) / qty) * 100)
                            Tools.clear_line()
                            print(("Processing [%s/%s => %s%%]" % (didx + 1, qty, p)), end='\r', flush=True)

                            oid = dd.get('ObjectIdentifier', None)
                            properties = dd.get('Properties', None)

                            if oid is None or properties is None:
                                raise Exception('Unable to parse user data 1: %s' % json.dumps(dd))

                            name = properties.get('name', '@').split('@')[0].lower()
                            dn = properties.get('distinguishedname', None)

                            if name is None:
                                raise Exception('Unable to parse user data 2: %s' % json.dumps(dd))

                            domain_id = self.get_domain(properties)

                            # Hard-coded empty password
                            self.db.insert_credential(
                                domain=domain_id,
                                username=name,
                                ntlm_hash='31d6cfe0d16ae931b73c59d7e0c089c0',
                                type='U')

                    else:
                        raise Exception('Unsupported BloodHound Version')


        except KeyboardInterrupt as e:
            Tools.clear_line()
            print((" " * 180), end='\r', flush=True)
            raise e

    def get_domain(self, properties):
        domain_name = properties.get('domain', None)
        if domain_name is None:
            properties.get('name', '@').split('@')[1].lower()
        domain_name = domain_name.lower()
        domain_sid = properties.get('domainsid', '')

        domain_id = self.db.get_domain_by_sid(domain_sid)

        if domain_id == -1:
            self.db.insert_or_get_domain(
                domain=domain_name,
                object_identifier=domain_sid)
            domain_id = self.db.get_domain_by_sid(domain_sid)

        if domain_id == -1:
            domain_id = self.db.get_domain(domain_name)

        if domain_id == -1:
            print(domain_name)
            raise Exception('Unable to get/create domain from JSON: %s' % json.dumps(properties))

        return domain_id
