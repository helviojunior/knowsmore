#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import datetime
import sys, os.path
import sqlite3
import string, base64
import json
import hashlib
from sqlite3 import Connection, OperationalError, IntegrityError, ProgrammingError

from .color import Color
from .database import Database
from ..password import Password


class KnowsMoreDB(Database):
    dbName = ""

    def __init__(self, auto_create=True, db_name=None):

        if db_name is None:
            db_name = "knowsmore.db"

        super().__init__(
            auto_create=auto_create,
            db_name=db_name
        )
        self.fill_data()

    def has_data(self) -> bool:
        return self.select_count('passwords') > 0

    def check_open(self) -> bool:
        return self.select_count('passwords') >= 0

    def insert_group(self, domain: int, object_identifier: str, name: str, dn: str = '', members: str = '',
                     membership: str = '') -> int:

        if domain == -1:
            raise Exception('Invalid domain')

        if object_identifier is None or object_identifier.strip() == '':
            raise Exception('object_identifier cannot be empty')

        #grp = self.select('groups',
        #                  object_identifier=object_identifier
        #                  )

        #if len(grp) == 0:
        #    self.insert_one('groups',
        self.insert_update_one('groups',
                               domain_id=domain,
                               name=name,
                               object_identifier=object_identifier,
                               dn=dn,
                               members=members,
                               membership=membership
                               )

    def update_password(self, password: Password, **kwargs):

        filter_data = {
            'ntlm_hash': password.ntlm_hash,
        }

        pwd = {
            'password': password.clear_text,
            'length': password.length,
            'entropy': password.entropy,
            'strength': password.strength,
            'upper': password.upper,
            'lower': password.lower,
            'digit': password.digit,
            'special': password.special,
            'latin': password.latin,
            'md5_hash': password.md5_hash,
            'sha1_hash': password.sha1_hash,
            'sha256_hash': password.sha256_hash,
            'sha512_hash': password.sha512_hash,
        }

        pwd.update(kwargs)

        self.update('passwords', filter_data, **pwd)

        # Get all credentials (user/computer) using this password
        credentials = self.select_raw(
            sql='select distinct c.credential_id, c.name, c.full_name, c.user_data_similarity from credentials as c '
                'inner join passwords as p on c.password_id = p.password_id '
                'where c.type = "U" '
                'and c.full_name != "" '
                'and p.ntlm_hash = ?',
            args=[password.ntlm_hash]
        )
        for c in credentials:
            names = [
                n.lower() for n in c['full_name'].split(' ')
                if len(n) > 3
            ]
            score = sorted(
                [password.calc_ratio(n) for n in names]
            )[-1]
            if int(c['user_data_similarity']) != int(score):
                self.update('credentials',
                            filter_data={'credential_id': c['credential_id']},
                            user_data_similarity=score
                            )

    def insert_password_manually(self, password: Password, **kwargs):

        self.insert_ignore_one('pre_computed',
                               ntlm_hash=password.ntlm_hash,
                               password=password.clear_text if password.length > 0 else ''
                               )

        self.update_password(password, **kwargs)

        self.insert_update_one('pre_computed',
                               ntlm_hash=password.ntlm_hash,
                               md5_hash=password.md5_hash,
                               sha1_hash=password.sha1_hash,
                               sha256_hash=password.sha256_hash,
                               sha512_hash=password.sha512_hash,
                               password=password.clear_text,
                               )

    def insert_or_update_bloodhound_object(self, label: str, object_id: str, filter_type: str = 'objectid',  **props):

        object_id = object_id.upper()

        name = props.get('name', '')
        domain = props.get('domain', '').upper()
        name = name.replace(f'@{domain}', '').replace(f'.{domain}', '')

        rid = ''
        if object_id[0:2] == "S-" and \
                (label.lower() == 'group' or label.lower() == 'user' or label.lower() == 'machine'):
            rid = object_id.split('-')[-1]

        self.insert_update_one(
            'bloodhound_objects',
            object_id=object_id,
            filter_type=filter_type,
            object_label=label,
            name=name,
            r_id=rid,
            props=json.dumps(props)
        )

    def insert_or_update_bloodhound_edge(self, source: str, target: str, source_label: str, target_label: str,
                                         edge_type: str, edge_props: str, filter_type: str = 'objectid',
                                         props: dict = {}):

        txt_props = json.dumps(props)
        checksum = hashlib.md5(
            f'{source_label}:{target_label}:{edge_type}:{source}:{target}:{txt_props}'.encode("UTF-8")
        ).hexdigest().lower()

        data = dict(
            edge_id=checksum,
            source_id=source,
            destination_id=target,
            edge_props=edge_props,
            source_label=source_label,
            target_label=target_label,
            edge_type=edge_type,
            source_filter_type=filter_type,
            updated_date=datetime.datetime.utcnow(),
            props=txt_props
        )

        self.insert_update_one('bloodhound_edge', **data)

        from ..config import Configuration
        from .tools import Tools
        if Configuration.verbose >= 4:
            Color.pl('{*} {O}insert_or_update_bloodhound_edge: {G}%s{W}{D}{W}' % (
                json.dumps(data, default=Tools.json_serial)))

    def insert_or_update_credential(self, domain: int, username: str, ntlm_hash: str,
                                    dn: str = '', groups: str = '', object_identifier: str = '',
                                    type: str = 'U', full_name: str = '', enabled: bool = True,
                                    pwd_last_set: datetime.datetime = datetime.datetime(1970, 1, 1, 0, 0, 0, 0),
                                    exclude_on_update: list = None
                                    ):
        try:

            # Hard-coded empty password
            update_password = True
            if ntlm_hash is None or ntlm_hash.strip() == '':
                update_password = False
                ntlm_hash = '31d6cfe0d16ae931b73c59d7e0c089c0'

            passwd = self.select_first('passwords', ntlm_hash=ntlm_hash)
            password_id = -1 if passwd is None else passwd['password_id']

            if password_id == -1:
                self.insert_one('passwords', domain_id=domain, ntlm_hash=ntlm_hash)

                passwd = self.select_first('passwords', ntlm_hash=ntlm_hash)
                password_id = -1 if passwd is None else passwd['password_id']

            if password_id == -1:
                raise Exception('Password not found at database')

            data = {
                'domain_id': domain,
                'name': username,
                'type': type,
                'enabled': enabled,
                'password_id': password_id
            }
            if full_name is not None:
                data['full_name'] = full_name
            if dn is not None:
                data['dn'] = dn
            if groups is not None:
                data['groups'] = groups
            if object_identifier is not None:
                data['object_identifier'] = object_identifier
            if pwd_last_set is not None and pwd_last_set.year > 1970:
                data['pwd_last_set'] = pwd_last_set

            ex = ['password_id'] if not update_password else []
            if exclude_on_update is not None and isinstance(exclude_on_update, list):
                ex += [str(x) for x in exclude_on_update]

            self.insert_update_one_exclude('credentials',
                                           exclude_on_update=exclude_on_update,
                                           **data)

        except Exception as e:
            Color.pl('{!} {R}Error inserting credential data:{O} %s{W}' % str(e))
        pass

    def insert_or_get_domain(self, domain: str, dn: str = '', object_identifier: str = '') -> int:

        if domain is None or domain.strip() == '':
            raise Exception('Domain cannot be empty')

        domain = domain.lower()
        dn = '' if dn is None else dn.lower()
        object_identifier = '' if object_identifier is None else object_identifier.strip()

        f = {
            '__operator': 'or',
            'name': domain.lower()
        }
        if dn is not None and dn != '':
            f['dn'] = dn

        if f is None and object_identifier is not None and object_identifier != '':
            f['object_identifier'] = object_identifier

        domain_id = self.get_domain(**f)

        if domain_id == -1:
            data = {
                'name': domain.lower()
            }

            if dn is not None and dn != '':
                data['dn'] = dn

            if object_identifier is not None and object_identifier != '':
                data['object_identifier'] = object_identifier

            self.insert_ignore_one('domains', **data)

            domain_id = self.get_domain(**f)

        else:
            data = {
                'name': domain.lower()
            }

            if dn is not None and dn != '':
                data['dn'] = dn

            if object_identifier is not None and object_identifier != '':
                data['object_identifier'] = object_identifier

            self.update('domains', {'domain_id': domain_id}, **data)

        return domain_id

    def get_domain(self, **kwargs) -> int:
        dom = self.select_first('domains', **kwargs)
        return dom.get('domain_id', None) if dom is not None else -1

    def fill_data(self):
        if not self.has_data():
            # Create default empty password hash
            self.insert_ignore_one('passwords',
                                   ntlm_hash='31d6cfe0d16ae931b73c59d7e0c089c0',
                                   password='(empty)'
                                   )

    def create_db(self):

        conn = self.connect_to_db(check=False)

        # definindo um cursor
        cursor = conn.cursor()

        # criando a tabela (schema)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [domains] (
                domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                object_identifier TEXT NOT NULL DEFAULT(''),
                dn TEXT NOT NULL DEFAULT(''),
                UNIQUE(name)
            );
        """)

        # criando a tabela (schema)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [passwords] (
                password_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                ntlm_hash TEXT NOT NULL,
                md5_hash TEXT NOT NULL DEFAULT(''),
                sha1_hash TEXT NOT NULL DEFAULT(''),
                sha256_hash TEXT NOT NULL DEFAULT(''),
                sha512_hash TEXT NOT NULL DEFAULT(''),
                password TEXT NOT NULL DEFAULT(''),
                entropy INTEGER NOT NULL DEFAULT(0),
                strength INTEGER NOT NULL DEFAULT(0),
                length INTEGER NOT NULL DEFAULT(0),
                upper INTEGER NOT NULL DEFAULT(0),
                lower INTEGER NOT NULL DEFAULT(0),
                digit INTEGER NOT NULL DEFAULT(0),
                special INTEGER NOT NULL DEFAULT(0),
                latin INTEGER NOT NULL DEFAULT(0),
                company_similarity INTEGER NOT NULL DEFAULT(0),
                UNIQUE(domain_id, ntlm_hash)
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [credentials] (
                credential_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                type varchar(1) NOT NULL  DEFAULT('U'),
                name varchar(500) NOT NULL,
                full_name TEXT NOT NULL DEFAULT(''),
                object_identifier TEXT NOT NULL DEFAULT(''),
                dn TEXT NOT NULL DEFAULT(''),
                groups TEXT NOT NULL DEFAULT(''),
                password_id INTEGER NOT NULL,
                user_data_similarity INTEGER NOT NULL DEFAULT(0),
                enabled INTEGER NOT NULL DEFAULT(1),
                pwd_last_set datetime NULL,
                insert_date datetime NOT NULL DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(domain_id) REFERENCES domains(domain_id),
                FOREIGN KEY(password_id) REFERENCES passwords(password_id),
                UNIQUE(domain_id, name)
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [groups] (
                group_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                name varchar(500) NOT NULL,
                object_identifier TEXT NOT NULL,
                dn TEXT NOT NULL,
                members TEXT NOT NULL DEFAULT(''),
                membership TEXT NOT NULL DEFAULT(''),
                FOREIGN KEY(domain_id) REFERENCES domains(domain_id),
                UNIQUE(name, object_identifier)
            );
        """)

        # criando a tabela (schema)
        cursor.execute("""
                    CREATE TABLE IF NOT EXISTS [pre_computed] (
                        password_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ntlm_hash TEXT NOT NULL,
                        md5_hash TEXT NOT NULL DEFAULT(''),
                        sha1_hash TEXT NOT NULL DEFAULT(''),
                        sha256_hash TEXT NOT NULL DEFAULT(''),
                        sha512_hash TEXT NOT NULL DEFAULT(''),
                        password TEXT NOT NULL,
                        UNIQUE(ntlm_hash)
                    );
                """)

        cursor.execute("""
                    CREATE TABLE IF NOT EXISTS [bloodhound_objects] (
                        object_id TEXT NOT NULL,
                        r_id TEXT NOT NULL DEFAULT(''),
                        object_label TEXT NOT NULL,
                        filter_type TEXT NOT NULL DEFAULT('objectid'),
                        name TEXT NOT NULL DEFAULT(''),
                        props TEXT NOT NULL DEFAULT(''),
                        insert_date datetime not null DEFAULT(strftime('%Y-%m-%d %H:%M:%f', 'NOW', 'localtime')),
                        updated_date datetime not null DEFAULT(strftime('%Y-%m-%d %H:%M:%f', 'NOW', 'localtime')),
                        sync_date datetime not null DEFAULT ('1970-01-01'),
                        UNIQUE(object_id, object_label)
                    );
                """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_bloodhound_objects_id_label
                    ON bloodhound_objects (object_id, object_label);
                """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_bloodhound_objects_sync_date
                    ON bloodhound_objects (sync_date);
                """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_bloodhound_objects_sync_updated_date
                    ON bloodhound_objects (sync_date, updated_date);
                """)

        conn.commit()

        cursor.execute("""
                    CREATE TABLE IF NOT EXISTS [bloodhound_edge] (
                        edge_id TEXT NOT NULL,
                        source_id TEXT NOT NULL,
                        destination_id TEXT NOT NULL,
                        source_label TEXT NOT NULL,
                        target_label TEXT NOT NULL,
                        edge_type TEXT NOT NULL DEFAULT(''),
                        edge_props TEXT NOT NULL DEFAULT(''),
                        source_filter_type TEXT NOT NULL DEFAULT('objectid'),
                        props TEXT NOT NULL DEFAULT(''),
                        insert_date datetime not null DEFAULT(strftime('%Y-%m-%d %H:%M:%f', 'NOW', 'localtime')),
                        updated_date datetime not null DEFAULT(strftime('%Y-%m-%d %H:%M:%f', 'NOW', 'localtime')),
                        sync_date datetime not null DEFAULT ('1970-01-01'),
                        UNIQUE(edge_id)
                    );
                """)

        conn.commit()

        cursor.execute("""
                    CREATE UNIQUE INDEX idx_bloodhound_edge_edge_id 
                    ON bloodhound_edge (edge_id);
                """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_bloodhound_edge_updated_date
                    ON bloodhound_edge (updated_date);
                """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_bloodhound_edge_sync_updated_date
                    ON bloodhound_edge (sync_date, updated_date);
                """)

        conn.commit()

        cursor.execute("""
            INSERT INTO [domains](name) values('default');
        """)

        conn.commit()

        #Must get the constraints
        self.get_constraints()
