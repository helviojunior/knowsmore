#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import sys, os.path
import sqlite3
import string, base64
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

        grp = self.select('groups',
                          object_identifier=object_identifier
                          )

        if len(grp) == 0:
            self.insert_one('groups',
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
        print(credentials)
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

        for row in self.select('domains'):

            passwd = self.select_first('passwords', domain_id=row['domain_id'], ntlm_hash=password.ntlm_hash)
            password_id = -1 if passwd is None else passwd['password_id']

            if password_id == -1:
                self.insert_one('passwords', domain_id=row['domain_id'], ntlm_hash=password.ntlm_hash)
                self.update_password(password, **kwargs)
            else:
                self.update_password(password, **kwargs)




    def insert_or_update_credential(self, domain: int, username: str, ntlm_hash: str,
                                    dn: str = '', groups: str = '', object_identifier: str = '',
                                    type: str = 'U'):
        try:

            # Hard-coded empty password
            update_password = True
            if ntlm_hash is None or ntlm_hash.strip == '':
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

            cred = self.select_first('credentials',
                                     domain_id=domain,
                                     name=username,
                                     type=type
                                     )
            cred_id = -1 if cred is None else cred['credential_id']

            if cred_id == -1:
                self.insert_ignore_one('credentials',
                                       domain_id=domain,
                                       name=username,
                                       password_id=password_id,
                                       dn=dn if dn is not None else '',
                                       object_identifier=object_identifier if object_identifier is not None else '',
                                       groups=groups if groups is not None else '',
                                       type=type
                                       )
            else:
                data = {
                    'domain_id': domain,
                    'name': username,
                    'type': type
                }
                if dn is not None:
                    data['dn'] = dn
                if groups is not None:
                    data['groups'] = groups
                if object_identifier is not None:
                    data['object_identifier'] = object_identifier
                if update_password:
                    data['password_id'] = password_id

                self.update('credentials', {'credential_id': cred_id}, **data)

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
