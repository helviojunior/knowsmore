#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import sys, os.path
import sqlite3
import string, base64
from sqlite3 import Connection

from .color import Color
from ..password import Password


class Database(object):
    dbName = ""

    def __init__(self, auto_create=True, db_name=None):

        if db_name is None:
            self.dbName = "knowsmore.db"
        else:
            self.dbName = db_name

        if not os.path.isfile(self.dbName):
            if auto_create:
                self.createDB()
            else:
                raise Exception("Database not found")

    def hasData(self):
        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select count(*) as cnt from [credentials];
        """)

        data = cursor.fetchall()
        if data:
            return int(data[0][0]) > 0

        conn.close()

        return False

    def get_connection(self):
        return sqlite3.connect(self.dbName)

    def checkOpen(self):
        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select count(*) as cnt from [credentials];
        """)

        conn.close()

    def insert_group(self, domain: int, object_identifier: str, name: str, dn: str = '', members: str = '', membership: str = '') -> int:

        if domain is -1:
            raise Exception('Invalid domain')

        if object_identifier is None or object_identifier.strip() == '':
            raise Exception('object_identifier cannot be empty')

        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        insert or ignore into [groups](domain_id, name, object_identifier, dn, members, membership) values (?, ?, ?, ?, ?, ?);
            """, (domain, name, object_identifier, dn, members, membership,))

        conn.commit()
        conn.close()

    def update_password(self, password: Password):
        try:
            conn = sqlite3.connect(self.dbName)
            cursor = conn.cursor()

            cursor.execute("""
                            update [passwords] set 
                            password = ?
                            , length = ?
                            , upper = ?
                            , lower = ?
                            , digit = ?
                            , special = ?
                            , latin = ?
                            WHERE password = '' and ntlm_hash = ?;
                            """,
                           (password.clear_text,
                            password.length,
                            password.upper,
                            password.lower,
                            password.digit,
                            password.special,
                            password.latin,
                            password.ntlm_hash,
                            ))

            conn.commit()

            conn.close()

        except Exception as e:
            Color.pl('{!} {R}Error inserting data:{O} %s{W}' % str(e))
        pass

    def insert_credential(self, domain: int, username: str, ntlm_hash: str, type: str = 'U'):
        try:
            conn = sqlite3.connect(self.dbName)
            cursor = conn.cursor()

            password_id = self.get_password_by_hash(domain, ntlm_hash, conn=conn)

            if password_id == -1:
                cursor.execute("""
                insert or ignore into [passwords] ([domain_id], [ntlm_hash])
                VALUES (?,?);
                """, (domain, ntlm_hash,))

                conn.commit()

            password_id = self.get_password_by_hash(domain, ntlm_hash, conn=conn)

            if password_id == -1:
                raise Exception('Password not found at database')

            # Create default empty password hash
            if ntlm_hash == '31d6cfe0d16ae931b73c59d7e0c089c0':
                pwd = Password(
                    ntlm_hash='31d6cfe0d16ae931b73c59d7e0c089c0',
                    clear_text=''
                )
                pwd.clear_text = '(empty)'
                self.update_password(pwd)

            cursor.execute("""
                insert or ignore into [credentials] ([domain_id], [name], [password_id], [type])
                VALUES (?,?,?,?);
                """, (domain, username, password_id, type,))

            conn.commit()

            conn.close()

        except Exception as e:
            Color.pl('{!} {R}Error inserting data:{O} %s{W}' % str(e))
        pass

    def insert_or_get_domain(self, domain: str, dn: str = '', object_identifier: str = '') -> int:

        if domain is None or domain.strip() == '':
            raise Exception('Domain cannot be empty')

        domain = domain.lower()
        dn = '' if dn is None else dn.lower()
        object_identifier = '' if object_identifier is None else object_identifier.strip()
        domain_id = self.get_domain(domain)

        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        if domain_id == -1:
            cursor.execute("""
            insert or ignore into [domains](name, dn, object_identifier) values (?, ?, ?);
                """, (domain, dn, object_identifier,))
        else:
            cursor.execute("""
            update [domains] set dn = ?, object_identifier = ? where domain_id = ?;
                """, (dn, object_identifier, domain_id,))

        conn.commit()
        conn.close()

        domain_id = self.get_domain(domain)

        return domain_id

    def get_domain(self, domain: str) -> int:

        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select domain_id from [domains] where [name] = ?;
            """, (domain,))

        domain_id = -1
        data = cursor.fetchall()
        if data:
            domain_id = data[0][0]

        conn.close()

        return domain_id

    def get_domain_by_sid(self, sid: str) -> int:

        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select domain_id from [domains] where [object_identifier] = ? and  [object_identifier] <> '';
            """, (sid,))

        domain_id = -1
        data = cursor.fetchall()
        if data:
            domain_id = data[0][0]

        conn.close()

        return domain_id

    def get_password_by_hash(self, domain: int, ntlm_hash: str, conn: Connection = None) -> int:

        close = True
        if conn is not None:
            close = False
            conn = sqlite3.connect(self.dbName)

        cursor = conn.cursor()

        cursor.execute("""
        select password_id from [passwords] where [domain_id] = ? and [ntlm_hash] = ?;
            """, (domain, ntlm_hash,))

        password_id = -1
        data = cursor.fetchall()
        if data:
            password_id = data[0][0]

        if close:
            conn.close()

        return password_id


    def createDB(self):
        # conectando...
        conn = sqlite3.connect(self.dbName)
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
                password TEXT NOT NULL DEFAULT(''),
                length INTEGER NOT NULL DEFAULT(0),
                upper INTEGER NOT NULL DEFAULT(0),
                lower INTEGER NOT NULL DEFAULT(0),
                digit INTEGER NOT NULL DEFAULT(0),
                special INTEGER NOT NULL DEFAULT(0),
                latin INTEGER NOT NULL DEFAULT(0),
                company_variation INTEGER NOT NULL DEFAULT(0),
                user_data_variation INTEGER NOT NULL DEFAULT(0),
                UNIQUE(domain_id, ntlm_hash)
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [credentials] (
                credential_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                type varchar(1) NOT NULL  DEFAULT('U'),
                name varchar(500) NOT NULL,
                object_identifier TEXT NOT NULL DEFAULT(''),
                groups TEXT NOT NULL DEFAULT(''),
                password_id INTEGER NOT NULL,
                insert_date datetime not null DEFAULT (datetime('now','localtime')),
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

        conn.commit()

        cursor.execute("""
            INSERT INTO [domains](name) values('default');
        """)

        conn.commit()

        #print('DB criado com sucesso.')
        # desconectando...
        conn.close()


