#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import sys, os.path
import sqlite3
import string, base64
from sqlite3 import Connection, OperationalError, IntegrityError, ProgrammingError

from .color import Color
from ..password import Password


# TODO: use this decorator to wrap commit/rollback in a try/except block ?
# see http://www.kylev.com/2009/05/22/python-decorators-and-database-idioms/
def connect(func):
    """Decorator to (re)open a sqlite database connection when needed.

    A database connection must be open when we want to perform a database query
    but we are in one of the following situations:
    1) there is no connection
    2) the connection is closed

    Parameters
    ----------
    func : function
        function which performs the database query

    Returns
    -------
    inner func : function
    """

    def inner_func(self, *args, **kwargs):
        if f'{func.__module__}.{func.__qualname__}' != f'{Database.__module__}.{Database.__qualname__}.{func.__name__}':
            raise Exception('The connect decorator cannot be used outside of Database class')

        #print(self)
        #print('Arguments for args: {}'.format(args))
        #print('Arguments for kwargs: {}'.format(kwargs))

        if not isinstance(self, Database):
            raise Exception('The connect decorator cannot be used outside of Database class')

        conn = kwargs.get('conn', None) if kwargs is not None else None
        try:
            # I don't know if this is the simplest and fastest query to try
            conn.execute(
                'SELECT name FROM sqlite_temp_master WHERE type="table";')
            pass
        except (AttributeError, ProgrammingError):
            conn = self.connect_to_db()
            pass

        #nargs = tuple([conn]) + args
        #kwargs.update({'conn': conn})

        return func(self, conn, *args, **kwargs)

    return inner_func

class Database(object):
    db_name = ""

    def __init__(self, auto_create=True, db_name=None):

        self.db_name = db_name

        if not os.path.isfile(self.db_name):
            if auto_create:
                self.create_db()
            else:
                raise Exception("Database not found")

    def connect_to_db(self):
        """Connect to a sqlite DB. Create the database if there isn't one yet.

        Open a connection to a SQLite DB (either a DB file or an in-memory DB).
        When a database is accessed by multiple connections, and one of the
        processes modifies the database, the SQLite database is locked until that
        transaction is committed.

        Parameters
        ----------
        db : str
            database name (without .db extension). If None, create an In-Memory DB.

        Returns
        -------
        connection : sqlite3.Connection
            connection object
        """
        return sqlite3.connect(self.db_name)

    def disconnect_from_db(self, conn):
        if conn is not None:
            conn.close()

    def scrub(self, input_string):
        """Clean an input string (to prevent SQL injection).

        Parameters
        ----------
        input_string : str

        Returns
        -------
        str
        """
        return ''.join(k for k in input_string if k.isalnum() or k in '_-')
    @connect
    def insert_one(self, conn, table_name, **kwargs):
        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)
        sql = "INSERT INTO {} ({}) VALUES ({})" \
            .format(table_name, ','.join(columns), ', '.join(['?'] * len(columns)))
        conn.execute(sql, values)
        conn.commit()
        self.disconnect_from_db(conn)

    @connect
    def insert_ignore_one(self, conn, table_name, **kwargs):
        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)
        sql = "INSERT OR IGNORE INTO {} ({}) VALUES ({})" \
            .format(table_name, ','.join(columns), ', '.join(['?'] * len(columns)))
        conn.execute(sql, values)
        conn.commit()
        self.disconnect_from_db(conn)

    @connect
    def select(self, conn, table_name, **kwargs):

        operator = self.scrub(kwargs.get('__operator', 'and'))

        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)

        sql = f"SELECT * FROM {table_name}"
        if len(columns) > 0:
            sql += " WHERE {}".format(f' {operator} '.join([f'{col} = ?' for col in columns]))

        cursor = conn.execute(sql, values)

        columns = cursor.description
        return [{columns[index][0]: column for index, column in enumerate(value)} for value in cursor.fetchall()]

    def select_first(self, table_name, **kwargs):
        data = self.select(table_name, **kwargs)
        if len(data) == 0:
            return None
        return data[0]

    @connect
    def select_count(self, conn, table_name, **kwargs) -> int:

        operator = self.scrub(kwargs.get('__operator', 'and'))

        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)

        sql = f"SELECT count(*) FROM {table_name}"
        if len(columns) > 0:
            sql += " WHERE {}".format(f' {operator} '.join([f'{col} = ?' for col in columns]))
        cursor = conn.execute(sql, values)
        data = cursor.fetchone()

        return int(data[0])

    @connect
    def update(self, conn, table_name, filter_data, **kwargs):

        operator = self.scrub(kwargs.get('__operator', 'and'))

        table_name = self.scrub(table_name)
        (f_columns, f_values) = self.parse_args(filter_data)
        (u_columns, u_values) = self.parse_args(kwargs)

        sql = f"UPDATE {table_name} SET "
        sql += "{}".format(', '.join([f'{col} = ?' for col in u_columns]))
        if len(f_columns) > 0:
            sql += " WHERE {}".format(f' {operator} '.join([f'{col} = ?' for col in f_columns]))
        conn.execute(sql, tuple(u_values + f_values,))
        conn.commit()
        self.disconnect_from_db(conn)

    def parse_args(self, source_dict) -> tuple:
        if source_dict is None:
            return [], tuple([])

        if not isinstance(source_dict, dict):
            raise Exception('kwargs is not a dictionary')

        columns = []
        values = []

        for key, value in source_dict.items():
            try:
                if key[0:2] != '__':
                    columns.append(f"[{self.scrub(key)}]")
                    values.append(value)
            except Exception as e:
                raise Exception(f'Error parsing {key}: {value}', e)

        return columns, tuple(values,)


    @connect
    def create_db(self, conn):

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
                dn TEXT NOT NULL DEFAULT(''),
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

