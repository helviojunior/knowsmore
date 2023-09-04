#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import math
import shutil
import sys, os.path
import sqlite3
import string, base64
from functools import reduce
from sqlite3 import Connection, OperationalError, IntegrityError, ProgrammingError


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

        if not isinstance(self, Database):
            raise Exception('The connect decorator cannot be used outside of Database class')

        conn = kwargs.get('conn', None) if kwargs is not None else None
        if conn is None:
            conn = self.connect_to_db()

        return func(self, conn, *args, **kwargs)

    return inner_func


class Database(object):
    db_name = ""

    # Static value
    db_connection = None
    constraints = []

    def __init__(self, auto_create=True, db_name=None):

        self.db_name = db_name

        if not os.path.isfile(self.db_name):
            if auto_create:
                self.create_db()
            else:
                raise Exception("Database not found")
        else:
            self.connect_to_db()

    @connect
    def insert_one(self, conn: Connection, table_name, **kwargs):
        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)
        sql = "INSERT INTO {} ({}) VALUES ({})" \
            .format(table_name, ','.join(columns), ', '.join(['?'] * len(columns)))
        conn.execute(sql, values)
        conn.commit()

    @connect
    def insert_ignore_one(self, conn: Connection, table_name, **kwargs):
        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)
        sql = "INSERT OR IGNORE INTO {} ({}) VALUES ({})" \
            .format(table_name, ','.join(columns), ', '.join(['?'] * len(columns)))
        conn.execute(sql, values)
        conn.commit()

    @connect
    def insert_replace_one(self, conn: Connection, table_name, **kwargs):
        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)
        sql = "INSERT OR REPLACE INTO {} ({}) VALUES ({})" \
            .format(table_name, ','.join(columns), ', '.join(['?'] * len(columns)))
        conn.execute(sql, values)
        conn.commit()

    def insert_update_one(self, table_name: str, **kwargs):
        return self.insert_update_one_exclude(table_name, [], **kwargs)

    @connect
    def insert_update_one_exclude(self, conn: Connection, table_name: str, exclude_on_update: list = [], **kwargs) -> dict:
        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)
        sql = "INSERT OR IGNORE INTO {} ({}) VALUES ({})" \
            .format(table_name, ','.join(columns), ', '.join(['?'] * len(columns)))
        c = conn.execute(sql, values)

        status = {'inserted': c.rowcount, 'updated': 0}

        # No inserted, need to update
        if c.rowcount == 0:
            table_name = self.scrub(table_name)
            f_columns = self.constraints[table_name]
            f_values = tuple([kwargs.get(c, None) for c in f_columns],)
            args = {k: v for k, v in kwargs.items() if k not in exclude_on_update}
            (u_columns, u_values) = self.parse_args(args)

            sql = f"UPDATE {table_name} SET "
            sql += "{}".format(', '.join([f'{col} = ?' for col in u_columns]))
            if len(f_columns) > 0:
                sql += " WHERE {}".format(f' and '.join([f'{col} = ?' for col in f_columns]))
            c = conn.execute(sql, tuple(u_values + f_values, ))
            conn.commit()

            status['updated'] = c.rowcount

        conn.commit()
        return status

    @connect
    def select(self, conn: Connection, table_name, **kwargs):

        operator = self.scrub(kwargs.get('__operator', 'and'))

        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)

        sql = f"SELECT * FROM {table_name}"
        if len(columns) > 0:
            sql += " WHERE {}".format(f' {operator} '.join([f'{col} = ?' for col in columns]))

        cursor = conn.execute(sql, values)
        if cursor.rowcount == 0:
            return []

        columns = cursor.description
        return [{columns[index][0]: column for index, column in enumerate(value)} for value in cursor.fetchall()]

    def select_first(self, table_name, **kwargs):
        data = self.select(table_name, **kwargs)
        if len(data) == 0:
            return None
        return data[0]

    @connect
    def select_raw(self, conn: Connection, sql: str, args: any):
        cursor = conn.execute(sql, tuple(args,))
        if cursor.rowcount == 0:
            return []
        columns = cursor.description
        return [{columns[index][0]: column for index, column in enumerate(value)} for value in cursor.fetchall()]

    @connect
    def select_count(self, conn: Connection, table_name, **kwargs) -> int:

        operator = self.scrub(kwargs.get('__operator', 'and'))

        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)

        sql = f"SELECT count(*) FROM {table_name}"
        if len(columns) > 0:
            sql += " WHERE {}".format(f' {operator} '.join([f'{col} = ?' for col in columns]))
        cursor = conn.execute(sql, values)
        if cursor.rowcount == 0:
            return 0
        data = cursor.fetchone()

        return int(data[0])

    @connect
    def delete(self, conn: Connection, table_name, **kwargs) -> None:

        operator = self.scrub(kwargs.get('__operator', 'and'))

        table_name = self.scrub(table_name)
        (columns, values) = self.parse_args(kwargs)

        sql = f"DELETE FROM {table_name}"
        if len(columns) > 0:
            sql += " WHERE {}".format(f' {operator} '.join([f'{col} = ?' for col in columns]))
        conn.execute(sql, values)
        conn.commit()

    @connect
    def update(self, conn: Connection, table_name, filter_data, **kwargs):

        operator = self.scrub(kwargs.get('__operator', 'and'))

        table_name = self.scrub(table_name)
        (f_columns, f_values) = self.parse_args(filter_data)
        (u_columns, u_values) = self.parse_args(kwargs)

        sql = f"UPDATE {table_name} SET "
        sql += "{}".format(', '.join([f'{col} = ?' for col in u_columns]))
        if len(f_columns) > 0:
            sql += " WHERE {}".format(f' {operator} '.join([f'{col} = ?' for col in f_columns]))
        conn.execute(sql, tuple(u_values + f_values, ))
        conn.commit()

    def get_constraints(self) -> dict:
        sql = ('SELECT '
               '  m.tbl_name AS table_name, '
               '  il.name AS key_name, '
               '  ii.name AS column_name '
               'FROM  '
               '  sqlite_master AS m,  '
               '  pragma_index_list(m.name) AS il,  '
               '  pragma_index_info(il.name) AS ii  '
               'WHERE  '
               '  m.type = "table" AND  '
               '  il.origin = "u"  '
               'ORDER BY table_name, key_name, ii.seqno')

        cursor = self.db_connection.execute(sql)
        columns = cursor.description
        db_scheme = [{columns[index][0]: column for index, column in enumerate(value)} for value in cursor.fetchall()]

        if len(db_scheme) > 0:
            self.constraints = reduce(lambda a, b: {**a, **b},
                                      [{table: [
                                            v['column_name'] for idx, v in enumerate(db_scheme)
                                            if v['table_name'] == table
                                        ]} for table in set([t['table_name'] for t in db_scheme])])
        else:
            self.constraints = {}

        return self.constraints

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

        return columns, tuple(values, )

    def connect_to_db(self, check: bool = True) -> Connection:
        """Connect to a sqlite DB. Create the database if there isn't one yet.

        Open a connection to a SQLite DB (either a DB file or an in-memory DB).
        When a database is accessed by multiple connections, and one of the
        processes modifies the database, the SQLite database is locked until that
        transaction is committed.

        Returns
        -------
        connection : sqlite3.Connection
            connection object
        """

        if self.db_connection is not None:
            return self.db_connection

        conn = sqlite3.connect(self.db_name, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        conn.create_function('log', 2, math.log)

        if check:
            try:
                # I don't know if this is the simplest and fastest query to try
                conn.execute(
                    'SELECT name FROM sqlite_temp_master WHERE type="table";')
                pass
            except (AttributeError, ProgrammingError) as e:
                raise Exception(f'Fail connecting to SQLite file: {self.db_name}', e)

        shutil.copy(self.db_name, f'{self.db_name}.bkp')

        cursor = conn.cursor()
        # www.sqlite.org/pragma.html
        # https://blog.devart.com/increasing-sqlite-performance.html
        cursor.execute("PRAGMA temp_store = MEMORY")
        # cursor.execute("PRAGMA page_size = 4096")
        # cursor.execute("PRAGMA cache_size = 10000")
        #cursor.execute("PRAGMA locking_mode=EXCLUSIVE")
        cursor.execute("PRAGMA synchronous=OFF")
        cursor.execute("PRAGMA journal_mode=MEMORY")
        # cursor.execute("PRAGMA foreign_keys=ON")

        #cursor.execute("PRAGMA synchronous=OFF")
        #cursor.execute("PRAGMA busy_timeout=15000")  # milliseconds
        #cursor.execute("PRAGMA lock_timeout=5000")  # milliseconds

        self.db_connection = conn

        # get database constraints
        self.get_constraints()

        return self.db_connection

    def scrub(self, input_string):
        return Database.scrub(input_string)

    @staticmethod
    def scrub(input_string):
        """Clean an input string (to prevent SQL injection).

        Parameters
        ----------
        input_string : str

        Returns
        -------
        str
        """
        return ''.join(k for k in input_string if k.isalnum() or k in '_-')

    def create_db(self):
        raise Exception('Method "create_db" is not yet implemented.')