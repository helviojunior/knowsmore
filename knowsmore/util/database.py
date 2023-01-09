#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import sys, os.path
import sqlite3
import string, base64

from .color import Color

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
        select count(*) as cnt from [users];
        """)

        data = cursor.fetchall()
        if data:
            return int(data[0][0]) > 0

        conn.close()

        return False

    def checkOpen(self):
        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select count(*) as cnt from [users];
        """)

        conn.close()


    def insertUri(self, uri, result_code, result_length):
        try:
            conn = sqlite3.connect(self.dbName)
            cursor = conn.cursor()

            cursor.execute("""
            insert into [stats] ([uri], [result_code], [result_length])
            VALUES (?,?,?);
            """, (uri, result_code, result_length,))

            conn.commit()

            conn.close()

        except Exception as e:
            Color.pl('{!} {R}Error inserting data:{O} %s{W}' % str(e))
        pass

    def insertStatsL1(self, hash, path):
        try:
            conn = sqlite3.connect(self.dbName)
            cursor = conn.cursor()

            cursor.execute("""
            insert or ignore into [summarized_l1] ([hash], [path])
            VALUES (?,?);
            """, (hash, path,))

            conn.commit()

            conn.close()

        except Exception as e:
            Color.pl('{!} {R}Error inserting data:{O} %s{W}' % str(e))
        pass

    def clearSummarized(self):
        conn = sqlite3.connect(self.dbName)

        cursor = conn.cursor()
        cursor.execute("""
        delete from [summarized_l1];
        """)

        cursor = conn.cursor()
        cursor.execute("""
        delete from [summarized_l2];
        """)

        conn.commit()

        conn.close()

    def insertStatsL2(self, word):
        try:

            if word is None or word.strip() == "":
                return;

            conn = sqlite3.connect(self.dbName)
            cursor = conn.cursor()

            cursor.execute("""
            insert or ignore into [summarized_l2] ([word])
            VALUES (?);
            """, (word,))

            cursor = conn.cursor()
            cursor.execute("""
            update [summarized_l2] set hits = (hits + 1) where [word] = ?;
            """, (word,))

            conn.commit()

            conn.close()

        except Exception as e:
            Color.pl('{!} {R}Error inserting data:{O} %s{W}' % str(e))
        pass

    def selectStats(self):

        ret = []

        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select distinct uri from [stats] where result_code = 200;
        """)

        data = cursor.fetchall()
        if data:
            for row in data:
                ret.append(row[0])

        conn.close()

        return ret

    def selectStatsL1(self):

        ret = []

        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select path from [summarized_l1];
        """)

        data = cursor.fetchall()
        if data:
            for row in data:
                ret.append(row[0])

        conn.close()

        return ret

    def selectStatsL2(self):

        ret = []

        conn = sqlite3.connect(self.dbName)
        cursor = conn.cursor()

        cursor.execute("""
        select word, hits from [summarized_l2] order by hits desc;
        """)

        data = cursor.fetchall()
        if data:
            for row in data:
                ret.append((row[0], row[1]))

        conn.close()

        return ret

    def createDB(self):
        # conectando...
        conn = sqlite3.connect(self.dbName)
        # definindo um cursor
        cursor = conn.cursor()

        # criando a tabela (schema)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [passwords] (
                password_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ntlm_hash TEXT NOT NULL,
                password TEXT NOT NULL DEFAULT(''),
                length INTEGER NOT NULL DEFAULT(0),
                upper INTEGER NOT NULL DEFAULT(0),
                lower INTEGER NOT NULL DEFAULT(0),
                special INTEGER NOT NULL DEFAULT(0),
                company_variation INTEGER NOT NULL DEFAULT(0),
                user_data_variation INTEGER NOT NULL DEFAULT(0)
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [users] (
                id varchar(500),
                domain varchar(500) NOT NULL,
                name varchar(500) NOT NULL,
                password_id INTEGER NOT NULL,
                insert_date datetime not null DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(password_id) REFERENCES passwords(password_id)
            );
        """)

        #print('DB criado com sucesso.')
        # desconectando...
        conn.close()
