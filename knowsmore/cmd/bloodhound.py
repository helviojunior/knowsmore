# BloodHound Sources
#  https://github.com/BloodHoundAD/BloodHound/blob/master/src/js/newingestion.js
#  https://github.com/BloodHoundAD/BloodHound/blob/master/src/js/utils.js
#

import datetime
import errno
import json
import os
import queue
import re
import shutil
import sqlite3
import threading
import time
import mimetypes
import tempfile
import logging
from enum import Enum
from pathlib import Path
from zipfile import ZipFile
from argparse import _ArgumentGroup, Namespace
from clint.textui import progress
from neo4j import GraphDatabase, exceptions, Session, Transaction
from neo4j.exceptions import ClientError
from neo4j.meta import ExperimentalWarning
import warnings

from knowsmore.cmdbase import CmdBase
from knowsmore.config import Configuration
from knowsmore.libs.bloodhoundsync import BloodhoundSync
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools

warnings.filterwarnings("ignore", category=ExperimentalWarning)


class Bloodhound(CmdBase):
    class ImportMode(Enum):
        Undefined = 0
        Import = 1
        MarkOwned = 2
        Sync = 3

    filename = ''
    db = None
    chain_enabled = False
    domain_cache = {}
    mode = ImportMode.Undefined
    synced = []
    tasks = 6

    class BloodhoundFile:
        file_name = None
        type = 'unknown'
        items = 0
        version = 0
        order = 99999
        bh_connection = None

        def __init__(self, file_name: str):
            self.file_name = file_name

            try:
                #json_data = self.get_json()

                meta = self.get_meta()
                self.type = meta.get('type', 'unknown').lower()
                self.items = meta.get('count', 0)
                self.version = meta.get('version', 0)

                if self.type == "domains":
                    self.order = 1
                elif self.type == "groups":
                    self.order = 2
                elif self.type == "computers":
                    self.order = 3
                elif self.type == "users":
                    self.order = 4

                if Configuration.verbose >= 2:
                    Color.pl('{*} {W}{D}%s: type {G}%s{W}{D}, version {G}%d{W}' % (
                        self.file_name, self.type, self.version))

            except KeyboardInterrupt as e:
                raise e
            except:
                pass

        def get_meta(self):
            with open(self.file_name, 'rb') as js:
                # Obtain meta tag
                js.seek(-0x100, os.SEEK_END)
                lastbytes = str(js.read(0x100), 'utf-8').strip()
                metatagstr = re.search(r'"meta":\s*{(?:.|\n)*?}', lastbytes, re.MULTILINE | re.IGNORECASE).group(0)
                metatag = json.loads('{' + metatagstr + '}')
                return metatag.get('meta', {})

        def get_json(self):
            try:
                with open(self.file_name, 'r', encoding="UTF-8", errors="surrogateescape") as f:
                    return json.load(f)
            except json.decoder.JSONDecodeError as e:
                if 'utf-8-sig' in str(e):
                    with open(self.file_name, 'r', encoding="utf-8-sig", errors="surrogateescape") as f:
                        return json.load(f)
                else:
                    with open(self.file_name, 'r', encoding="latin-1", errors="surrogateescape") as f:
                        return json.load(f)

    class BloodHoundVersion:
        major = 0
        minor = 0
        release = ''
        name = ''
        edition = ''

        def __init__(self, name: str, edition: str, version: str):
            from pkg_resources import parse_version

            v = parse_version(version)

            self.major = v.major
            self.minor = v.minor
            self.release = version.replace(f"{self.major}.{self.minor}", "").strip(". ")
            self.name = name
            self.edition = edition

        def __str__(self):
            return f"{self.name} {self.edition} v{self.major}.{self.minor}.{self.release}"

    class BloodHoundConnection:

        database = None
        version = None
        groups = {}

        def __init__(self, uri, user, password, database):
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            try:
                self.driver.verify_connectivity()

                self.version = self.get_version()

            except exceptions.ServiceUnavailable as e:
                raise e
            except exceptions.AuthError as e:
                raise e
            except Exception as e:
                #print(e.__class__)
                raise e

            self.database = database
            self.groups = {}

        def close(self):
            self.driver.close()

        def get_all_owned(self) -> list:
            with self.driver.session(database=self.database) as session:
                return session.execute_read(self._get_owned)

        def set_owned(self, source_filter_type: str, source_label: str, source:str, owned: bool = True):
            with self.driver.session(database=self.database) as session:
                return session.execute_write(self._set_owned, source_filter_type, source_label, source, owned)

        def get_session(self) -> Session:
            return self.driver.session(database=self.database)

        @staticmethod
        def execute(tx: Transaction, query, **data):
            tx.run(query, **data)

        @staticmethod
        def _get_owned(tx: Transaction):
            accounts = []
            result = tx.run("MATCH (n) WHERE n.owned IS NOT NULL RETURN n.name as name, n.owned as owned")
            for record in result:
                accounts.append(
                    {
                        'name': record.get("name", None),
                        'owned': record.get("owned", None),
                    }
                )
            return accounts

        @staticmethod
        def _set_owned(tx: Transaction, source_filter_type: str, source_label: str, source: str, owned: bool = True):
            query = 'UNWIND $props AS prop MATCH (n:Base {{{0}: prop.objectid}}) SET n:{1} SET n += prop.map RETURN n.name as name, n.owned as owned LIMIT 1'
            #query = 'UNWIND $props AS prop MERGE (n:Base {{{0}: prop.source}}) ON MATCH SET n:{1} ON CREATE SET n:{1} SET n += prop.map RETURN n.name as name, n.owned as owned LIMIT 1'
            #query = "UNWIND $props AS prop MATCH (n:{1} {{0}: prop.source}) SET n += prop.map RETURN n.name as name, n.owned as owned LIMIT 1"\
            query = query.format(source_filter_type, source_label)
            result = tx.run(query,
                            props=dict(objectid=source.upper(), map=dict(owned=owned))
                            )
            rst = result.single()
            if rst is None:
                return None

            ret_data = {
                'name': rst.get("name", None),
                'owned': rst.get("owned", None),
            }
            return ret_data

        def set_schema(self):
            """Adds bloodhound schema to neo4j

            Arguments:
                tx {neo4j.Transaction} -- Neo4j transaction.
            """
            luceneIndexProvider = "lucene+native-3.0"
            labels = ["User", "Group", "Computer", "GPO", "OU", "Domain", "Container", "Base",
                      "AZBase", "AZApp", "AZDevice", "AZGroup", "AZKeyVault", "AZResourceGroup",
                      "AZServicePrincipal", "AZTenant", "AZUser", "AZVM"]
            azLabels = ["AZBase", "AZApp", "AZDevice", "AZGroup", "AZKeyVault", "AZResourceGroup",
                        "AZServicePrincipal", "AZTenant", "AZUser", "AZVM"]
            schema = {}
            for label in labels:
                schema[label] = dict(
                    name=label,
                    indexes=[dict(
                        name="{}_{}_index".format(label.lower(), "name"),
                        provider=luceneIndexProvider,
                        property="name"
                    )],
                    constraints=[dict(
                        name="{}_{}_constraint".format(label.lower(), "objectid"),
                        provider=luceneIndexProvider,
                        property="objectid"
                    )],
                )

            for label in azLabels:
                schema[label]["indexes"].append({
                    'name': "{}_{}_index".format(label.lower(), "azname"),
                    'provider': luceneIndexProvider,
                    'property': "azname"
                })

            for label in labels:
                for constraint in schema[label]['constraints']:

                    try:
                        if self.version.major >= 5:
                            query = f"CREATE CONSTRAINT {constraint['name']} IF NOT EXISTS FOR (b:{label}) REQUIRE b.{constraint['property']} IS UNIQUE"

                            with self.driver.session(database=self.database) as session:
                                session.execute_write(self.execute, query)

                        else:
                            query = f"CREATE CONSTRAINT {constraint['name']} IF NOT EXISTS ON (b:{label}) ASSERT b.{constraint['property']} IS UNIQUE"

                            with self.driver.session(database=self.database) as session:
                                session.write_transaction(self.execute, query)

                    except Exception as e:
                        #print(e)
                        pass

                for index in schema[label]['indexes']:
                    props = dict(
                        name=index['name'],
                        label=[label],
                        properties=[index['property']],
                        provider=index['provider']
                    )
                    try:
                        if self.version.major >= 5:
                            query = f"CREATE INDEX {index['name']} IF NOT EXISTS FOR (b:{label}) ON (b.{index['property']})"

                            with self.driver.session(database=self.database) as session:
                                session.execute_write(self.execute, query, **props)
                        else:
                            query = "CALL db.createIndex($name, $label, $properties, $provider)"

                            with self.driver.session(database=self.database) as session:
                                session.write_transaction(self.execute, query)

                        #print(query)

                    except Exception as e:
                        #print(e)
                        pass

        def get_version(self) -> list:
            try:
                with self.driver.session(database=self.database) as session:
                    return session.execute_read(self._get_version)
            except:
                with self.driver.session(database=self.database) as session:
                    return session.read_transaction(self._get_version)

        @staticmethod
        def _get_version(tx: Transaction):
            result = tx.run(
                "call dbms.components() yield name, versions, edition unwind versions as version return name, version, edition;",
                )
            rst = result.single()
            if rst is None:
                return None

            return Bloodhound.BloodHoundVersion(
                name=rst.get("name", None),
                version=rst.get("version", '0.0.0'),
                edition=rst.get("edition", None)
            )

    def __init__(self):
        super().__init__('bloodhound', 'Import BloodHound files')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('-T',
                           action='store',
                           metavar='[tasks]',
                           type=int,
                           default=6,
                           dest=f'tasks',
                           help=Color.s('number of connects in parallel (per host, default: 6)'))

        flags.add_argument('--enable-group-chain',
                           action='store_true',
                           default=False,
                           dest=f'chain_enabled',
                           help=Color.s('Enable group chain calculation.'))

        flags.add_argument('-u',
                           action='store',
                           metavar='[neo4j username]',
                           type=str,
                           default='neo4j',
                           dest=f'neo4j_username',
                           help=Color.s('Neo4j Username to mark host/users as owned. (default: neo4j)'))

        flags.add_argument('-p',
                           action='store',
                           metavar='[neo4j password]',
                           type=str,
                           default='neo4j',
                           dest=f'neo4j_password',
                           help=Color.s('Neo4j Password to mark host/users as owned. (default: neo4j)'))

        flags.add_argument('-d',
                           action='store',
                           metavar='[neo4j database]',
                           type=str,
                           default='neo4j',
                           dest=f'neo4j_database',
                           help=Color.s('Neo4j Database to mark host/users as owned. (default: neo4j)'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--import-data',
                          action='store',
                          metavar='[bloodhound file]',
                          type=str,
                          dest=f'bhfile',
                          help=Color.s('BloodHound file. Available parses: {G}.zip{W} and {G}.json{W}'))

        cmds.add_argument('--mark-owned',
                          action='store',
                          metavar='[neo4j host and port]',
                          type=str,
                          dest=f'neo4j_host',
                          help=Color.s('BloodHound Neo4j Database. host:port'))

        cmds.add_argument('--sync-to',
                          action='store',
                          metavar='[neo4j host and port]',
                          type=str,
                          dest=f'neo4j_host2',
                          help=Color.s('BloodHound Neo4j Database. host:port'))

    def load_from_arguments(self, args: Namespace) -> bool:
        if (args.neo4j_host is not None and args.neo4j_host != '') or \
                (args.neo4j_host2 is not None and args.neo4j_host2 != ''):

            host = args.neo4j_host
            self.mode = Bloodhound.ImportMode.MarkOwned

            if args.neo4j_host2 is not None and args.neo4j_host2 != '':
                self.mode = Bloodhound.ImportMode.Sync
                host = args.neo4j_host2

            port = 7687
            if ':' in host:
                (host, port) = host.split(':', 2)

            try:
                self.bh_connection = Bloodhound.BloodHoundConnection(
                    f'bolt://{host}:{port}',
                    args.neo4j_username,
                    args.neo4j_password,
                    args.neo4j_database,
                )

            except Exception as e:
                Logger.pl('{!} {R}error: Fail to connect with Neo4j Database: {O}%s{R} {W}\r\n' % (
                    e))
                Tools.exit_gracefully(1)

            #try:
            #    self.bh_connection.add_constraints()
            #except ClientError:
            #    pass
            #except Exception as e:
            #    Logger.pl('{!} {R}error: Fail adding BloodHound constraints Neo4j Database: {O}%s{R} {W}\r\n' % (
            #        e))
            #    Tools.exit_gracefully(1)

        elif args.bhfile is not None and args.bhfile.strip() != '':

            if not os.path.isfile(args.bhfile):
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
            self.chain_enabled = args.chain_enabled
            self.mode = Bloodhound.ImportMode.Import

        if self.mode == Bloodhound.ImportMode.Undefined:
            Logger.pl('{!} {R}error: Nor {O}--import-data{R} or {O}--mark-owned{R} was provided{W}\r\n')
            Tools.exit_gracefully(1)

        if args.tasks >= 1:
            self.tasks = int(args.tasks)

        self.db = self.open_db(args)

        Logger.pl('     {C}operational mode:{O} %s{W}' % self.mode)

        return True

    def thread_start_callback(self, index, **kwargs):
        return self.bh_connection.get_session()

    def bh_callback1(self, entry, thread_callback_data, **kwargs):
        #print(entry, thread_callback_data)

        #https://github.com/BloodHoundAD/BloodHound/blob/master/src/js/newingestion.js

        #query = 'UNWIND $props AS prop MERGE (n:Base {{{0}: prop.source}}) ON MATCH SET n:{1} ON CREATE SET n:{1} SET n += prop.map'
        query = 'UNWIND $props AS prop MERGE (n:Base {{{0}:prop.objectid}}) SET n:{1} SET n += prop.map'
        query = query.format(entry['filter_type'], entry['object_label'])

        props = dict(
            props=dict(
                map=json.loads(entry['props']),
                objectid=entry['object_id'].upper()
            )
        )

        thread_callback_data.write_transaction(
            Bloodhound.BloodHoundConnection.execute,
            query,
            **props)

        self.synced.append(str(entry['object_id']))

    def bh_callback2(self, entry, thread_callback_data, **kwargs):


        #https://github.com/BloodHoundAD/BloodHound/blob/master/src/js/newingestion.js


        # Merge source and target object too
        #insert_query = 'UNWIND $props AS prop MERGE (n:Base {{{0}: prop.source}}) ON MATCH SET n:{1} ON CREATE SET n:{1} MERGE (m:Base {{objectid: prop.target}}) ON MATCH SET m:{2} ON CREATE SET m:{2} MERGE (n)-[r:{3} {4}]->(m)'
        insert_query = 'UNWIND $props AS prop MERGE (n:Base {{{0}: prop.source}}) SET n:{1} MERGE (m:Base {{objectid: prop.target}}) SET m:{2} MERGE (n)-[r:{3} {4}]->(m)'

        # Merge only the relationship from source and target
        #insert_query = 'UNWIND $props AS prop MATCH (n:Base {{{0}: prop.source}}) MATCH (m:Base {{objectid: prop.target}}) MERGE (n)-[r:{3} {4}]->(m)'

        #Replace all tags
        insert_query = insert_query.format(entry['source_filter_type'],
                                           entry['source_label'],
                                           entry['target_label'],
                                           entry['edge_type'],
                                           entry['edge_props'])

        props = dict(
            props=json.loads(entry['props']),
        )

        #print(insert_query)
        thread_callback_data.write_transaction(
            Bloodhound.BloodHoundConnection.execute,
            insert_query,
            **props)

        self.synced.append(str(entry['edge_id']))

    def status(self, text, sync, total):
        with progress.Bar(label=" %s " % text, expected_size=total) as bar:
            try:
                while sync.running:
                    ex = sync.executed
                    if ex > total:
                        bar.expected_size = ex
                    bar.show(ex)
                    time.sleep(0.3)
            except KeyboardInterrupt as e:
                raise e
            except:
                pass
            finally:
                bar.hide = True
                Tools.clear_line()
                sync.close()

        return

    def mark_owned(self):
        Color.pl('{?} {W}{D}Syncing owned objects...{W}')

        db_cracked = self.db.select_raw(
            sql='select c.name, d.name as domain_name, c.type, c.object_identifier from credentials as c '
                'inner join passwords as p '
                'on c.password_id  = p.password_id  '
                'inner join domains as d '
                'on c.domain_id = d.domain_id  '
                'where p.length > 0',
            args=[]
        )

        if len(db_cracked) > 0:
            with progress.Bar(label=" Marking as owned ", expected_size=len(db_cracked)) as bar:
                try:
                    for idx, row in enumerate(db_cracked):
                        bar.show(idx)

                        label = "Computer" if row['type'] == "M" else "User"
                        if row['object_identifier'] is not None and row['object_identifier'].strip() != '':
                            filter_type = "objectid"
                            source = row['object_identifier']
                        else:
                            filter_type = "name"
                            source = f'{row["name"]}@{row["domain_name"]}'.upper()
                            if row['type'] == "M":
                                source = f'{row["name"]}.{row["domain_name"]}'.upper()

                        self.bh_connection.set_owned(
                            source_filter_type=filter_type,
                            source_label=label,
                            source=source,
                            owned=True
                        )

                    # print(self.bh_connection.get_all_owned())

                except KeyboardInterrupt as e:
                    raise e
                finally:
                    bar.hide = True
                    Tools.clear_line()

    def run(self):

        # Disable warning logs of neo4j driver
        logging.getLogger().setLevel(logging.DEBUG)

        if self.mode == Bloodhound.ImportMode.MarkOwned:
            try:
                Color.pl('{?} {W}{D}Setting neo4j bloodhound schema...{W}')
                self.bh_connection.set_schema()
            except ClientError:
                pass
            except Exception as e:
                Logger.pl('{!} {R}error: Fail adding BloodHound schema Neo4j Database: {O}%s{R} {W}\r\n' % (
                    e))
                Tools.exit_gracefully(1)

            self.mark_owned()

        elif self.mode == Bloodhound.ImportMode.Sync:
            try:
                Color.pl('{?} {W}{D}Setting neo4j bloodhound schema...{W}')
                self.bh_connection.set_schema()
            except ClientError:
                pass
            except Exception as e:
                Logger.pl('{!} {R}error: Fail adding BloodHound schema Neo4j Database: {O}%s{R} {W}\r\n' % (
                    e))
                Tools.exit_gracefully(1)

            Color.pl('{?} {W}{D}Syncing objects...{W}')

            db_sync_count = self.db.select_raw(
                sql='select count(*) as qty from bloodhound_objects '
                    'where sync_date <= updated_date',
                args=[]
            )
            total = int(db_sync_count[0]['qty'])

            if total > 0:
                if total > 10000:
                    Color.pl('{?} {W}{D}this could take a while so go grab a redbull...{W}')

                with BloodhoundSync(callback=self.bh_callback1, per_thread_callback=self.thread_start_callback, threads=self.tasks) as t:
                    t.start()

                    t1 = threading.Thread(target=self.status, kwargs=dict(sync=t, total=total, text="Syncing objects (step 1/4)"))
                    t1.daemon = True
                    t1.start()

                    try:

                        while True:
                            for idx, row in enumerate(self.synced):
                                self.db.update(
                                    'bloodhound_objects',
                                    filter_data={'object_id': row},
                                    updated_date=datetime.datetime.now() - datetime.timedelta(seconds=60),
                                    sync_date=datetime.datetime.now()
                                )
                            self.synced = []

                            while t.count > 1000:
                                time.sleep(0.3)

                            db_sync = self.db.select_raw(
                                sql='select * from bloodhound_objects '
                                    'where sync_date <= updated_date '
                                    'order by updated_date ASC '
                                    'limit 10000',
                                args=[]
                            )

                            if len(db_sync) == 0:
                                break

                            for idx, row in enumerate(db_sync):
                                t.add_item(row['object_id'], row)

                            # clear control
                            t.inserted = [row['object_id'] for idx, row in enumerate(db_sync)]

                        while t.executed < 1 and t.count > 0:
                            time.sleep(0.3)

                        while t.running and t.count > 0:
                            time.sleep(0.300)

                    except KeyboardInterrupt as e:
                        raise e
                    finally:
                        t.close()
                        Tools.clear_line()
                        Color.pl('{?} {W}{D}Updating synced objects, wait a few seconds...{W}')

                        with progress.Bar(label=" Updating synced objects (step 2/4) ", expected_size=len(self.synced)) as bar:
                            try:
                                for idx, row in enumerate(self.synced):
                                    bar.show(idx)

                                    self.db.update(
                                        'bloodhound_objects',
                                        filter_data={'object_id': row},
                                        updated_date=datetime.datetime.now() - datetime.timedelta(seconds=60),
                                        sync_date=datetime.datetime.now()
                                    )

                            except KeyboardInterrupt as e:
                                raise e
                            finally:
                                bar.hide = True
                                Tools.clear_line()

            self.synced = []

            Color.pl('{?} {W}{D}Syncing edges...{W}')

            db_sync_count = self.db.select_raw(
                    sql='select count(*) as qty from bloodhound_edge '
                        'where sync_date <= updated_date',
                    args=[]
                )
            total = int(db_sync_count[0]['qty'])
            if total > 0:
                if total > 10000:
                    Color.pl('{?} {W}{D}this could take a while so go grab 2 more redbulls...{W}')
                elif total > 5000:
                    Color.pl('{?} {W}{D}this could take a while so go grab a redbull...{W}')

                with BloodhoundSync(callback=self.bh_callback2, per_thread_callback=self.thread_start_callback, threads=self.tasks) as t:
                    t.start()

                    t1 = threading.Thread(target=self.status, kwargs=dict(sync=t, total=total, text="Syncing edges (step 3/4)"))
                    t1.daemon = True
                    t1.start()

                    try:
                        while True:
                            for idx, row in enumerate(self.synced):
                                self.db.update(
                                    'bloodhound_edge',
                                    filter_data={'edge_id': row},
                                    updated_date=datetime.datetime.now() - datetime.timedelta(seconds=60),
                                    sync_date=datetime.datetime.now()
                                )
                            self.synced = []

                            while t.count > 3000:
                                time.sleep(0.3)

                            db_sync = self.db.select_raw(
                                sql='select * from bloodhound_edge '
                                    'where sync_date <= updated_date '
                                    'order by updated_date ASC '
                                    'limit 10000',
                                args=[]
                            )

                            if len(db_sync) == 0:
                                break

                            for idx, row in enumerate(db_sync):
                                t.add_item(row['edge_id'], row)

                            # clear control
                            t.inserted = [row['edge_id'] for idx, row in enumerate(db_sync)]

                        while t.executed < 1 and t.count > 0:
                            time.sleep(0.3)

                        while t.running and t.count > 0:
                            time.sleep(0.300)

                    except KeyboardInterrupt as e:
                        raise e
                    finally:
                        t.close()
                        Tools.clear_line()
                        Color.pl('{?} {W}{D}Updating synced objects, wait a few seconds...{W}')

                        with progress.Bar(label=" Updating synced objects (step 4/4) ", expected_size=len(self.synced)) as bar:
                            try:
                                for idx, row in enumerate(self.synced):
                                    bar.show(idx)

                                    self.db.update(
                                        'bloodhound_edge',
                                        filter_data={'edge_id': row},
                                        updated_date=datetime.datetime.now() - datetime.timedelta(seconds=60),
                                        sync_date=datetime.datetime.now()
                                    )

                            except KeyboardInterrupt as e:
                                raise e
                            finally:
                                bar.hide = True
                                Tools.clear_line()

            #Mark owned objects
            self.mark_owned()

        elif self.mode == Bloodhound.ImportMode.Import:
            start_date = datetime.datetime.now()
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

                            Color.pl('{?} {W}{D}checking file consistency...{W}')
                            t_files = [
                                f for f in self.get_files(tmpdirname)
                                if f is not None or f.strip() != ''
                            ]
                            files = []
                            with progress.Bar(label=" Parsing ", expected_size=len(t_files)) as bar:
                                try:
                                    for idx, f in enumerate(t_files):
                                        bar.show(idx)
                                        f1 = Bloodhound.BloodhoundFile(f)
                                        if f1.type != 'unknown':
                                            files.append(f1)
                                        else:
                                            Color.pl('{?} {W}{D}invalid file: {G}%s{W}' % f)

                                except KeyboardInterrupt as e:
                                    raise e
                                finally:
                                    bar.hide = True
                                    Tools.clear_line()

                            Color.pl('{?} {W}{O}%s{G} valid files in ZIP{W}' % len(files))

                            self.parse_files(files)

                        finally:
                            shutil.rmtree(tmpdirname)
                else:
                    f = Bloodhound.BloodhoundFile(self.filename)
                    if f.type == 'unknown':
                        Logger.pl('{!} {R}error: BloodHound file is invalid {O}%s{R} {W}\r\n' % (
                            f.file_name))
                        Tools.exit_gracefully(1)
                    self.parse_files([f])

            except KeyboardInterrupt as e:
                Tools.clear_line()
                print((" " * 180), end='\r', flush=True)
                print('')
                Logger.pl("{!} {C}Interrupted by user{W}")
                raise e
            finally:
                imported = self.db.select_raw(
                    sql='select row_number() OVER (ORDER BY o.object_label ASC) AS __line, o.object_label as Type, '
                        'sum(CASE WHEN o.insert_date >= ? THEN 1 ELSE 0 END) as Inserted, '
                        'sum(CASE WHEN o.insert_date < ? THEN 1 ELSE 0 END) as Updated '
                        'from bloodhound_objects as o '
                        'where o.updated_date >= ? '
                        'group by o.object_label '
                        'order by o.object_label',
                    args=[start_date, start_date, start_date])

                if len(imported) == 0:
                    Color.pl(('{!} {O}Process finished with none data imported. '
                          '{G}Generally it occurs when there are previously imported data in database and '
                          'this data is updated.{W}'))

                    start_date = datetime.date(1970, 1, 1)

                    imported = self.db.select_raw(
                        sql='select row_number() OVER (ORDER BY o.object_label ASC) AS __line, o.object_label as Type, '
                            'sum(CASE WHEN o.insert_date >= ? THEN 1 ELSE 0 END) as Inserted, '
                            'sum(CASE WHEN o.insert_date < ? THEN 1 ELSE 0 END) as Updated '
                            'from bloodhound_objects as o '
                            'where o.updated_date >= ? '
                            'group by o.object_label '
                            'order by o.object_label',
                        args=[start_date, start_date, start_date])

                Color.pl('{+} {W}Imported objects{W}')
                Color.pl('{W}{D}%s{W}' % Tools.get_tabulated(imported))


    def parse_files(self, files):

        unsupported = [
            f for f in files
            if f.version != 4 and f.version != 5
        ]
        if len(unsupported) > 0:
            Logger.pl('{!} {R}error: Unsupported BloodHound Version:{W}')
            for f in unsupported:
                Color.pl('{!} {W}{D}%s: {G}v%d{W}' % (f.file_name, f.version))
            Tools.exit_gracefully(1)

        self.groups = {}

        # Domains
        self.parse_domains_files(sorted([
            f for f in files
            if f.type == 'domains'
        ], key=lambda x: (x.order, x.file_name), reverse=False))

        # GPO
        self.parse_gpo_files(sorted([
            f for f in files
            if f.type == 'gpos'
        ], key=lambda x: (x.order, x.file_name), reverse=False))

        # OU
        self.parse_ou_files(sorted([
            f for f in files
            if f.type == 'ous'
        ], key=lambda x: (x.order, x.file_name), reverse=False))

        # Groups
        self.parse_groups_file(sorted([
            f for f in files
            if f.type == 'groups'
        ], key=lambda x: (x.order, x.file_name), reverse=False))

        # Computers
        self.parse_computers_files(sorted([
            f for f in files
            if f.type == 'computers'
        ], key=lambda x: (x.order, x.file_name), reverse=False))

        # Users
        self.parse_users_file(sorted([
            f for f in files
            if f.type == 'users'
        ], key=lambda x: (x.order, x.file_name), reverse=False))

    def parse_computers_files(self, files):

        Color.pl('{?} {W}{D}importing computers...{W}')

        total = sum(f.items for f in files)
        with progress.Bar(label=" Processing ", expected_size=total) as bar:
            try:
                count = 0
                for file in files:
                    data = file.get_json().get('data', [])
                    for idx, computer in enumerate(data):
                        count += 1
                        bar.show(count)

                        oid = computer.get('ObjectIdentifier', None)
                        properties = computer.get('Properties', None)

                        if oid is None or properties is None:
                            raise Exception('Unable to parse domain data')

                        self.db.insert_or_update_bloodhound_object(
                            label='Computer',
                            object_id=oid,
                            filter_type='objectid',
                            source=oid,
                            **properties
                        )

                        name = properties.get('name', None)
                        domain = properties.get('domain', None)
                        dn = properties.get('distinguishedname', None)

                        if name is None or domain is None or dn is None:
                            raise Exception('Unable to parse domain data')

                        name = name.lower()
                        domain = domain.lower()

                        if name.endswith(f'.{domain}'):
                            name = name.replace(f'.{domain}', '')

                        domain_id = self.get_domain(properties)

                        if (gid := Tools.get_dict_value(computer, 'PrimaryGroupSID')) is not None:
                            if gid not in self.groups:
                                self.groups[gid] = {"members": []}
                            self.groups[gid]['members'].append(oid)

                            self.db.insert_or_update_bloodhound_edge(
                                source=oid,
                                target=gid,
                                source_label='Computer',
                                target_label='Group',
                                edge_type='MemberOf',
                                edge_props='{isacl: false}',
                                filter_type='objectid',
                                props=dict(source=oid, target=gid)
                            )

                        self.db.insert_or_update_credential(
                            domain=domain_id,
                            username=name,
                            groups='',
                            object_identifier=oid,
                            dn=dn,
                            ntlm_hash='',
                            type='M')

                        self.process_options(computer, 'Computer')

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

    def parse_ou_files(self, files):

        Color.pl('{?} {W}{D}importing OU...{W}')

        total = sum(f.items for f in files)
        with progress.Bar(label=" Processing ", expected_size=total) as bar:
            try:
                count = 0
                for file in files:
                    data = file.get_json().get('data', [])
                    for idx, ou in enumerate(data):
                        count += 1
                        bar.show(count)

                        oid = ou.get('ObjectIdentifier', None)
                        properties = ou.get('Properties', None)

                        if oid is None or properties is None:
                            raise Exception('Unable to parse OU data')

                        self.db.insert_or_update_bloodhound_object(
                            label='OU',
                            object_id=oid,
                            filter_type='objectid',
                            source=oid,
                            **properties
                        )

                        if 'Aces' in ou and ou['Aces'] is not None:
                            self.process_ace_list(ou['Aces'], oid, "OU")

                        options = [
                            ('Users', 'User', 'Contains'),
                            ('Computers', 'Computer', 'Contains'),
                            ('ChildOus', 'OU', 'Contains'),
                        ]

                        for option, member_type, edge_name in options:
                            if option in ou and ou[option]:
                                targets = ou[option]
                                for target in targets:
                                    self.db.insert_or_update_bloodhound_edge(
                                        source=oid,
                                        target=target,
                                        source_label='OU',
                                        target_label=member_type,
                                        edge_type=edge_name,
                                        edge_props='{isacl: false}',
                                        filter_type='objectid',
                                        props=dict(source=oid, target=target)
                                    )

                        if 'Links' in ou and ou['Links']:
                            for gpo in ou['Links']:
                                self.db.insert_or_update_bloodhound_edge(
                                    source=oid,
                                    target=gpo['GUID'].upper(),
                                    source_label='GPO',
                                    target_label='OU',
                                    edge_type='GpLink',
                                    edge_props='{isacl: false, enforced: prop.enforced}',
                                    filter_type='objectid',
                                    props=dict(source=oid, target=gpo['GUID'].upper(), enforced=gpo['IsEnforced'])
                                )

                        self.process_options(ou, 'Computer')

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

    def parse_gpo_files(self, files):

        Color.pl('{?} {W}{D}importing GPO...{W}')

        total = sum(f.items for f in files)
        with progress.Bar(label=" Processing ", expected_size=total) as bar:
            try:
                count = 0
                for file in files:
                    data = file.get_json().get('data', [])
                    for idx, gpo in enumerate(data):
                        count += 1
                        bar.show(count)

                        oid = gpo.get('ObjectIdentifier', None)
                        properties = gpo.get('Properties', None)

                        if oid is None or properties is None:
                            raise Exception('Unable to parse GPO data')

                        self.db.insert_or_update_bloodhound_object(
                            label='GPO',
                            object_id=oid,
                            filter_type='objectid',
                            source=oid,
                            **properties
                        )

                        if "Aces" in gpo and gpo["Aces"] is not None:
                            self.process_ace_list(gpo['Aces'], oid, "GPO")

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

    def parse_domains_files(self, files):

        Color.pl('{?} {W}{D}importing domains...{W}')

        total = sum(f.items for f in files)
        with progress.Bar(label=" Processing ", expected_size=total) as bar:
            try:
                count = 0
                for file in files:
                    data = file.get_json().get('data', [])
                    for idx, domain in enumerate(data):
                        count += 1
                        bar.show(count)

                        oid = domain.get('ObjectIdentifier', None)
                        properties = domain.get('Properties', None)

                        if oid is None or properties is None:
                            raise Exception('Unable to parse domain data')

                        name = properties.get('name', None)
                        domain_name = properties.get('domain', None)
                        dn = properties.get('distinguishedname', None)

                        if name is None or domain_name is None or dn is None:
                            raise Exception('Unable to parse domain data')

                        self.db.insert_or_get_domain(
                            domain=domain_name,
                            dn=dn,
                            object_identifier=oid)

                        #BloodHound objects

                        self.db.insert_or_update_bloodhound_object(
                            label='Domain',
                            object_id=oid,
                            filter_type='objectid',
                            source=oid,
                            **properties
                        )

                        if 'Aces' in domain and domain['Aces'] is not None:
                            self.process_ace_list(domain['Aces'], oid, "Domain")

                        trust_map = {0: 'ParentChild', 1: 'CrossLink', 2: 'Forest', 3: 'External', 4: 'Unknown'}
                        if 'Trusts' in domain and domain['Trusts'] is not None:
                            for trust in domain['Trusts']:
                                trust_type = trust['TrustType']
                                direction = trust['TrustDirection']
                                props = {}
                                if direction in [1, 3]:
                                    props = dict(
                                        source=oid,
                                        target=trust['TargetDomainSid'],
                                        trusttype=trust_map[trust_type],
                                        transitive=trust['IsTransitive'],
                                        sidfiltering=trust['SidFilteringEnabled'],
                                    )
                                elif direction in [2, 4]:
                                    props = dict(
                                        target=oid,
                                        source=trust['TargetDomainSid'],
                                        trusttype=trust_map[trust_type],
                                        transitive=trust['IsTransitive'],
                                        sidfiltering=trust['SidFilteringEnabled'],
                                    )
                                else:
                                    Color.pl('{!} {W}{D}Could not determine direction of trust... direction: {O}%s{W}' % direction)
                                    continue

                                self.db.insert_or_update_bloodhound_edge(
                                    source=props['source'],
                                    target=props['target'],
                                    source_label='Domain',
                                    target_label='Domain',
                                    edge_type='TrustedBy',
                                    edge_props='{sidfiltering: prop.sidfiltering, trusttype: prop.trusttype, transitive: prop.transitive, isacl: false}',
                                    filter_type='objectid',
                                    props=props
                                )

                        options = [
                            ('Users', 'User', 'Contains'),
                            ('Computers', 'Computer', 'Contains'),
                            ('ChildOus', 'OU', 'Contains'),
                        ]

                        for option, member_type, edge_name in options:
                            if option in domain and domain[option]:
                                targets = domain[option]
                                for target in targets:
                                    self.db.insert_or_update_bloodhound_edge(
                                        source=oid,
                                        target=target,
                                        source_label='OU',
                                        target_label=member_type,
                                        edge_type=edge_name,
                                        edge_props='{isacl: false}',
                                        filter_type='objectid',
                                        props=dict(source=oid, target=target)
                                    )

                        if 'Links' in domain and domain['Links']:
                            for gpo in domain['Links']:
                                self.db.insert_or_update_bloodhound_edge(
                                    source=oid,
                                    target=gpo['GUID'].upper(),
                                    source_label='GPO',
                                    target_label='OU',
                                    edge_type='GpLink',
                                    edge_props='{isacl: false, enforced: prop.enforced}',
                                    filter_type='objectid',
                                    props=dict(source=oid,
                                           target=gpo['GUID'].upper(),
                                           enforced=gpo['IsEnforced'])
                                )

                        self.process_options(domain, 'Computer')

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

    def parse_groups_file(self, files):

        Color.pl('{?} {W}{D}importing groups...{W}')

        total = sum(f.items for f in files)
        with progress.Bar(label=" Importing ", expected_size=total) as bar:
            try:
                count = 0
                for file in files:
                    data = file.get_json().get('data', [])
                    for idx, group in enumerate(data):
                        count += 1
                        bar.show(count)

                        gid = group.get('ObjectIdentifier', None)
                        properties = group.get('Properties', None)

                        if gid is None or properties is None:
                            raise Exception('Unable to parse domain data')

                        if gid not in self.groups:
                            self.groups[gid] = { "members": [] }

                        self.db.insert_or_update_bloodhound_object(
                            label='Group',
                            object_id=gid,
                            filter_type='objectid',
                            source=gid,
                            **properties
                        )

                        if 'Aces' in group and group['Aces'] is not None:
                            self.process_ace_list(group['Aces'], gid, "Group")

                        if (pgsid := Tools.get_dict_value(group, 'PrimaryGroupSID')) is not None:
                            if pgsid not in self.groups:
                                self.groups[pgsid] = {"members": []}
                            self.groups[pgsid]['members'].append(gid)

                            self.db.insert_or_update_bloodhound_edge(
                                source=gid,
                                target=pgsid,
                                source_label='Group',
                                target_label='Group',
                                edge_type='MemberOf',
                                edge_props='{isacl: false}',
                                filter_type='objectid',
                                props=dict(source=gid, target=pgsid)
                            )

                        for entry in Tools.get_dict_value(group, 'AllowedToDelegate', []):
                            self.db.insert_or_update_bloodhound_edge(
                                source=gid,
                                target=entry,
                                source_label='Group',
                                target_label='Computer',
                                edge_type='AllowedToDelegate',
                                edge_props='{isacl: false}',
                                filter_type='objectid',
                                props=dict(source=gid, target=entry)
                            )

                        for member in group['Members']:
                            self.db.insert_or_update_bloodhound_edge(
                                source=member['ObjectIdentifier'],
                                target=gid,
                                source_label=member['ObjectType'],
                                target_label='Group',
                                edge_type='MemberOf',
                                edge_props='{isacl: false}',
                                filter_type='objectid',
                                props=dict(source=member['ObjectIdentifier'], target=gid)
                            )

                            t = group.get('ObjectType', None)
                            oid = group['ObjectIdentifier']
                            if t == "Group":
                                self.groups[gid]['members'].append(oid)

                        name = properties.get('name', '@').split('@')[0]
                        dn = properties.get('distinguishedname', None)

                        domain_id = self.get_domain(properties)

                        self.groups[gid].update(**{
                            "name": name,
                            "domain_id": domain_id,
                            "object_identifier": gid,
                            "dn": dn,
                            "json_members": group.get('Members', []),
                            "members": self.groups.get(gid, []).get("members", []),
                            "membership": self.groups.get(gid, []).get("membership", [])
                        })

                        self.db.insert_group(
                            domain=self.groups[gid]['domain_id'],
                            object_identifier=self.groups[gid].get('object_identifier', '') if self.groups[gid].get(
                                'object_identifier', None) is not None else '',
                            name=self.groups[gid]['name'],
                            dn=self.groups[gid].get('dn', '') if self.groups[gid].get('dn', None) is not None else '',
                            members=json.dumps(self.groups[gid]['json_members']),
                            membership=','.join(self.groups[gid]['membership'])
                        )

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

        if len(self.groups) > 0:

            Color.pl('{?} {W}{D}calculating group chain...{W}' + ' ' * 50)
            cnt = len(self.groups)
            with progress.Bar(label=" Processing ", expected_size=cnt) as bar:
                try:
                    for idx, g in enumerate(self.groups):
                        bar.show(idx)

                        self.groups[g]['membership'] = [g1 for g1 in self.get_group_chain(self.groups, g, [])]

                except KeyboardInterrupt as e:
                    raise e
                finally:
                    bar.hide = True
                    Tools.clear_line()

    def parse_users_file(self, files):
        Color.pl('{?} {W}{D}loading groups from db...{W}' + ' ' * 50)
        user_groups = {}
        groups = {}

        db_groups = self.db.select('groups')

        with progress.Bar(label=" Loading ", expected_size=len(db_groups)) as bar:
            try:
                for idx, row in enumerate(db_groups):
                    bar.show(idx)

                    gid = row['group_id']
                    members = json.loads(row['members'])
                    for g in members:
                        t = g['ObjectType']
                        oid = g['ObjectIdentifier']
                        if t == "User":
                            ug = user_groups.get(oid, [])
                            ug.append(gid)
                            user_groups[oid] = ug

                    groups[gid] = {
                        'name': row['name'],
                        'membership': row['membership'].split(',')
                    }

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

        Tools.clear_line()
        Color.pl('{?} {W}{D}importing users...{W}' + ' ' * 50)
        total = sum(f.items for f in files)
        with progress.Bar(label=" Processing ", expected_size=total) as bar:
            try:
                count = 0
                for file in files:
                    data = file.get_json().get('data', [])
                    for idx, user in enumerate(data):
                        count += 1
                        bar.show(count)

                        oid = user.get('ObjectIdentifier', None)
                        properties = user.get('Properties', None)

                        if oid is None or properties is None:
                            raise Exception('Unable to parse user data 1: %s' % json.dumps(user))

                        name = properties.get('name', '@').split('@')[0].lower()
                        dn = properties.get('distinguishedname', None)

                        if name is None:
                            raise Exception('Unable to parse user data 2: %s' % json.dumps(user))

                        domain_id = self.get_domain(properties)

                        full_name = properties.get('displayname', '')
                        pwd_last_set = datetime.datetime.fromtimestamp(properties.get('pwdlastset', 0))
                        enabled = bool(properties.get('enabled', True))

                        self.db.insert_or_update_credential(
                            domain=domain_id,
                            username=name,
                            groups=self.get_user_groups(groups, user_groups, oid),
                            object_identifier=oid,
                            dn=dn,
                            ntlm_hash='',
                            type='U',
                            full_name=full_name,
                            pwd_last_set=pwd_last_set,
                            enabled=enabled
                        )

                        self.db.insert_or_update_bloodhound_object(
                            label='User',
                            object_id=oid,
                            filter_type='objectid',
                            source=oid,
                            **properties
                        )

                        if (pgsid := Tools.get_dict_value(user, 'PrimaryGroupSID')) is not None:
                            if pgsid not in self.groups:
                                self.groups[pgsid] = {"members": []}
                            self.groups[pgsid]['members'].append(oid)

                            self.db.insert_or_update_bloodhound_edge(
                                source=oid,
                                target=pgsid,
                                source_label='User',
                                target_label='Group',
                                edge_type='MemberOf',
                                edge_props='{isacl: false}',
                                filter_type='objectid',
                                props=dict(source=oid, target=pgsid)
                            )

                        for entry in Tools.get_dict_value(user, 'AllowedToDelegate', []):
                            self.db.insert_or_update_bloodhound_edge(
                                source=oid,
                                target=entry,
                                source_label='User',
                                target_label='Computer',
                                edge_type='AllowedToDelegate',
                                edge_props='{isacl: false}',
                                filter_type='objectid',
                                props=dict(source=oid, target=entry)
                            )

                        # TODO add HasSIDHistory objects

                        if 'Aces' in user and user['Aces'] is not None:
                            self.process_ace_list(user['Aces'], oid, "User")

                        if 'SPNTargets' in user and user['SPNTargets'] is not None:
                            self.process_spntarget_list(user['SPNTargets'], oid)

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()

    def get_user_groups(self, groups, user_groups, user_id):
        ug = user_groups.get(user_id, [])
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

    def get_files(self, path):
        for file in os.listdir(path):
            p1 = os.path.join(path, file)
            if os.path.isfile(p1):
                yield p1
            elif os.path.isdir(p1):
                yield from self.get_files(p1)

    def get_group_chain(self, groups, group_id, chain):

        if group_id in chain:
            return []

        grp = []
        grp.append(group_id)

        if not self.chain_enabled:
            return grp

        for g in groups:
            members = groups[g].get('members', [])
            if group_id in members:
                if g not in grp:
                    grp.append(g)
                    tmp = self.get_group_chain(groups, g, chain + grp)
                    for t in tmp:
                        if t not in grp:
                            grp.append(t)
        return grp

    def get_domain(self, properties):
        domain_name = properties.get('domain', None)
        if domain_name is None:
            properties.get('name', '@').split('@')[1].lower()
        domain_name = domain_name.lower()
        domain_sid = properties.get('domainsid', '')

        if domain_sid in self.domain_cache:
            return self.domain_cache[domain_sid]

        domain_id = self.db.insert_or_get_domain(
            domain=domain_name,
            object_identifier=domain_sid
        )

        if domain_id == -1:
            raise Exception('Unable to get/create domain from JSON: %s' % json.dumps(properties))

        self.domain_cache[domain_sid] = domain_id

        return domain_id

    def process_ace_list(self, ace_list: list, objectid: str, objecttype: str) -> None:
        for entry in ace_list:
            principal = entry['PrincipalSID']
            principaltype = entry['PrincipalType']
            right = entry['RightName']

            if objectid == principal:
                continue

            props = dict(
                source=principal,
                target=objectid,
                isinherited=entry['IsInherited'],
            )

            self.db.insert_or_update_bloodhound_edge(
                source=principal,
                target=objectid,
                source_label=principaltype,
                target_label=objecttype,
                edge_type=right,
                edge_props='{isacl: true, isinherited: prop.isinherited}',
                filter_type='objectid',
                props=props
            )

    def process_spntarget_list(self, spntarget_list: list, objectid: str) -> None:
        for entry in spntarget_list:
            props = dict(
                source=objectid,
                target=entry['ComputerSID'],
                port=entry['Port'],
            )

            self.db.insert_or_update_bloodhound_edge(
                source=objectid,
                target=entry['ComputerSID'],
                source_label='User',
                target_label='Computer',
                edge_type='SPNTarget',
                edge_props='{isacl: false, port: prop.port}',
                filter_type='objectid',
                props=props
            )

    def process_options(self, target: dict, target_type: str) -> None:

        options = [
            ('LocalAdmins', 'AdminTo', '{isacl:false, fromgpo: false}', []),
            ('PSRemoteUsers', 'CanPSRemote', '{isacl:false, fromgpo: false}', []),
            ('DcomUsers', 'ExecuteDCOM', '{isacl:false, fromgpo: false}', []),
            ('RemoteDesktopUsers', 'CanRDP', '{isacl:false, fromgpo: false}', []),
            ('Sessions', 'HasSession', '{isacl:false, source:"netsessionenum"}', ['User']),
            ('PrivilegedSessions', 'HasSession', '{isacl:false, source:"netwkstauserenum"}', ['User']),
            ('RegistrySessions', 'HasSession', '{isacl:false, source:"registry"}', ['User']),
        ]

        maps = dict(
            user=['ObjectIdentifier', 'UserSID'],
            computer=['ObjectIdentifier', 'ComputerSID'],
        )

        oid = Tools.get_dict_value(target, 'ObjectIdentifier', None)
        if oid is None:
            return

        for option, edge_name, edge_props, ot_list in options:
            if isinstance((source := Tools.get_dict_value(target, option, {})), dict):
                if isinstance((r_dict := Tools.get_dict_value(source, 'Results', [])), list):

                    for src_data in r_dict:

                        if isinstance(src_data, dict):

                            sid = Tools.get_dict_value(src_data, 'ObjectIdentifier', None)
                            st = src_data.get('ObjectType', None)
                            if st is None:
                                st, sid = next(iter([
                                    (o, v) for o in ot_list for k in maps[o.lower()]
                                    if (v := Tools.get_dict_value(src_data, k, None)) is not None
                                ]), (None, None))

                            if st is None or sid is None:
                                raise Exception('Unable to get/create property from JSON: %s' % json.dumps(source))

                            self.db.insert_or_update_bloodhound_edge(
                                source=oid,
                                target=sid,
                                source_label=target_type,
                                target_label=st,
                                edge_type=edge_name,
                                edge_props=edge_props,
                                filter_type='objectid',
                                props=dict(target=sid, source=oid)
                            )
