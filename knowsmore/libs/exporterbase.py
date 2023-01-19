import json

from datetime import datetime, timezone, timedelta
from knowsmore.password import Password

from knowsmore.util.knowsmoredb import KnowsMoreDB


class ExporterBase(KnowsMoreDB):

    def __init__(self, auto_create=True, db_name=None):
        super().__init__(
            auto_create=auto_create,
            db_name=db_name
        )

    def get_data_len(self, cracked_only=False) -> int:
        sql = (
            'select count(c.credential_id) as qty '
            'from credentials as c '
            'inner join passwords as p '
            'on c.password_id = p.password_id '
            'inner join domains as d '
            'on c.domain_id = d.domain_id '
        )

        if cracked_only:
            sql += ' where (p.length > 0) '

        return int(self.select_raw(
            sql=sql,
            args=[]
        )[0]['qty'])

    def get_data(self, export_password=False, cracked_only=False) -> list:
        sql = (
            'select c.credential_id, c.name, c.type, c.object_identifier, c.dn, c.user_data_similarity, c.insert_date, d.domain_id, d.name as domain_name, d.object_identifier as domain_object_identifier, '
            'd.dn as domain_dn, p.* '
            'from credentials as c '
            'inner join passwords as p '
            'on c.password_id = p.password_id '
            'inner join domains as d '
            'on c.domain_id = d.domain_id '
        )

        if cracked_only:
            sql += ' where (p.length > 0) '

        rows = self.select_raw(
            sql=sql,
            args=[]
        )
        for r in rows:
            p = r.get('password', '')
            if '$HEX[' in p:
                p1 = Password('', p)
                r['password'] = p1.latin_clear_text

            dt = datetime.strptime(str( r['insert_date']), '%Y-%m-%d %H:%M:%S')
            dt.astimezone(timezone(timedelta(hours=0), 'Z'))

            properties = dict(
                    name=r['name'],
                    distinguishedname=r['dn'],
                    object_identifier=r['object_identifier'],
                    type='Machine' if r['type'] == "M" else "User"
                )

            pwd = dict(
                cracked=bool(int(r['length']) > 0),
                length=r['length'],
                entropy=r['entropy'],
                upper=r['upper'],
                lower=r['lower'],
                digit=r['digit'],
                special=r['special'],
                latin=r['latin'],
                company_similarity=r['company_similarity'],
                user_data_similarity=r['user_data_similarity']
            )

            if export_password:
                pwd['password'] = r['password'],
                pwd['md5_hash'] = r['md5_hash'],
                pwd['sha1_hash'] = r['sha1_hash'],
                pwd['sha256_hash'] = r['sha256_hash'],
                pwd['sha512_hash'] = r['sha512_hash']

            bh = []
            if r['object_identifier'] is not None and r['object_identifier'].strip() != '':
                bh_objects = self.db.select(
                    'bloodhound_objects',
                    object_id=r['object_identifier']
                )
                for bho in bh_objects:
                    props = {}
                    try:
                        props = json.loads(bho['props'])
                    except:
                        pass

                    try:
                        dt = props.get('whencreated', dt)
                        properties['enabled'] = props.get('enabled', None)
                        properties['lastlogon'] = props.get('lastlogon', None)
                        properties['lastlogontimestamp'] = props.get('lastlogontimestamp', None)
                        properties['pwdlastset'] = props.get('pwdlastset', None)
                        properties['displayname'] = props.get('displayname', None)
                    except:
                        pass

                    bh.append(
                        dict(
                            object_id=bho['object_id'],
                            object_label=bho['object_label'],
                            filter_type=bho['filter_type'],
                            props=props,
                        )
                    )

            yield dict(
                created_at=int(dt.strftime("%s")),
                created_at_iso=dt.strftime("%Y-%m-%dT%H:%M:%S%Z"),
                object_id=r['credential_id'],
                password=pwd,
                properties=properties,
                domain=dict(
                    name=r['domain_name'],
                    distinguishedname=r['domain_dn'],
                    domainsid=r['domain_object_identifier'],
                ),
                bloodhound=bh
            )

