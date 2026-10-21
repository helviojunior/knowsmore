import json

from datetime import datetime, timezone, timedelta
from knowsmore.password import Password

from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.tools import Tools

class ExporterBase(KnowsMoreDB):

    def __init__(self, auto_create=True, db_name=None):
        super().__init__(
            auto_create=auto_create,
            db_name=db_name
        )

    def get_data_len(self, cracked_only=False, enabled_only=False) -> int:
        sql = (
            'select count(c.credential_id) as qty '
            'from credentials as c '
            'inner join passwords as p '
            'on c.password_id = p.password_id '
            'inner join domains as d '
            'on c.domain_id = d.domain_id '
        )

        conditions = []
        if cracked_only:
            conditions.append('(p.length > 0)')
        if enabled_only:
            conditions.append('(c.enabled = 1)')
        if len(conditions) > 0:
            sql += ' where ' + ' and '.join(conditions) + ' '

        return int(self.select_raw(
            sql=sql,
            args=[]
        )[0]['qty'])

    def _build_sam_index(self) -> dict:
        # Credentials imported from an NTDS/secretsdump often have no SID
        # (object_identifier is empty), so they cannot be linked to the
        # BloodHound objects by object_id. Build a samAccountName -> SID index
        # once so those credentials can still resolve their BloodHound props.
        index = {}
        try:
            rows = self.select_raw(
                sql=(
                    "select object_id, lower(json_extract(props, '$.samaccountname')) as sam "
                    "from bloodhound_objects "
                    "where object_label in ('User', 'Computer') "
                    "and json_extract(props, '$.samaccountname') is not null"
                ),
                args=[]
            )
            for row in rows:
                sam = row.get('sam', None)
                sid = row.get('object_id', None)
                if sam is not None and str(sam).strip() != '' and sid is not None and sam not in index:
                    index[sam] = sid
        except:
            pass

        return index

    def get_data(self, export_password=False, cracked_only=False, enabled_only=False) -> list:
        sql = (
            'select c.credential_id, c.name, c.type, c.object_identifier, c.dn, c.user_data_similarity, c.insert_date, d.domain_id, d.name as domain_name, d.object_identifier as domain_object_identifier, '
            'd.dn as domain_dn, p.* '
            'from credentials as c '
            'inner join passwords as p '
            'on c.password_id = p.password_id '
            'inner join domains as d '
            'on c.domain_id = d.domain_id '
        )

        conditions = []
        if cracked_only:
            conditions.append('(p.length > 0)')
        if enabled_only:
            conditions.append('(c.enabled = 1)')
        if len(conditions) > 0:
            sql += ' where ' + ' and '.join(conditions) + ' '

        rows = self.select_raw(
            sql=sql,
            args=[]
        )

        sam_to_sid = None  # lazily built only when a credential has no SID
        for r in rows:
            p = r.get('password', '')
            if '$HEX[' in p:
                p1 = Password('', p)
                r['password'] = p1.latin_clear_text

            dt = datetime.strptime(str(r['insert_date']), '%Y-%m-%d %H:%M:%S')

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
                pwd['clear_text'] = r['password']
                pwd['md5_hash'] = r['md5_hash']
                pwd['sha1_hash'] = r['sha1_hash']
                pwd['sha256_hash'] = r['sha256_hash']
                pwd['sha512_hash'] = r['sha512_hash']

            bh = []
            object_identifier = r['object_identifier']

            # Fallback: credentials without a SID (e.g. imported from NTDS)
            # are matched to their BloodHound object by samAccountName (name).
            if object_identifier is None or object_identifier.strip() == '':
                if sam_to_sid is None:
                    sam_to_sid = self._build_sam_index()
                object_identifier = sam_to_sid.get(str(r['name']).lower().strip(), '')

            if object_identifier is not None and object_identifier.strip() != '':
                bh_objects = self.select(
                    'bloodhound_objects',
                    object_id=object_identifier
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

                    if isinstance(dt, int):
                        dt = datetime(1970, 1, 1, 0, 0, 0, tzinfo=None) + timedelta(seconds=dt)

                    for k in ["lastlogon", "pwdlastset"]:
                        try:
                            if properties.get(k, None) is not None and isinstance(properties[k], int):
                                properties[k] = datetime(1970, 1, 1, 0, 0, 0, tzinfo=None) + timedelta(seconds=int(properties[k]))
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

            # When BloodHound data exists for this credential, treat its
            # 'enabled' flag as the authoritative source and AND it with the
            # --enabled-only filter: a credential already marked enabled is
            # still dropped if BloodHound says it is disabled.
            if enabled_only and len(bh) > 0:
                bh_enabled = properties.get('enabled', None)
                if bh_enabled is not None and not bool(bh_enabled):
                    continue

            # Expose pwdlastset at the top level: the raw Unix epoch (seconds)
            # as stored by BloodHound, plus a derived UTC ISO-8601 string.
            # The epoch is read straight from the BloodHound props to avoid any
            # timezone shift (strftime('%s') would reinterpret a naive datetime
            # in local time and offset the value).
            pwdlastset_epoch = None
            pwdlastset_iso = None
            try:
                raw_pwdlastset = bh[0]['props'].get('pwdlastset', None) if len(bh) > 0 else None
                if isinstance(raw_pwdlastset, int) and raw_pwdlastset > 0:
                    pwdlastset_epoch = raw_pwdlastset
                    pwdlastset_iso = datetime.fromtimestamp(
                        raw_pwdlastset, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
            except:
                pass

            yield dict(
                created_at=int(dt.strftime("%s")),
                created_at_iso=dt.strftime("%Y-%m-%dT%H:%M:%S%Z"),
                pwdlastset=pwdlastset_epoch,
                pwdlastset_iso=pwdlastset_iso,
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

