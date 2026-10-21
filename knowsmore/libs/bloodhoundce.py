import base64
import datetime
import hashlib
import hmac
import json
from urllib.parse import urljoin, quote_plus

import requests


class BloodHoundCEError(Exception):
    pass


class BloodHoundCEApi(object):
    """Minimal client for the BloodHound Community Edition (BHCE) REST API.

    It is used to mark Active Directory objects as *Owned* in a way that is
    persistent across BloodHound "Graph Analysis" runs (unlike writing the
    ``Tag_Owned`` label directly in Neo4j, which the BHCE maintainers do not
    support and which gets wiped on the next analysis).

    Authentication follows the ``bhesignature`` scheme documented by SpecterOps:
    an HMAC-SHA256 chain keyed by the token key, signing the HTTP
    method+URI, then the hour-truncated request date, then the body.
    """

    # Asset group tag types: 1 = tier (zone), 2 = label, 3 = owned
    OWNED_TAG_TYPE = 3

    # Selector seed types: 1 = object id, 2 = cypher
    SEED_TYPE_OBJECTID = 1

    def __init__(self, base_url: str, token_id: str, token_key: str, verify_tls: bool = True):
        self.base_url = (base_url or '').rstrip('/')
        self._token_id = token_id
        self._token_key = token_key
        self._verify = verify_tls

    def _request(self, method: str, uri: str, payload=None) -> requests.Response:
        # The URI (path + query string) must be identical for signing and for
        # the actual request, otherwise the signature is rejected.
        body = None
        if payload is not None:
            body = json.dumps(payload).encode('utf-8')

        digester = hmac.new(self._token_key.encode(), None, hashlib.sha256)
        digester.update(f'{method}{uri}'.encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        datetime_formatted = datetime.datetime.now().astimezone().isoformat('T')
        # Only the date + hour (e.g. 2020-12-01T23) takes part in the signature.
        digester.update(datetime_formatted[:13].encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        if body is not None:
            digester.update(body)

        headers = {
            'User-Agent': 'knowsmore',
            'Authorization': f'bhesignature {self._token_id}',
            'RequestDate': datetime_formatted,
            'Signature': base64.b64encode(digester.digest()),
            'Content-Type': 'application/json',
        }

        url = urljoin(self.base_url + '/', uri.lstrip('/'))

        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                timeout=(5, 60),
                verify=self._verify,
            )
        except requests.exceptions.RequestException as e:
            raise BloodHoundCEError(str(e))

        if resp.status_code == 401:
            raise BloodHoundCEError('authentication failed (401): check --bh-token-id/--bh-token-key')

        return resp

    @staticmethod
    def _json(resp: requests.Response):
        try:
            return resp.json()
        except Exception:
            return {}

    def test_connection(self):
        """Validate the base URL and the API credentials."""
        resp = self._request('GET', '/api/v2/asset-group-tags')
        if not resp.ok:
            raise BloodHoundCEError('unexpected response %d from %s' % (resp.status_code, self.base_url))
        return True

    def get_owned_tag_id(self):
        """Return the id of the built-in *Owned* asset group tag (type 3)."""
        resp = self._request('GET', '/api/v2/asset-group-tags')
        if not resp.ok:
            raise BloodHoundCEError('could not list asset group tags (%d)' % resp.status_code)

        data = self._json(resp).get('data', {})
        tags = data.get('tags', data if isinstance(data, list) else [])
        for tag in tags:
            if int(tag.get('type', -1)) == self.OWNED_TAG_TYPE:
                return tag.get('id')

        raise BloodHoundCEError('the Owned asset group tag (type 3) was not found')

    def get_selector_names(self, tag_id) -> set:
        """Return the set of existing selector names for a tag (for dedup)."""
        resp = self._request('GET', '/api/v2/asset-group-tags/%s/selectors' % tag_id)
        if not resp.ok:
            return set()

        data = self._json(resp).get('data', {})
        selectors = data.get('selectors', data if isinstance(data, list) else [])
        return {
            s.get('name') for s in selectors
            if isinstance(s, dict) and s.get('name') is not None
        }

    @staticmethod
    def _local_part(name: str) -> str:
        """Return the account/host label of a node name (upper-cased).

        Handles the UPN form ``user@domain`` and the ``domain\\user`` form.
        The FQDN form (``host.domain``) is kept as-is here and reduced to its
        first label by the caller only when needed.
        """
        name = str(name)
        if '\\' in name:
            name = name.split('\\')[-1]
        name = name.split('@')[0]
        return name.upper()

    def search_node(self, query: str, kind: str = None):
        """Resolve a node (dict with name/objectid) by samAccountName/hostname.

        The KnowsMore database stores the samAccountName and the UPN/e-mail
        domain suffix, which does not match the Active Directory domain used by
        BloodHound, so a lookup must be done by the bare account/host name.
        """
        uri = '/api/v2/search?q=%s' % quote_plus(query)
        if kind is not None and kind != '':
            uri += '&type=%s' % quote_plus(kind)

        resp = self._request('GET', uri)
        if not resp.ok:
            return None

        data = self._json(resp).get('data') or []
        if not isinstance(data, list) or len(data) == 0:
            return None

        q = query.upper()

        # 1) exact full-name match (e.g. query already is NAME@DOMAIN)
        for row in data:
            if str(row.get('name', '')).upper() == q:
                return row

        # 2) match by the account/host label (handles UPN and FQDN forms)
        for row in data:
            lp = self._local_part(row.get('name', ''))
            if lp == q or lp.split('.')[0] == q:
                return row

        # 3) single, unambiguous result
        if len(data) == 1:
            return data[0]

        return None

    def add_owned_selector(self, tag_id, name: str, objectid: str):
        """Create a selector that adds a single object id to the Owned tag.

        Note: the Owned tag (type 3) rejects the ``auto_certify`` field, so the
        body carries only ``name`` and ``seeds`` (matching the BloodHound CE UI).
        """
        payload = {
            'name': name,
            'seeds': [
                {'type': self.SEED_TYPE_OBJECTID, 'value': objectid},
            ],
        }

        resp = self._request('POST', '/api/v2/asset-group-tags/%s/selectors' % tag_id, payload=payload)
        if resp.ok:
            return True

        # Treat an already-existing selector as a soft success.
        body = self._json(resp)
        msg = json.dumps(body) if body else resp.text
        if resp.status_code in (400, 409) and 'exist' in msg.lower():
            return True

        raise BloodHoundCEError('failed to create selector for %s (%d): %s' % (name, resp.status_code, msg[:200]))
