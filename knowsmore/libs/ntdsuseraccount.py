

class NTDSUserAccount:
    domain = 'default'
    user_name = rid = lm_ash = nt_hash = pwd_last_set = status = clear_text = object_sid = ''
    history = -1

    def __init__(self, domain, user_name, rid, lm_ash, nt_hash, pwd_last_set,
                 status: str = '',
                 clear_text: str = '',
                 history: int = -1,
                 full_name: str = '',
                 object_sid: str = ''):
        self.domain = domain
        self.user_name = user_name
        self.rid = rid
        self.lm_ash = lm_ash
        self.nt_hash = nt_hash
        self.pwd_last_set = pwd_last_set
        self.status = status
        self.clear_text = clear_text
        self.history = history
        self.full_name = full_name
        self.object_sid = object_sid

        if (self.domain is None or self.domain == '') and '\\' in self.user_name:
            f1s = self.user_name.strip().split('\\')
            self.domain = f1s[0].strip()
            self.user_name = f1s[1].strip()



