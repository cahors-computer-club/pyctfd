from bs4 import BeautifulSoup
import requests
import json
from urllib.parse import urljoin
import re

#TODO: decorate self.logged_in check
#TODO: get if user is admin

class CTFd(object):
    """
    API wrapper for CTFd 2.1.2
    """

    PATH_GET_CURRENT_USER = r"/api/v1/users/me" 
    PATH_GET_CHALLENGES = r"/api/v1/challenges" 
    PATH_GET_CHALLENGE = r"/api/v1/challenges/%d"
    PATH_NONCE_DELETE_CHALLENGE = r"/admin/challenges/%d" 
    PATH_DELETE_CHALLENGE = r"/api/v1/challenges/%d"
    PATH_NONCE_CREATE_CHALLENGE = r"/admin/challenges/new" 
    PATH_CREATE_CHALLENGE = r"/api/v1/challenges"
    PATH_NONCE_PATCH_CHALLENGE = r"/admin/challenges/%d"
    PATH_PATCH_CHALLENGE = r"/api/v1/challenges/%d"
    PATH_NONCE_CREATE_FLAG = r"/admin/challenges/%d" 
    PATH_CREATE_FLAG = r"/api/v1/flags" 
    PATH_GET_FLAG = r"/api/v1/flags/%d"
    PATH_NONCE_PATCH_FLAG = r"/admin/challenges/%d" 
    PATH_PATCH_FLAG = r"/api/v1/flags/%d"
    PATH_NONCE_DELETE_FLAG = r"/admin/challenges/%d" 
    PATH_DELETE_FLAG = r"/api/v1/flags/%d"
    PATH_GET_CHALLENGE_FLAGS = r"/api/v1/challenges/%d/flags"
    PATH_SETUP = r"/setup" 
    PATH_GET_TAG = r"/api/v1/tags/%d"
    PATH_NONCE_DELETE_TAG = r"/admin/challenges/%d" 
    PATH_DELETE_TAG = r"/api/v1/tags/%d"
    PATH_NONCE_CREATE_TAG = r"/admin/challenges/%d" 
    PATH_CREATE_TAG = r"/api/v1/tags" 
    PATH_NONCE_PATCH_TAG = r"/admin/challenges/%d" 
    PATH_PATCH_TAG = r"/api/v1/tags/%d"
    PATH_GET_CHALLENGE_TAGS = r"/api/v1/challenges/%d/tags"
    PATH_GET_HINT = r"/api/v1/hints/%d"
    PATH_NONCE_DELETE_HINT = r"/admin/challenges/%d" 
    PATH_DELETE_HINT = r"/api/v1/hints/%d"
    PATH_NONCE_CREATE_HINT = r"/admin/challenges/%d" 
    PATH_CREATE_HINT = r"/api/v1/hints" 
    PATH_NONCE_PATCH_HINT = r"/admin/challenges/%d" 
    PATH_PATCH_HINT = r"/api/v1/hints/%d"
    PATH_GET_CHALLENGE_HINTS = r"/api/v1/challenges/%d/hints"

    PATH_NONCE_CREATE_FILE = r"/admin/challenges/%d" 
    PATH_CREATE_FILE = r"/api/v1/files" 
    PATH_NONCE_DELETE_FILE = r"/admin/challenges/%d" 
    PATH_DELETE_FILE = r"/api/v1/files/%d"
    PATH_GET_CHALLENGE_FILES = r"/api/v1/challenges/%d/files"
    PATH_GET_FILE = r"/api/v1/files/%d"

    def __init__(self, host, verify=True):
        """
            host: CTFd URL
        """
        self.host = host
        self.s = requests.Session()
        if verify is False:
            self.s.verify = False
        self.logged_in = False

    def setup(self, **kwargs):
        """
        kwargs must be:
        {
            ctf_name: str, #ctf name
            name: str, #admin name,
            email: str, #admin email
            password: str #admin password
            user_mode: str, #("teams", "users")
        }
        """
        ret = None
        r = self.s.get(
            urljoin(
                self.host,
                self.__class__.PATH_SETUP
            )
        )
        if r.status_code == 302:
            return True

        m = re.search(
            r'var csrf_nonce = "(.+?)";',
            r.text
        )
        nonce = m.group(1)

        args = {}
        params = ["ctf_name", "name", "email", "password", "user_mode"]
        args = {}
        for key in params:
            if key in kwargs.keys():
                args[key] = kwargs[key]

        args["nonce"] = nonce

        r = self.s.post(
            urljoin(
                self.host,
                self.__class__.PATH_SETUP
            ),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=args,
            allow_redirects=False
        )
        ret = (r.status_code == 302)
        return ret

    def login(self, login: str, password: str):
        """
            login: CTFd admin login
            password CTFd admin password
        """
        r = self.s.get(
            urljoin(self.host, "/login"),
        )
        soup = BeautifulSoup(r.text, 'html.parser')
        nonce = soup.find(
            "input",
            attrs={
                "type": "hidden",
                "name": "nonce"
            }
        )["value"]

        r = self.s.post(
            urljoin(self.host, "/login"),
            data={
                "name": login,
                "password": password,
                "nonce": nonce
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
            allow_redirects=False
        )
        self.logged_in = r.status_code == 302
        return self.logged_in
    
    def get_current_user(self):
        ret = None
        if self.logged_in is True:
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CURRENT_USER
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret
    
    def get_challenges(self):
        ret = None
        if self.logged_in is True:
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGES
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def get_challenge(self, cid: int):
        ret = None
        if self.logged_in is True:
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGE % (cid)
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def create_challenge(self, **kwargs):
        """
        kwargs mut be jsonifyable as follows:
        {
            description: str,
            category: str,
            name: str,
            value: int
            state: str, ("hidden", "locked", "visible"),
            type: str, ("standard", "dynamic"),
            decay: int, #only if challenge is dynamic
            minimum: int, #only if challenge is dynamic
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_CREATE_CHALLENGE
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)

            args = {}
            params = ["description", "category", "name", "value", "state", "type", "decay", "minimum"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]

            r = self.s.post(
                urljoin(
                    self.host,
                    self.__class__.PATH_CREATE_CHALLENGE
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def patch_challenge(self, cid: int, **kwargs):
        """
        cid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            description: str,
            category: str,
            name: str,
            value: int
            state: str, ("hidden", "locked", "visible"),
            type: str, ("standard", "dynamic"),
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_PATCH_CHALLENGE % (cid)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)

            args = {}
            params = ["description", "category", "name", "value", "state", "type", "decay", "minimum"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]

            r = self.s.patch(
                urljoin(
                    self.host,
                    self.__class__.PATH_PATCH_CHALLENGE % (cid)
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def delete_challenge(self, cid):
        """
        cid: challenge id
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_DELETE_CHALLENGE % (cid)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            r = self.s.delete(
                urljoin(
                    self.host,
                    self.__class__.PATH_DELETE_CHALLENGE % (cid)
                ),
                headers={
                    "CSRF-Token": nonce,
                    "Content-Type": "application/json"
                }
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret
        return  ret

    def create_flag(self, cid, **kwargs):
        """
        cid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            content: str,
            type: str, ("static", "regex")
            challenge: int,
            data: "case_insensitive" # not present if case sensitive
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_CREATE_FLAG % (cid)
                )
            )

            args = {}
            params = ["content", "type", "challenge", "data"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            args["challenge"] = cid
            r = self.s.post(
                urljoin(
                    self.host,
                    self.__class__.PATH_CREATE_FLAG
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def patch_flag(self, fid, **kwargs):
        """
        cid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            content: str,
            type: str, ("static", "regex")
            challenge: int,
            data: "case_insensitive" # not present if case sensitive
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_GET_FLAG % (fid)
                )
            )
            challenge_id = r.json()["data"]["challenge_id"]
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_PATCH_FLAG % (challenge_id)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)

            args = {}
            params = ["content", "type", "challenge", "data"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]

            args["id"] = fid
            r = self.s.patch(
                urljoin(
                    self.host,
                    self.__class__.PATH_PATCH_FLAG % (fid)
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def delete_flag(self, fid):
        """
        fid: flag id
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_GET_FLAG % (fid)
                )
            )
            challenge_id = r.json()["data"]["challenge_id"]
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_DELETE_FLAG % (challenge_id)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            r = self.s.delete(
                urljoin(
                    self.host,
                    self.__class__.PATH_DELETE_FLAG % (fid)
                ),
                json={},
                headers={
                    "CSRF-Token": nonce
                }
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret
        return  ret

    def get_challenge_flags(self, cid):
        ret = None
        if self.logged_in is True:
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGE_FLAGS % (cid)
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def create_tag(self, cid, **kwargs):
        """
        cid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            value: str,
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_CREATE_TAG % (cid)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)

            args = {}
            params = ["value"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]

            args["challenge"] = cid
            r = self.s.post(
                urljoin(
                    self.host,
                    self.__class__.PATH_CREATE_TAG
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def patch_tag(self, tid, **kwargs):
        """
        tid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            value: str,
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_GET_TAG % (tid)
                )
            )
            challenge_id = r.json()["data"]["challenge_id"]
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_PATCH_TAG % (challenge_id)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)

            args = {}
            params = ["value"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]

            args["id"] = tid
            r = self.s.patch(
                urljoin(
                    self.host,
                    self.__class__.PATH_PATCH_TAG % (tid)
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret
    
    def delete_tag(self, tid):
        """
        fid: tag id
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_GET_TAG % (tid)
                )
            )
            challenge_id = r.json()["data"]["challenge_id"]
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_DELETE_TAG % (challenge_id)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            r = self.s.delete(
                urljoin(
                    self.host,
                    self.__class__.PATH_DELETE_TAG % (tid)
                ),
                json={},
                headers={
                    "CSRF-Token": nonce
                }
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret
        return  ret

    def get_challenge_tags(self, cid):
        ret = None
        if self.logged_in is True:
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGE_TAGS % (cid)
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret
    
    def create_hint(self, cid, **kwargs):
        """
        cid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            content: str,
            cost: int
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_CREATE_HINT % (cid)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)

            args = {}
            params = ["content", "cost"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]
            args["challenge"] = cid
            r = self.s.post(
                urljoin(
                    self.host,
                    self.__class__.PATH_CREATE_HINT
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def patch_hint(self, hid, **kwargs):
        """
        hid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            content: str,
            cost: int
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_GET_HINT % (hid)
                )
            )
            challenge_id = r.json()["data"]["challenge"]
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_PATCH_HINT % (challenge_id)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            args = {}
            params = ["content", "cost"]
            args = {}
            for key in params:
                if key in kwargs.keys():
                    args[key] = kwargs[key]
            args["id"] = hid
            r = self.s.patch(
                urljoin(
                    self.host,
                    self.__class__.PATH_PATCH_HINT % (hid)
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=args
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret
    
    def delete_hint(self, hid):
        """
        fid: hint id
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_GET_HINT % (hid)
                )
            )
            challenge_id = r.json()["data"]["challenge"]
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_DELETE_HINT % (challenge_id)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            r = self.s.delete(
                urljoin(
                    self.host,
                    self.__class__.PATH_DELETE_HINT % (hid)
                ),
                json={},
                headers={
                    "CSRF-Token": nonce
                }
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret
        return  ret

    def get_challenge_hints(self, cid):
        ret = None
        if self.logged_in is True:
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGE_HINTS % (cid)
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def create_file(self, cid, **kwargs):
        """
        cid: challenge id
        kwargs mut be jsonifyable as follows:
        {
            file: file,
            filename: str,
            mime: str,
            type: str, ("challenge")
        }
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_CREATE_FILE % (cid)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)

            args = {
                "challenge": cid,
                "nonce": nonce,
                "type": "challenge"
            }
            r = self.s.post(
                urljoin(
                    self.host,
                    self.__class__.PATH_CREATE_FILE
                ),
                data=args,
                files={"file": (kwargs["filename"], kwargs["file"], kwargs["mime"])}
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret

    def delete_file(self, cid, fid):
        """
        fid: file id
        """
        ret = None
        if self.logged_in is True:
            r = self.s.get(
                urljoin(
                    self.host,
                    self.__class__.PATH_NONCE_DELETE_FILE % (cid)
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            r = self.s.delete(
                urljoin(
                    self.host,
                    self.__class__.PATH_DELETE_FILE % (fid)
                ),
                json={},
                headers={
                    "CSRF-Token": nonce
                }
            )
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret
        return  ret

    def get_challenge_files(self, cid):
        ret = None
        if self.logged_in is True:
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGE_FILES % (cid)
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret
