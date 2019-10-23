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

    def __init__(self, host):
        """
            host: CTFd URL
        """
        self.host = host
        self.s = requests.Session()
        self.logged_in = False

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
            r = self.s.post(
                urljoin(
                    self.host,
                    self.__class__.PATH_CREATE_CHALLENGE
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=kwargs
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
                    self.__class__.PATH_NONCE_PATCH_CHALLENGE
                )
            )

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            r = self.s.patch(
                urljoin(
                    self.host,
                    self.__class__.PATH_PATCH_CHALLENGE % (cid)
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=kwargs
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

            m = re.search(
                r'var csrf_nonce = "(.+?)";',
                r.text
            )
            nonce = m.group(1)
            kwargs["challenge"] = cid
            r = self.s.post(
                urljoin(
                    self.host,
                    self.__class__.PATH_CREATE_FLAG
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=kwargs
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
            print(r.text)
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
            kwargs["id"] = fid
            r = self.s.patch(
                urljoin(
                    self.host,
                    self.__class__.PATH_PATCH_FLAG % (fid)
                ),
                headers={
                    "CSRF-Token": nonce
                },
                json=kwargs
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
            print(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGE_FLAGS % (cid)
            ))
            r = self.s.get(urljoin(
                self.host,
                self.__class__.PATH_GET_CHALLENGE_FLAGS % (cid)
            ))
            if r.status_code == 200:
                j = r.json()
                ret = j if j["success"] is True else ret

        return  ret