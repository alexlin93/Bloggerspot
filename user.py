import random
import hashlib

from string import letters
from google.appengine.ext import db


# helper functions
def make_salt(length=5):
    """Makes the salt from a random choice of 5 letters"""
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """Makes a the pw hashed and h is stored to db"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """Takes name and pw and checks values in db"""
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    """Creates ancestor element to store all users in db"""
    return db.Key.from_path('users', group)


# User Model
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    """Convenience function for looking up user by id"""
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    """Convenience function for looking up user by name"""
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    """Convenience function for creating new user"""
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    """
    Convenience function for making sure
    user exists and pw is valid
    """
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
