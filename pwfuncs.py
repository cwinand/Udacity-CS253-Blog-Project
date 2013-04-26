import random, hashlib, hmac, string 

SECRET = 'thisissupersecret'

def make_salt():
    x = ''
    while len(x) < 5:
        x = x + random.choice(string.ascii_letters)
    return x

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')
    salt = salt[1]
    return make_pw_hash(name,pw,salt) == h

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    if h:
        val = h.find("|")
        if h[val+1:] == hash_str(h[0:val]):
            return h[0:val]