import os, sys, re, logging, string, time, json

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

from pwfuncs import *


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#GLOBAL STUFF

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def render_post(self, response, post):
    self.response.out.write('<b>' + post.subject + '</b><br>')
    self.response.out.write(post.content)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


        

#END GLOBAL STUFF

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

#Blog Post Handlers
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BaseHandler):
    def top_posts(self):
        posts = memcache.get('key')
        cached_time = memcache.get('keytwo')
        if posts is not None:
            return {'posts': posts, 'time': cached_time}
        else:
            posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
            queried_time = time.time() 
            memcache.set_multi({'key': posts, 'keytwo': queried_time})
            return {'posts': posts, 'time': queried_time}

    def get(self):
        results = self.top_posts()
        posts = results['posts']
        cur_time = int(time.time() - results['time'])
        self.render('front.html', posts = posts, cur_time = 'Queried %s seconds ago' %  cur_time)

class PostPage(BaseHandler):  
    def single_post(self, post_id):
        post = memcache.get('post_key')
        cached_time = memcache.get('post_keytwo')
        if post is not None:
            results = {'post': post, 'time': cached_time}
            return results
        else:
            # key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            # post = db.get(key)
            post = Post.get_by_id(int(post_id))
            queried_time = time.time()
            memcache.set_multi({'post_key': post, 'post_keytwo': queried_time})
            results = {'post': post, 'time': queried_time}
            return results

    def get(self, post_id):
        results = self.single_post(post_id)
        single_post = results['post']
        cur_time = int(time.time() - results['time'])

        if not single_post:
            self.error(404)
            return
        self.render("permalink.html", single_post = single_post, cur_time = 'Queried %s seconds ago' %  cur_time)

class NewPost(BaseHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

#Homepage
class MainPage(BaseHandler):
    def get(self):
        self.redirect('/blog')
        # self.response.headers['Content-Type'] = 'text/plain'
        # visits = 0                                        
        # cookie_val = self.request.cookies.get('visits')       
        # if cookie_val:
        #     good_cookie_val = check_secure_val(cookie_val)
        #     if good_cookie_val:
        #         visits = int(good_cookie_val)
        
        # visits = visits + 1
        # new_cookie_val = make_secure_val(str(visits))
        # self.response.headers.add_header('Set-Cookie', 'visits = %s' % new_cookie_val)
        # self.write("You've been here %s times." % visits)

#User account handlers
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

class Signup(BaseHandler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = {username:username,
                      email:email}

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        q = User.all()
        q.filter("username = ", username)
        filtered_q = q.get()
        if filtered_q:
            params['username_exists'] = "That username already exists."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            hashed_password = make_pw_hash(username, password)
            acct = User(username = username, password = hashed_password, email = email)
            acct.put() 
            self.response.headers['Content-Type'] = 'text/plain'
            secure_user_id = make_secure_val(str(acct.key().id()))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % secure_user_id)
            self.redirect('/blog/welcome')

class Login(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        have_error = False
        
        username = self.request.get('username')
        password = self.request.get('password')

        params = {}

        q = User.all()
        q.filter("username =", username)
        find_user = q.get()

        if find_user:
            hashed_pw = find_user.password
            acct = find_user.key().id()
            check_pw_match = valid_pw(username, password, hashed_pw)
            if check_pw_match:
                self.response.headers['Content-Type'] = 'text/plain'
                secure_user_id = make_secure_val(str(acct))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % secure_user_id)
                self.redirect('/blog/welcome')
            else:
                have_error = True
        else:
            have_error = True

        if have_error:
            params['login_error'] = 'Invalid Login'
            self.render('login.html', **params)

class Welcome(BaseHandler):
    def get(self):
        acct_num = check_secure_val(self.request.cookies.get('user_id'))
        if acct_num:
            user = User.get_by_id(int(acct_num))
            username = user.username
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

class Logout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog/signup')

#JSON Output Handlers
class BlogJson(BaseHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        json_output = []
        posts = Post.all()
        for post in posts.run(limit=10):
            t = time.strptime(str(post.created), '%Y-%m-%d %H:%M:%S.%f')
            new_t = time.strftime('%a %b %d %H:%M:%S %Y', t)
            m = time.strptime(str(post.last_modified), '%Y-%m-%d %H:%M:%S.%f')
            new_m = time.strftime('%a %b %d %H:%M:%S %Y', m)
            d = dict(content=post.content, created=str(new_t), last_modified=str(new_m), subject=post.subject)
            json_output.append(d)
        j = json.dumps(json_output)
        self.write(j)

class PostJson(BaseHandler):
    def get(self, post_id):
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        t = time.strptime(str(post.created), '%Y-%m-%d %H:%M:%S.%f')
        new_t = time.strftime('%a %b %d %H:%M:%S %Y', t)
        m = time.strptime(str(post.last_modified), '%Y-%m-%d %H:%M:%S.%f')
        new_m = time.strftime('%a %b %d %H:%M:%S %Y', m)
        d = dict(content=post.content, created=str(new_t), last_modified=str(new_m), subject=post.subject)
        j = json.dumps(d)
        self.write(j)

#Cache Flush
class FlushCache(BaseHandler):
    def get(self):
        memcache.flush_all()
        self.write("Flushed!")


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/.json', BlogJson),
                               ('/blog/([0-9]+).json', PostJson),
                               ('/blog/flush', FlushCache)],
                              debug=True)
