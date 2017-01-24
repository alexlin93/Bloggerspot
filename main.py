import os
import hmac
import re
import random
from string import letters
import hashlib

import jinja2
import webapp2

from google.appengine.ext import db

secret = 'du.uyX9fE~Tb6.pp&U3D-0smY0,Gqi$^jS34tzu9'
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# takes the user's password and hashes it with the secret
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# makes sure that the hashed password is secure
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# main arguments that other classes will pass through
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # sets a cookie with name as name and value as val
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # reads the cookie in the request
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # sets the cookie with user id and enters into db
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # deletes the cookie by setting user to nothing
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # checks cookie to see if user is logged in
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# user info
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


# makes a the pw hashed and h is stored to db
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


# takes name and pw and checks values in db
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# creates ancestor element to store all users in db
def users_key(group='default'):
    return db.Key.from_path('users', group)


# user object stored in db
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # convenience function for looking up user by id
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    # convenience function for looking up user by name
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    # convenience function for creating new user
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    # convenience function for making sure
    # user exists and pw is valid
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# Registration

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def val_username(username):
    return username and USER_RE.match(username)


def val_password(password):
    return password and PASSWORD_RE.match(password)


def val_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not val_username(self.username):
            params['error1'] = "That's not a valid username."
            have_error = True

        if not val_password(self.password):
            params['error2'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error3'] = "Your passwords didn't match."
            have_error = True

        if not val_email(self.email):
            params['error4'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # makes sure the user doesn't already exist
        # if it already exists, renders error msg
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error1=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            print "name ===", self.username
            u.put()
            # if user is valid then user info is
            # stored to db and user redirected to main pg
            self.login(u)
            self.redirect('/')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # from @classmethod login, returns user
        # if info is valid combination
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.TextProperty()
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    @classmethod
    def by_post_name(cls, name):
        # find post by name as name
        u = cls.all().filter('name =', name).get()
        return u

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post =", str(self.key().id()))


class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("newcomment.html")


class MainPage(Handler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('main.html', posts=posts)


class PostHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        print post

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class LikeError(Handler):
    def get(self):
        self.write("Oops! You can't like your own post & only like once!")


class EditDeleteError(Handler):
    def get(self):
        self.write("You can only edit or delete posts you have created.")


class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     created_by=User.by_name(self.user.name).name, likes=0,
                     liked_by=[])
            p.put()
            self.redirect('/%s' % str(p.key().id()))
            pid = p.key().id()
            print "pid = ", str(pid)
            n1 = User.by_name(self.user.name).name
            print "post created by", n1
        else:
            error = "oops! you need a subject and content!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class UpdatePost(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            n1 = post.created_by
            n2 = self.user.name
            print "n1 = ", n1
            print "n2 = ", n2
            if n1 == n2:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                print "post = ", post
                error = ""
                self.render("updatepost.html", subject=post.subject,
                            content=post.content, error=error)
            else:
                self.redirect("/editDeleteError")

    def post(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)
            p.subject = self.request.get('subject')
            p.content = self.request.get('content')
            p.put()
            self.redirect('/%s' % str(p.key().id()))
            pid = p.key().id()
            print "pid = ", str(pid)


class LikePost(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.created_by
            current_user = self.user.name

            if author == current_user or current_user in post.liked_by:
                self.redirect('/likeError')
            else:
                post.likes = post.likes + 1
                post.liked_by.append(current_user)
                post.put()
                self.redirect('/')


class DeletePost(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            n1 = post.created_by
            n2 = self.user.name

            if n1 == n2:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.delete()
                self.render("deletepost.html")
            else:
                self.redirect("/editDeleteError")


class NewComment(Handler):
    def get(self, post_id):
        # Shows the new comment page
        if not self.user:
            error = "You must be logged in to comment"
            self.redirect("/login")
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        self.render("newcomment.html", subject=subject, content=content,
                    pkey=post.key())

    def post(self, post_id):
        # If a ew comment was made,
        # this makes sure post_id exists
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        # make sure user is signed in
        if not self.user:
            self.redirect('login')
        # creates the comment
        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment, post=post_id, parent=self.user.key())
            c.put()
            self.redirect('/%s' % str(post_id))
        else:
            error = "please provide a comment!"
            self.render("permalink.html", post=post,
                        content=content, error=error)


class UpdateComment(Handler):
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            self.render("updatecomment.html", subject=post.subject,
                        content=post.content, comment=comment.comment)
        else:
            self.redirect('/commenterror')

    def post(self, post_id, comment_id):
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        self.redirect('/%s' % str(post_id))


class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # this ensures the user created the comment
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            comment.delete()
            self.redirect('/%s' % str(post_id))
        else:
            self.redirect('/commenterror')


class CommentError(Handler):
    def get(self):
        self.write('You can only edit or delete comments you have created.')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/([0-9]+)', PostHandler),
                               ('/newpost', NewPost),
                               ('/([0-9]+)/updatepost', UpdatePost),
                               ('/([0-9]+)/newcomment', NewComment),
                               ('/([0-9]+)/updatecomment/([0-9]+)',
                                UpdateComment),
                               ('/([0-9]+)/deletecomment/([0-9]+)',
                                DeleteComment),
                               ('/commenterror', CommentError),
                               ('/([0-9]+)/like', LikePost),
                               ('/signup', Register),
                               ('/([0-9]+)/deletepost', DeletePost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/editDeleteError', EditDeleteError),
                               ('/likeError', LikeError)],
                              debug=True)
