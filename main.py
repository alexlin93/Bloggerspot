import os
import hmac
import re

from post import Post
from comment import Comment
from user import User

import jinja2
import webapp2

from google.appengine.ext import db

secret = 'du.uyX9fE~Tb6.pp&U3D-0smY0,Gqi$^jS34tzu9'
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Helper Functions
def render_str(template, **params):
    """Strings together the parameters for jinja templates"""
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    """Takes hashed pw and adds salt; this will be the cookie"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """Checks if val is secured by running make_secure_val again"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Main Handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    """Sets the cookie as the name, hashed password plus salt"""
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    """Reads the cookie in the request"""
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    """Sets the cookie with user id and enters into db"""
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    """Deletes the cookie by setting user to nothing"""
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    """Checks cookie to see if user is logged in"""
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# Registration
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def val_username(username):
    return username and USER_RE.match(username)


PASSWORD_RE = re.compile(r"^.{3,20}$")


def val_password(password):
    return password and PASSWORD_RE.match(password)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


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
        """Val is None then errors will be in params"""
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
        """If there are errors then signup.html will render with params"""
        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        """
        Makes sure the user doesn't already exist
        If it already exists, renders error msg
        """
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error1=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            print "name ===", self.username
            u.put()
            """
            If user is valid then user info is
            Stored to db and user redirected to main pg
            """
            self.login(u)
            return self.redirect('/')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        """
        From @classmethod login, returns user
        If info is valid combination
        """
        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


# Main Page and Post Pages
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class MainPage(Handler):
    def get(self):
        """Main page will be all the posts with most recent on top"""
        posts = Post.all().order('-created')
        self.render('main.html', posts=posts)


class PostHandler(Handler):
    def get(self, post_id):
        """Renders the post from db using post_id into a permalink page"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        print post

        if not post:
            return self.error(404)

        self.render("permalink.html", post=post)


# Error Pages
class LikeError(Handler):
    def get(self):
        self.write("Oops! You can't like your own post & only like once!")


class EditDeleteError(Handler):
    def get(self):
        self.write("You can only edit or delete posts you have created.")


class CommentError(Handler):
    def get(self):
        self.write('You can only edit or delete comments you have created.')


# New Post
class NewPost(Handler):
    def get(self):
        """
        Make sure only a user creates a newpost
        Or redirects to login
        """
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        """
        If not a user, redirects to main page
        If the post is created right it gets put into Post db
        But if not it returns an error
        """
        if not self.user:
            return self.redirect('/')

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
            return self.render("newpost.html", subject=subject,
                               content=content, error=error)


# Edit Post
class UpdatePost(Handler):
    def get(self, post_id):
        """
        If not a user, redirects to login
        If the user is the author,
        Edit page renders with the post content
        """
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.created_by
            current_user = self.user.name
            if author == current_user:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                print "post = ", post
                error = ""
                return self.render("updatepost.html", subject=post.subject,
                                   content=post.content, error=error)
            else:
                return self.redirect("/editDeleteError")

    def post(self, post_id):
        """
        If not a user, redirects to login
        If the post has a post_id and it's the author,
        Post or p is updated with new subject and content
        """
        if not self.user:
            self.redirect("/login")

        if post_id:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)
            author = p.created_by
            current_user = self.user.name
            if author == current_user:
                p.subject = self.request.get('subject')
                p.content = self.request.get('content')
                p.put()
                self.redirect('/%s' % str(p.key().id()))
                pid = p.key().id()
                print "pid = ", str(pid)


# How to Like Posts
class LikePost(Handler):
    def get(self, post_id):
        """
        If not a user, redirects to login
        If the post has a post_id and it's the author,
        Post or p is updated with new subject and content
        """
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.created_by
            current_user = self.user.name

            if author == current_user or current_user in post.liked_by:
                return self.redirect('/likeError')
            else:
                post.likes = post.likes + 1
                post.liked_by.append(current_user)
                post.put()
                return self.redirect('/')


# How to Delete Posts
class DeletePost(Handler):
    def get(self, post_id):
        """
        If not a user, redirects to login
        If current user is the author,
        Post is deleted or else error page renders
        """
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.created_by
            current_user = self.user.name

            if author == current_user:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.delete()
                return self.render("deletepost.html")
            else:
                return self.redirect("/editDeleteError")


# How to Make a New Comment
class NewComment(Handler):
    def get(self, post_id):
        """
        If not a user, redirects to login,
        The post is rendered
        """
        if not self.user:
            error = "You must be logged in to comment"
            return self.redirect("/login", error=error)
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        return self.render("newcomment.html", subject=subject, content=content,
                           pkey=post.key())

    def post(self, post_id):
        """
        If a new comment was made,
        This makes sure post_id exists
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            return self.error(404)
        """Makes sure user is signed in"""
        if not self.user:
            return self.redirect('login')
        """Creates the comment"""
        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment, post=post_id, parent=self.user.key())
            c.put()
            return self.redirect('/%s' % str(post_id))
        else:
            error = "please provide a comment!"
            return self.render("permalink.html", post=post,
                               error=error)


# How to Edit a Comment
class UpdateComment(Handler):
    def get(self, post_id, comment_id):
        """
        Looks up comments by the current user,
        If the comment id matches with current user,
        Comment page is rendered
        If not, error page is rendered
        """
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            return self.render("updatecomment.html", subject=post.subject,
                               content=post.content, comment=comment.comment)
        else:
            return self.redirect('/commenterror')

    def post(self, post_id, comment_id):
        """
        Comment is put into user key with the same id
        Redirects to post page after
        """
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        return self.redirect('/%s' % str(post_id))


# How to Delete a Comment
class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        """
        Looks up comments by the current user,
        If the comment id matches with current user,
        And If the current user is the author,
        Then comment is deleted and redirect to post page
        Else, error page is rendered
        """
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            author = post.created_by
            current_user = self.user.name
            if author == current_user:
                comment.delete()
                return self.redirect('/%s' % str(post_id))
        else:
            return self.redirect('/commenterror')


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
