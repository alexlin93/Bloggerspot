import os
import jinja2

from google.appengine.ext import db

from comment import Comment

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# Post Model
class Post(db.Model):
    """
    This is a Post Class which contains information for a post
    Stored in a database.

    Attributes:
        subject = string; title of the post
        content = text; body of the post
        created = datetime; date and time of the post
        last_modified = datatime; date and time of modification
        created_by = text; user name that created the post
        likes = integer; likes that the post receives
        liked_by = list; list of users that liked the post
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.TextProperty()
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    @classmethod
    def by_post_name(cls, name):
        """Finds post by name as name."""
        u = cls.all().filter('name =', name).get()
        return u

    def render(self):
        """Renders the post using the object data."""
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post =", str(self.key().id()))
