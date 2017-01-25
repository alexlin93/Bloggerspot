from google.appengine.ext import db


class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("newcomment.html")
