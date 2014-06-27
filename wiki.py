import webapp2
import jinja2
import re
import os
from config import SECRET
from google.appengine.ext import db
import random
import string
import hmac
from google.appengine.api import memcache
from urllib import quote, unquote
from uuid import uuid4
import logging

##################################################################
#Jinja configuration settings, notice we have autoescape enabled.#
##################################################################
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__),
                                                'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


#######################################################
#Lets write a helper class to handle boilerplate code.#
#######################################################
class Handler(webapp2.RequestHandler):

    def render_to_response(self, template, **kargs):
        '''Render and write template to response'''

        #Prepare Jinja template.
        template_values = kargs
        template = JINJA_ENVIRONMENT.get_template(template)

        #Write response.
        self.response.write(template.render(template_values))

    def set_session_cookie(self, username):
        '''Set user cookie'''

        #Generate cookie value
        cookie_val = username+'|'+hmac.new(SECRET, username).hexdigest()

        #Write cookie header
        self.response.headers.add_header('Set-Cookie', 'user={0}; Path=/'.format(cookie_val))

    def authenticate_user_through_cookie(self, user_environment):
        '''Authenticate user through cookie'''
        
        #Fetch user cookie
        user_cookie = self.request.cookies.get('user')

        #Verify user cookie and update user_environment accordingly.
        try:
            username, HASH = user_cookie.split('|')
            if HASH == hmac.new(SECRET, username).hexdigest():
                user_environment['logged_in'] = True
                user_environment['username'] = username
            else:
                user_environment['logged_in'] = False
        except:
            user_environment['logged_in'] = False

    def load_wiki(self, user_environment, page):
        '''Load wiki content'''
        content = None
        #Check if a particular page id was specified and if so fetch it
        #from the database - assuming this is not done very often.
        page_id = self.request.get('page_id')
        if page_id:
            content = db.GqlQuery('select * from Content where page_id = :page_id',
                                  page_id=page_id).get().content
            

        #Try getting content from memcache.
        if not content: content = memcache.get(page)

        #Only hit the database if content is not in memcache.
        #Ideally and for scalability we would like to limit the number of entries the query returns.
        #The above also should be done to manage pagination.
        if not content:
            content = db.GqlQuery('select * from Content where page = :page order by date desc',
                                  page=page).get()
            if content: memcache.set(page, content)

        
        #Since content is rendered with Jinja autoescape off
        #we would ideally only allow a whitelist of html tags.
        #Ideally we should also check for malformed html that could break our DOM structure.
        #For now I'll only escape <script> tags (blacklist approach).
        try:
            content = content.decode("utf-8").replace('<script>','&lt;script&gt;').\
                      replace('</script>','&lt;/script&gt;').encode("utf-8")
        except Exception as e:
            logging.error(e)
            content = None

        #Load content into user_environment.
        user_environment['content'] = content

    def update_wiki(self, page, content):
        '''Update wiki content'''

        #Update memcache and db.
        #Ideally we would like these operations to be atomic.
        memcache.set(page, content)
        Content(page=page, content=content, page_id=str(uuid4())).put()

    def load_history(self, user_environment, page):
        '''Load wiki history'''

        #Assuming the history page doesn't get visited nearly as often,
        #we'll fetch the data from the database as opposed to from memcache.
        history = db.GqlQuery('select * from Content where page = :page order by date desc',
                                  page=page)

        #Load history into user_environment.
        user_environment['history'] = [{'date': h.date.strftime("%H:%M:%S, %B %d, %Y"),
                                        'content': h.content,
                                        'page_id': h.page_id} for h in history]


##################
#Datastore models#
##################
        
class User(db.Model):
    username = db.StringProperty()
    pwd = db.StringProperty(indexed=False)
    email = db.StringProperty()

class Content(db.Model):
    page = db.StringProperty()
    content = db.TextProperty(indexed=False)
    date = db.DateTimeProperty(auto_now_add = True)
    page_id = db.StringProperty()

##################
#Request Handlers#
##################
    
class Signup(Handler):
    def get(self):
        user_environment = {}
        
        #Check if the user is not already logged in.
        self.authenticate_user_through_cookie(user_environment)

        #If user is logged in already, rediredt to main page.
        if user_environment['logged_in']:
            self.redirect('/')
            return

        #Get referer
        try: referer = self.request.headers['Referer']
        except: referer = '/'

        #Render to response
        self.render_to_response('signup.html', referer=referer)

    def post(self):

        #Fetch form values - Jinja autoescape on.
        username = self.request.get('username')
        password = self.request.get('password')
        verify_password = self.request.get('verify')
        email = self.request.get('email')
        referer = str(self.request.get('referer'))[:-1]

        #Check that the form values are valid.
        user_environment = {}
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            user_environment['username_error'] = True
        if not re.match(r'^.{3,20}$', password):
            user_environment['password_error'] = True
        if not password == verify_password:
            user_environment['verify_password_error'] = True
        if email and not re.match(r'^[\S]+@[\S]+\.[\S]+$', email):
            user_environment['email_error'] = True

        #Check username is not taken
        user = db.GqlQuery('select * from User where username = :username',
                           username=username).get()
        if user: user_environment['username_error'] = True

        #If the form is not valid or username is taken resend the form and highlight errors.
        if any([user_environment[e] for e in user_environment.keys()]):
            self.render_to_response('signup.html', **user_environment)
            return

        #Store user in database
        salt = ''.join([random.choice(string.letters) for i in range(5)])
        pwd = hmac.new(SECRET, username+password+salt).hexdigest()
        User(username=username, pwd=pwd+'|'+salt, email=email).put()

        #Set session cookie
        self.set_session_cookie(username)

        #Redirect user to main page
        self.redirect(referer)


class Login(Handler):
    def get(self):
        user_environment = {}
        
        #Check if the user is not already logged in.
        self.authenticate_user_through_cookie(user_environment)

        #If user is logged in already, rediredt to main page.
        if user_environment['logged_in']:
            self.redirect('/')
            return
        
        #Get referer
        try: referer = self.request.headers['Referer']
        except: referer = '/'

        #Render to response
        self.render_to_response('login.html', referer=referer)

    def post(self):

        #Fetch form values - notice Jinja autoescape should be on.
        username = self.request.get('username')
        password = self.request.get('password')
        referer = str(self.request.get('referer'))[:-1]

        #Retrieve user
        user = db.GqlQuery('select * from User where username = :username',
                           username=username).get()

        #If username does not exist, resend the form and highlight login error.
        if not user:
            self.render_to_response('login.html', **{'login_error': True})
            return

        #Check that the password is valid. Otherwise, resend the form and highlight login error.
        pwd, salt = user.pwd.split('|')
        if hmac.new(SECRET, username+password+salt).hexdigest() != pwd:
            self.render_to_response('login.html', **{'login_error': True})
            return

        #Set session cookie
        self.set_session_cookie(username)

        #Redirect user to referer
        self.redirect(referer)

class Logout(Handler):
    def get(self):
        #Delete user cookie
        self.response.delete_cookie('user')

        #Redirect user to referer
        try: referer = self.request.headers['Referer']
        except: referer = '/'
        self.redirect(referer)

class EditPage(Handler):
    def get(self, page):
        user_environment = {'edit': True}

        #Verify user through cookie
        self.authenticate_user_through_cookie(user_environment)

        #Redirect the user to wiki page if he/she is not logged in.
        if not user_environment['logged_in']: self.redirect(page)

        #Include view link.
        user_environment['page'] = page

        #Load content, if there is no content load empty textarea.
        self.load_wiki(user_environment, page)
        if not user_environment['content']: user_environment['content'] = ''

        #Render webpage
        self.render_to_response('wiki.html', **user_environment)

    def post(self,page):

        #Fetch form values - Jinja autoescape is off.
        content = self.request.get('content').strip()

        #Update wiki
        self.update_wiki(page, content)

        #Redirect to wiki
        self.redirect(page)

class WikiPage(Handler):
    def get(self, page):
        user_environment = {'edit': False}

        #Verify user through cookie
        self.authenticate_user_through_cookie(user_environment)

        #Include edit link if user is logged in
        if user_environment['logged_in']:
            user_environment['edit_page'] = '/_edit{0}'.format(page)

        #Include history link
        user_environment['history'] = '/_history{0}'.format(page)

        #Load content
        self.load_wiki(user_environment, page)

        #If there is no content at this address and user is logged in
        #redirect to edit page.
        if not user_environment['content'] and user_environment['logged_in']:
            self.redirect('/_edit{0}'.format(page))
            return
        elif not user_environment['content']: user_environment['content'] = ''

        #Render wiki page
        self.render_to_response('wiki.html', **user_environment)

class HistoryPage(Handler):

    def get(self, page):
        user_environment = {}

        #Verify user through cookie
        self.authenticate_user_through_cookie(user_environment)

        #Include view link.
        user_environment['page'] = page

        #Load history
        self.load_history(user_environment, page)

        #Add view link and, if user is logged in, add edit link as well.
        for item in user_environment['history']:
            item['view'] = '{0}?page_id={1}'.format(page, item['page_id'])
            if user_environment['logged_in']:
                item['edit'] = '/_edit{0}?page_id={1}'.format(page, item['page_id'])

        #Render history page
        self.render_to_response('history.html', **user_environment)


############
#URL mapper#
############
        
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/_edit' + PAGE_RE, EditPage),
    ('/_history' + PAGE_RE, HistoryPage),
    (PAGE_RE, WikiPage),
], debug=True)
