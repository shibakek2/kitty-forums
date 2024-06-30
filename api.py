# meow 
import os
import asyncio
from datetime import timedelta
import random
import string
import httpx
from flask import Flask, render_template, redirect, url_for, request, make_response, Response
from flask import Flask, Blueprint, request
from flask import Flask, request, jsonify
from flask import Flask, render_template, redirect, url_for, request
from flask import Flask, send_file
from flask import Flask, request, jsonify
from flask import Flask
from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_cors import CORS
from flask import Flask, request, jsonify, send_from_directory
import os
from markupsafe import escape
from uuid import uuid4
import secrets
import json
import requests
import json
import secrets
import urllib.parse
from urllib.parse import urlparse, parse_qs
from glob import glob
import os
from datetime import datetime
import RPi.GPIO as GPIO
import threading
import socketio
from flask_socketio import SocketIO, emit
follow_queue = asyncio.Queue()
queue = asyncio.Queue()
lock = threading.Lock()
cooldowns = {}
success_count = 0
fail_count = 0
GPIO.setmode(GPIO.BCM)
led_pin = 17
fan_pin = 27
GPIO.setup(led_pin, GPIO.OUT)
app = Flask(__name__)
socketio = SocketIO(app)
app.config['SECRET_KEY'] = secrets.token_hex(32) 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60) 
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'sign_in' 
CORS(app)
USER_DATA_FILE = "users.json"
HCAPTCHA_SECRET_KEY = ''
KEY_LENGTH = 32
TOKEN_LENGTH = 64
api_key = ''
api_secret = ''
api_url = 'https://api.mailjet.com/v3.1/send'
sender_name = 'Dev'
sender_email = 'trash-bin@kitty-forums.lol'
subject = 'Verification Code'
# gayass
Website_url = "kitty-forums.lol"
embed_image = "https://cdn.discordapp.com/attachments/1154960779175534612/1246040333041795153/download.jpg?ex=665af0fd&is=66599f7d&hm=e7c3dad4a2251e2cd48254cde14d40a179091fd1d55c2353663db4af403f2bdc&"
discord_invite_link = "https://discord.gg/dH3QzRabg7"
@app.before_request
def rotate_session():
    session.modified = True 
#


def get_token():
    file_path = 'tokens.txt'
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return random.choice(lines).strip()

#@app.after_request
#def set_csp(response):
#    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
#    return response
#
@app.after_request
def set_hsts(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
#
#
#
@app.before_request
def make_session_permanent():
    session.permanent = True

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def load_ads():
    with open('ads.json', 'r') as f:
        ads = json.load(f)
        ad_key = random.choice(list(ads.keys()))
        return ads[ad_key]

def send_discord_message(message):
    username = "Kitty-forums"
    avatar_url = "https://cdn.discordapp.com/attachments/1154960779175534612/1246040333041795153/download.jpg?ex=665af0fd&is=66599f7d&hm=e7c3dad4a2251e2cd48254cde14d40a179091fd1d55c2353663db4af403f2bdc&"
    webhook_url = "https://discord.com/api/webhooks/1246038807242084434/jQDeKwWAX_1RTelAkeSOfrt_Brci3-2aND1o-u0gC0dbUL3990a21SE-1XLKgY-VddKt"
    
    data = {
        "username": username,
        "avatar_url": avatar_url,
        "embeds": [
            {
                "title": "New Message",
                "description": message,
                "color": 7506394  # Decimal color value for the embed
            }
        ]
    }
    
    response = requests.post(webhook_url, json=data)
    
    if response.status_code == 204:
        print("Message sent successfully")
    else:
        print(f"Failed to send message: {response.status_code}, {response.text}")

def send_admin_logs(message):
    username = "Kitty site logs"
    avatar_url = "https://cdn.discordapp.com/attachments/1154960779175534612/1246040333041795153/download.jpg?ex=665af0fd&is=66599f7d&hm=e7c3dad4a2251e2cd48254cde14d40a179091fd1d55c2353663db4af403f2bdc&"
    webhook_url = "https://discord.com/api/webhooks/1246737696588824597/wF8QTVaIeTbVq4_gDzMUt_igBlRyWlB0pkVZ8Fz_mfDqvUBYa_SVisKUSWl9JRJ3-k-W"
    
    data = {
        "username": username,
        "avatar_url": avatar_url,
        "embeds": [
            {
                "title": "New action",
                "description": message,
                "color": 7506394  # Decimal color value for the embed
            }
        ]
    }
    
    response = requests.post(webhook_url, json=data)
    
    if response.status_code == 204:
        print("Message sent successfully")
    else:
        print(f"Failed to send message: {response.status_code}, {response.text}")



@app.route('/usernames', methods=['GET'])
def fetch_usernames():
    try:
        response = requests.get('http://localserverip/api/v1/usernames')
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
        usernames = response.json()  # Try to parse JSON
        return jsonify(usernames)
    except requests.exceptions.RequestException as e:
        # Catch any request-related errors
        return jsonify({"error": str(e)}), 500
    except ValueError:
        # Catch JSON decode errors
        return jsonify({"error": "Invalid JSON response"}), 500

def search_username(username):
    response = requests.post('http://localserverip/search-by-username', json={'username': username})
    if response.status_code == 200:
        return response.json()
    return None

def search_username_by_token(token):
    response = requests.post('http://localserverip/search-username-by-token', json={'token': token})
    if response.status_code == 200:
        return response.json().get('username')
    return None

def search_usernames(username, field):
    user_data = search_username(username)
    if user_data:
        return user_data.get(field, None)
    return None

class User(UserMixin):
    def __init__(self, id):
        self.id = id

def update_token(username, new_token):
    requests.post(f'http://localserverip/update-token', params={'username': username, 'new_token': new_token})


@login_manager.user_loader
def load_user(user_id):
    user_data = search_username(user_id)
    if user_data:
        user = User(user_id)
        session.permanent = True  # Set session to be permanent
        return user
    return None

def save_user_data(user_data):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file, indent=2)

def verify_hcaptcha(token):
    data = {
        'secret': HCAPTCHA_SECRET_KEY,
        'response': token
    }
    response = requests.post('https://hcaptcha.com/siteverify', data=data)
    result = response.json()
    return result.get('success', False)

def verify_password(hashed_password, password_to_check):
    return check_password_hash(hashed_password, password_to_check)

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

random_code = generate_random_string(32)

def generate_verification_code():
    code_length = 150
    characters = string.ascii_lowercase + string.digits
    verification_code = ''.join(random.choice(characters) for _ in range(code_length))
    return verification_code


def create_email_payload(code, recipient_email, username):
    text_message = 'Null'
    
    html_message = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
        <style>
            body {{
                font-family: 'Courier New', Courier, monospace;
                background-color: #1a1a1a;
                color: #e0e0e0;
                margin: 0;
                padding: 0;
            }}
            .navbar {{
                display: flex;
                justify-content: flex-end;
                background-color: #444444;
                padding: 10px;
            }}
            .navbar button {{
                background-color: #666666;
                color: #ffffff;
                border: none;
                padding: 10px 20px;
                margin: 0 5px;
                cursor: pointer;
                border-radius: 5px;
                font-family: inherit;
            }}
            .navbar button:hover {{
                background-color: #888888;
            }}
            .container {{
                width: 80%;
                max-width: 800px;
                margin: 40px auto;
                background: #2e2e2e;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
            }}
            .forum-post {{
                border-bottom: 1px solid #999999;
                padding: 10px 0;
                position: relative;
            }}
            .forum-post h2 {{
                margin: 0;
                color: #00ff00;
            }}
            .forum-post p {{
                margin: 5px 0;
            }}
            .delete-btn, .edit-btn {{
                color: #ffffff;
                border: none;
                padding: 5px 10px;
                cursor: pointer;
                border-radius: 5px;
                position: absolute;
                right: 10px;
                top: 10px;
                font-family: inherit;
            }}
            .delete-btn {{
                background-color: #ff0000;
            }}
            .delete-btn:hover {{
                background-color: #ff5555;
            }}
            .edit-btn {{
                background-color: #666666;
                right: 100px;
            }}
            .edit-btn:hover {{
                background-color: #888888;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Hello {username}!</h1>
            <p>Welcome to kitty-forums.lol</p>
            <p>Click the button below to verify your account:</p>
            <a href="https://{Website_url}/verify-email?code={code}&username={username}" style="display: inline-block; background-color: #666666; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 10px;">Verify Account</a>
            <p>If you have trouble clicking the button, you can also copy and paste the following link into your browser:</p>
            <p>https://{Website_url}/verify-email?code={code}&username={username}</p>
            <br>
            <p>Discord server {discord_invite_link}<p>
        </div>
    </body>
    </html>
    '''

    payload = {
        'Messages': [
            {
                'From': {
                    'Email': sender_email,
                    'Name': sender_name
                },
                'To': [
                    {
                        'Email': recipient_email
                    }
                ],
                'Subject': subject,
                'TextPart': text_message,
                'HTMLPart': html_message
            }
        ]
    }
    print(payload)
    return payload

def send_verification_email(email, username):
    try:
        verification_code = generate_verification_code()
        recipient_email = email
        payload = create_email_payload(verification_code, recipient_email, username)
        user_data = search_username(username)
        if user_data is None:
            return False
        
        with open('pending.json', 'r') as f:
            pending_users = json.load(f)
            if username in pending_users:
                return False
            
        pending_users[username] = {
            'username': username,
            'verification_code': verification_code,
        }

        with open('pending.json', 'w') as f:
            json.dump(pending_users, f, indent=4)
        response = requests.post(api_url, json=payload, auth=(api_key, api_secret))

        if response.status_code == 200:
            print(f'Email sent successfully to {username}')
        else:
            print(f'Failed to send email. Status code: {response.status_code}')
            print(response.json())

    except Exception as e:
        print(f"An error occurred: {str(e)}")

async def blink_once():
    GPIO.output(led_pin, GPIO.HIGH)
    await asyncio.sleep(0.5)
    GPIO.output(led_pin, GPIO.LOW)

def run_async_function(async_func):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(async_func)
    loop.close()

def blink_thread():
    thread = threading.Thread(target=run_async_function, args=(blink_once(),))
    thread.start()
    return thread

@app.route('/', methods=['GET'])
async def home():
    return render_template('home.html')


@app.route('/test/test', methods=['GET'])
async def testtt():

    return render_template('test.html')

@app.route('/sign-up', methods=['GET'])
async def sign_up():
    
    return render_template('register.html')


@app.route('/sign-in', methods=['GET'])
async def sign_in():
    
    return render_template('login.html')


@app.route('/home', methods=['GET'])
@login_required
async def home_page():
    
    username = current_user.id
    token = search_usernames(username, "token")
    verified = search_usernames(username, 'verified')
    if verified == True:
        badge = search_usernames(username, 'role')
        if badge == "Owner" or badge ==  "Admin":
            return render_template('adminhome.html', username=username, token=token)
        return render_template('ahome.html', username=username, token=token)
    else:
        return render_template('nverified.html', username=username)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    
    username = current_user.id
    new_token = secrets.token_hex(TOKEN_LENGTH)
    update_token(username, new_token)
    logout_user()
    return render_template('home.html')

@app.route('/search', methods=['GET'])
def search():
    
    return render_template('search.html')

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    username = current_user.id
    token = search_usernames(username, "token")
    
    return render_template('profile.html', username=username, token=token)

@app.route('/nverified', methods=['GET'])
def nverified():
    
    return render_template('nverified.html')

@app.route('/rules', methods=['GET'])
def rules():
    
    return render_template('rules.html')

@app.route('/apanel', methods=['GET'])
@login_required
def apanel():
    
    username = current_user.id
    badge = search_usernames(username, 'role')
    if badge == "Owner" or badge ==  "Admin":
        token = search_usernames(username, "token")
        return render_template('apanel.html', username=username, token=token)
    else:
        return render_template('ahome.html')

@app.route('/auserpanel', methods=['GET'])
@login_required
def auserpanel():
    
    username = current_user.id
    badge = search_usernames(username, 'role')
    if badge == "Owner" or badge ==  "Admin":
        token = search_usernames(username, "token")
        return render_template('auserpanel.html', username=username, token=token)
    else:
        return render_template('ahome.html')

@app.route('/create-post', methods=['GET'])
@login_required
async def create_post():
    
    username = current_user.id
    token = search_usernames(username, "token")
    return render_template('post.html', username=username, token=token)


@app.route('/b', methods=['GET'])
@login_required
async def view_bio():
    
    username = current_user.id
    posts = search_usernames(username, "posts")
    role = search_usernames(username, "role")
    bio = search_usernames(username, "bio")
    return render_template('tprofile.html', username=username, posts=posts, role=role, bio=bio)


@app.route('/verify-email', methods=['GET'])
def verify_email():
    try:
        code = request.args.get('code')
        username = request.args.get('username')
        
        response = requests.get(f'http://localserverip/verify-email', params={'code': code, 'username': username})
        response.raise_for_status()  # Raises HTTPError for bad responses
        
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Error verifying email: {e}")
        return jsonify({"message": "Error verifying email"}), 400

@app.route('/api/V1/login', methods=['POST'])
def loginuser():
    if current_user.is_authenticated:
        return redirect('https://kitty-forums.lol/home')

    data = request.get_json()

    try:
        response = requests.post('http://localserverip/api/V1/login', json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        user_data = response.json()
        if 'message' in user_data:
            return jsonify({'message': user_data['message']}), response.status_code
        print(f"Error logging in: {e}")
        return jsonify({'message': 'Unable to login'}), 400

    user_data = response.json()
    if 'message' in user_data:
        return jsonify({'message': user_data['message']}), response.status_code

    username = user_data.get('username')
    token = user_data.get('token')
    role = user_data.get('role')
    verified = user_data.get('verified')

    if not username:
        return jsonify({'message': 'Invalid response from authentication server'}), 500

    user = load_user(username)
    if user is None:
        print(f"User {username} not found")
        return jsonify({'message': 'User not found'}), 404

    login_user(user)

    # Return the appropriate response based on the user's role
    if role in ["Owner", "Admin"]:
        return render_template('apanel.html'), 200
    else:
        return render_template('ahome.html'), 200


@app.route('/api/V1/register', methods=['POST'])
def api_register():
    data = request.json
    try:
        response = requests.post(f'http://localserverip/api/V1/register', json=data)
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error registering user: {e}")
        return jsonify({'error': 'Unable to register user'}), 400

    return jsonify(response.json())

@app.route('/api/form/V1/submit-form', methods=['POST'])
def submit_form():
    #return jsonify({'message': 'Form creation is under construction to bring you a better and safer experience'}), 400
    data = request.form
    topic = escape(data.get('topic', ''))
    message = escape(data.get('message', ''))
    title = escape(data.get('title', '').replace(' ', '-'))
    token = escape(data.get('token', ''))
    username = search_username_by_token(token)
    title = title.replace('-', ' ')
    random_filename = ''.join([str(random.randint(0, 9)) for _ in range(15)]) + '.json'
    form_id = random_filename.split('.')[0]
    filename = f'./forms/{random_filename}'
    verified = search_usernames(username, 'verified')
    usertoke = search_usernames(username, "token")
    
    if username:
        if token == usertoke:
            if verified:
                if 'img src=' in message or 'xss' in message or 'video src=x' in message:
                    return jsonify({'error': 'Nice Try buddy XD'}), 400
                if '@here' in message or '@everyone' in message:
                    return jsonify({'error': 'The message cannot contain @here or @everyone.'}), 400
                if os.path.exists(filename):
                    return jsonify({'error': 'A form with this title already exists. Please choose a different title.'}), 400
                if not username or not message or not title:
                    return jsonify({'error': 'Username, message, and title are required'}), 400
                if len(message) < 1 or len(message) > 1000:
                    return jsonify({'error': 'Post must be between 1 and 1000 characters!'}), 400
                json_data = {
                    "title": title,
                    "author": username,
                    "message": message,
                    "topic": topic,
                    "token": token,
                    "username": username,
                    "verified": verified,
                    "usertoke": usertoke,
                    "form_id": form_id
                }
    
                response = requests.post('http://localserverip/api/form/V1/handle-form', json=json_data)
                return jsonify(response.json()), response.status_code
    
            else:
                return jsonify({'message': 'You need to verify your email to continue'}), 403
        else:
            return jsonify({'message': 'Incorrect Token'}), 403
        

@app.route('/api/form/V1/delete-post', methods=['POST'])
def delete_post():
    data = request.json
    try:
        response = requests.post(f'http://localserverip/api/form/V1/delete-post', json=data)
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error deleting post: {e}")
        return jsonify({'error': 'Unable to delete post'}), 400

    return jsonify(response.json())

@app.route('/api/ads/V1/random-ad', methods=['GET'])
def get_random_ad():
    ad_url = load_ads()
    return jsonify({'url': ad_url})

@app.route('/api/form/V1/add-comment', methods=['POST'])
def add_comment():
    data = request.json
    try:
        response = requests.post(f'http://localserverip/api/form/V1/add-comment', json=data)
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error adding comment: {e}")
        return jsonify({'error': 'Unable to add comment'}), 400

    return jsonify(response.json())

@app.route('/api/form/V1/add-view', methods=['POST'])
def add_view():
    data = request.json
    try:
        response = requests.post(f'http://localserverip/api/form/V1/add-view', json=data)
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error adding view: {e}")
        return jsonify({'error': 'Unable to add view'}), 400

    return jsonify(response.json())
 
@app.route('/api/v1/get-my-posts/', methods=['GET'])
def get_my_posts():
    username = request.args.get('username', '')
    try:
        response = requests.get(f'http://localserverip/api/v1/get-my-posts/', params={'username': username})
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error fetching posts: {e}")
        return jsonify({'error': 'Unable to fetch posts'}), 400

    return jsonify(response.json())

@app.route('/api/form/V1/delete-comment', methods=['POST'])
def delete_comment():
    data = request.json
    try:
        response = requests.post(f'http://localserverip/api/form/V1/delete-comment', json=data)
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error deleting comment: {e}")
        return jsonify({'error': 'Unable to delete comment'}), 400

    return jsonify(response.json())

@app.route('/api/form/V1/search', methods=['GET'])
def search_forms():
    form = request.args.get('form')
    try:
        response = requests.get(f'http://localserverip/api/form/V1/search', params={'form': form})
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error searching forms: {e}")
        return jsonify({'error': 'Form not found'}), 400

    return jsonify(response.json())

@app.route('/api/form/V1/list-forms', methods=['POST'])
def list_forms():
    try:
        response = requests.post(f'http://localserverip/api/form/V1/list-forms')
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error listing forms: {e}")
        return jsonify({'forms': 'under construction'}), 400

    return jsonify(response.json())

@app.route('/api/form/V1/get-form/<form_id>', methods=['GET'])
def forward_get_form(form_id):
    try:
        response = requests.get(f'http://localserverip/api/form/V1/get-form/{form_id}')
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching form: {e}")
        return jsonify({"error": "Form not found"}), 404

    return jsonify(response.json())

@app.route('/api/form/V1/list-topic-forms', methods=['GET'])
def list_topic_forms():
    try:
        response = requests.get(f'http://localserverip/get-formsssss')
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching form: {e}")
        return jsonify({"error": "Form not found"}), 404

    return jsonify(response.json())

@app.route('/api/topic/V1/get-topics', methods=['GET'])
def get_topics():
    try:
        response = requests.get(f'http://localserverip/api/topic/V1/get-topics')
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error fetching topics: {e}")
        return jsonify({'error': 'Unable to fetch topics'}), 400

    return jsonify(response.json())


FORMS_DIR = './forms'

@app.route('/p/<form_name>', methods=['GET'])
def get_form(form_name):
    form_id = escape(form_name)
    response = requests.get(f'http://localserverip/api/form/V1/get-form/{form_id}')
    
    if response.status_code == 200:
        form_data = response.json()
        
        if current_user.is_authenticated:
            username = current_user.id 
            usertoke = search_usernames(username, "token")
            return render_template("aglobalpost.html", username=username, form_data=form_data, token=usertoke)
        else:
            return render_template("globalpost.html", form_data=form_data)
    else:
        return render_template("404.html") , 400

####################################################################

@app.route('/api/form/V1/recent-posts', methods=['GET'])
def get_recent_posts():
    files = glob('./forms/*.json')
    sorted_files = sorted(files, key=os.path.getmtime, reverse=True)[:5]
    recent_posts = []
    for file_path in sorted_files:
        with open(file_path, 'r') as file:
            post_data = json.load(file)
            recent_posts.append(post_data)
    return jsonify(recent_posts),   200

@app.route('/api/form/V1/search', methods=['GET'])
def search_posts():
    query = request.args.get('query')
    if not query:
        return jsonify({'error': 'Query parameter "query" is required'}), 400
    files = glob('./forms/*.json')
    found_posts = []
    for file_path in files:
        with open(file_path, 'r') as file:
            post_data = json.load(file)
            if query.lower() in post_data['title'].lower():
                found_posts.append(post_data)
    return jsonify(found_posts), 200


#############ADMIN STUFF##########################  


@app.route('/blacklist', methods=['POST'])
def blacklist():
    data = request.json
    busername = escape(data.get('busername',''))
    username = escape(data.get('username',''))
    token = escape(data.get('token', ''))
    verified = search_usernames(username, 'verified')
    usertoke = search_usernames(username, "token")
    if busername == "shibakek":
        return jsonify({"error": "Your actions have been recorded and reported"}), 400
    if token == usertoke:
        if verified == True:
            badge = search_usernames(username, 'role')
            if badge == "Owner" or badge ==  "Admin":
                with open(USER_DATA_FILE, 'r') as file:
                    user_data = json.load(file)

                if busername not in user_data:
                    return jsonify({"error": "User not found"}), 404
                user_data[busername]['token'] = secrets.token_hex(TOKEN_LENGTH)
                user_data[busername]['muted'] = True
                user_data[busername]['banned'] = True
                user_data[busername]['verified'] = False
                save_user_data(user_data)
                message = f"{username} Banned {busername}"
                send_admin_logs(message)
                return jsonify({"success": "User was blacklisted"}), 200
            else:
                return jsonify({"message": "Incorrect Token"}), 403
        else:
            return jsonify({"message": "Verify your email to continue"}), 403 
    else:
        return jsonify({"message": "Incorrect token"}), 403 

@app.route('/unblacklist', methods=['POST'])
def unblacklist():
    data = request.json
    busername = escape(data.get('busername',''))
    username = escape(data.get('username',''))
    token = escape(data.get('token', ''))
    verified = search_usernames(username, 'verified')
    usertoke = search_usernames(username, "token")
    if busername == "shibakek":
        return jsonify({"error": "Your actions have been recorded and reported"}), 400
    if token == usertoke:
        if verified == True:
            badge = search_usernames(username, 'role')
            if badge == "Owner" or badge ==  "Admin":
                with open(USER_DATA_FILE, 'r') as file:
                    user_data = json.load(file)

                if busername not in user_data:
                    return jsonify({"error": "User not found"}), 404
                user_data[busername]['token'] = secrets.token_hex(TOKEN_LENGTH)
                user_data[busername]['muted'] = False
                user_data[busername]['banned'] = False
                user_data[busername]['verified'] = True
                save_user_data(user_data)
                message = f"{username} Unbaned {busername}"
                send_admin_logs(message)
                return jsonify({"success": "User was Unblacklisted"}), 200
            else:
                return jsonify({"message": "Incorrect Token"}), 403
        else:
            return jsonify({"message": "Verify your email to continue"}), 403 
    else:
        return jsonify({"message": "Incorrect token"}), 403 
    
#TEST ENDPOINTS#######


@app.route('/login-with-token', methods=['GET'])
def token_login():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Token is required"}), 400

    username = search_username_by_token(token)
    if username:
        user = load_user(username)
        if user:
            session['username'] = username
            login_user(user)
            return jsonify({"message": "Logged in successfully", "username": username}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Invalid token"}), 401



@app.route('/api/forms/report-form/V1', methods=['POST'])
def report():
    data = request.get_json()
    if not all(k in data for k in ("username", "token", "formid")):
        return jsonify({"error": "Missing required fields"}), 400

    username = data['username']
    token = data['token']
    formid = data['formid']
    usertoke = search_usernames(username, "token")
    if token == usertoke:
        form_path = f"./forms/{formid}.json"
        if not os.path.isfile(form_path):
            return jsonify({"error": "Form not found"}), 404

        pending_reports_path = "pendingreports.json"
        if os.path.isfile(pending_reports_path):
            with open(pending_reports_path, 'r') as file:
                pending_reports = json.load(file)
        else:
            pending_reports = []
        for report in pending_reports:
            if report["username"] == username and report["formid"] == formid:
                return jsonify({"error": "Report already submitted for this form"}), 409

        pending_reports.append({"username": username, "formid": formid})
        with open(pending_reports_path, 'w') as file:
            json.dump(pending_reports, file, indent=4)
        message = f"A New post was reported\n\nPost: https://kitty-forums.lol/p/{formid}\n\nUser: {username}"    
        send_admin_logs(message)
        return jsonify({"message": "Report submitted successfully"}), 200
    else:
        return jsonify({"message": "Incorrect token"}), 403
     
@app.route('/api/forms/get-form/<formid>', methods=['GET'])
def get_report(formid):
    pending_reports_path = "pendingreports.json"
    if os.path.isfile(pending_reports_path):
        with open(pending_reports_path, 'r') as file:
            pending_reports = json.load(file)
        
        form_report = next((report for report in pending_reports if report['formid'] == formid), None)
        
        if form_report:
            return jsonify(form_report), 200
        else:
            return jsonify({"error": "Form not found"}), 404
    else:
        return jsonify({"error": "Pending reports file not found"}), 404




@app.route('/stream')
def stream():
    return render_template('stream.html')

def load_messages():
    try:
        with open('chat.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

@app.route('/chat')
def snake():
    messages = load_messages()
    return render_template('snake.html', messages=messages)    

def save_messages(messages):
    with open('chat.json', 'w') as file:
        json.dump(messages, file)

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('message')
def handle_message(message):
    messages = load_messages()
    messages.append(message)
    save_messages(messages)
    emit('message', message, broadcast=True)

if __name__ == '__main__':
    app.run(debug=False)
