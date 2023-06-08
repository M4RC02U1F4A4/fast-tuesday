from flask import Flask, render_template, redirect, request, make_response
from flask_socketio import SocketIO, join_room, emit
from datetime import datetime
import random
import hashlib
import redis
import os

redis_host = str(os.getenv('REDIS_HOST'))

r_cve = redis.Redis(host= redis_host, port = 6379, db = 0)
r_item = redis.Redis(host = redis_host, port = 6379, db = 1, decode_responses = True)
r_user = redis.Redis(host = redis_host, port = 6379, db = 2, decode_responses = True)
r_stats = redis.Redis(host = redis_host, port = 6379, db = 3, decode_responses = True)

print(f"Connected to r_cve {r_cve.ping()}")
print(f"Connected to r_item {r_item.ping()}")
print(f"Connected to r_user {r_user.ping()}")
print(f"Connected to r_stats {r_stats.ping()}")

async_mode = None
app = Flask(__name__)
app.config['SECRET_KEY'] = hashlib.sha256(f"{random.randint(0, 999999)}".encode()).hexdigest()
socketio = SocketIO(app)

# FLASK ROUTES

@app.route('/')
def home():
    resp = make_response(render_template('home.html', NA = r_stats.get("NA"), total_number = r_stats.get("total_number"), critical_number = r_stats.get("critical_number"), high_number = r_stats.get("high_number"), medium_number = r_stats.get("medium_number"), low_number = r_stats.get("low_number"), to_analyze_number =  r_stats.get("to_analyze_number")))
    resp.delete_cookie("user")
    return resp

@app.route('/join', methods = ['POST'])
def join():
    if r_stats.get("NA") == '0':
        if r_user.exists(str(request.form.get('user'))):
            resp = make_response(redirect('/fast'))
            resp.set_cookie("user", value = f"{request.form.get('user')}", httponly = True)
        elif r_user.exists(str(request.cookies.get('user'))):
            resp = make_response(redirect('/fast'))
        else:
            resp = make_response(redirect('/create'))
        return resp
    else:
        return 'bad request!', 400

@app.route('/create')
def create():
    if r_stats.get("NA") == '0':
        resp = make_response(redirect("/fast"))
        user = hashlib.sha256(f"{random.randint(0, 999999)}".encode()).hexdigest()
        resp.set_cookie("user", value = user, httponly = True)
        r_user.json().set(user, "$", {})
        r_user.expire(user, 1209600)
        return resp
    else:
        return 'bad request!', 400

@app.route('/fast')
def fast():
    if not request.cookies.get('user'):
        return make_response(redirect('/'))
    cve_list = get_cve()
    item_list = get_item()
    user = request.cookies.get('user')
    return render_template("fast.html", cve_list = sorted(cve_list, key=lambda d: d['Title']['Value']) , item_list = item_list, user_id = user, user_cve = r_user.json().get(user))

@app.route('/export')
def export():
    if not r_user.exists(str(request.cookies.get('user'))):
        return make_response(redirect('/'))
    cve_list = get_cve()
    user = request.cookies.get('user')
    user_cve = r_user.json().get(user)
    cve_list_final = []
    for cve in cve_list:
        if cve['CVE'] in user_cve and user_cve[cve['CVE']] == 1:
            cve_list_final.append(cve)
    return render_template("export.html", cve_list_final = sorted(cve_list_final, key=lambda d: d['CVSSScoreSets'][0]['BaseScore'], reverse=True), accepted = len(cve_list_final), rejected = len(cve_list) - len(cve_list_final), user_id = user)

@app.route('/status')
def status():
    try:
        r_cve.ping()
        return "OK", 200
    except:
        return "ERROR", 500

# OTHER FUNCTIONS

def get_cve():
    month = f"{datetime.now().year}-{datetime.now().strftime('%b')}"
    cve_list_name = r_cve.keys(f"{month}:*")
    cve_list = []
    for cve in cve_list_name:
        cve_list.append(r_cve.json().get(cve.decode()))
    return cve_list

def get_item():
    item_list_name = r_item.keys("*")
    item_list = {}
    for item in item_list_name:
        item_list[f'{item}'] = r_item.get(item)
    return item_list

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d %b %Y'):
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S').strftime(format)

@socketio.on('join_room')
def on_join(data):
    room = data["room"]
    join_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    room = data["room"]
    cve = data["cve"]
    action = data["action"]
    r = r_user.json().get(room)
    r[cve] = action
    r_user.json().set(room, '$', r)
    emit("room_message", {'cve':cve, 'action':action}, room=room)