import os
import io
import time
import textwrap
import sqlite3
import requests
import humanize

from flask import Flask, flash, redirect, render_template, request, session, url_for
# from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload
from google.oauth2 import service_account

from functions import login_required, moderator_required

BACKUP_INTERVAL = 36000
UPLOAD_FOLDER = "static/uploads"
ITEMS_FOLDER = "items"
TMP_FOLDER = "/tmp"
SHORTCUTS_FOLDER = "shortcuts"
SERVICE_ACCOUNT_FILE = "credentials.json"
SCOPES = ['https://www.googleapis.com/auth/drive']
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

latest_backup = time.time()

os.makedirs(TMP_FOLDER, exist_ok=True)

creds = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)

service = build('drive', 'v3', credentials=creds)

DB_FILE_ID = "1JbCLaBDiGXLUU_G8EHKPSvaQ2MSGBK4T"
DEST_FOLDER = TMP_FOLDER
DEST_FILE_NAME = "mkw.db"

DB_LOCATION = os.path.join(DEST_FOLDER, DEST_FILE_NAME)

db_request = service.files().get_media(fileId=DB_FILE_ID)

fh = io.FileIO(DB_LOCATION, 'wb')
downloader = MediaIoBaseDownload(fh, request)
done = False

while not done: _, done = downloader.next_chunk()

print("File downloaded.")

app = Flask(__name__)
app.secret_key = "zFO3TG|`+!seJvvGky>2d)/pA'6HC;i@"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# app.config["SESSION_PERMANENT"] = False
# app.config["SESSION_TYPE"] = "filesystem"
# app.config["SESSION_FILE_DIR"] = "/tmp/flask_session"
# Session(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
def index():
    if time.time() - latest_backup >= BACKUP_INTERVAL:
        update_database()
        latest_backup = time.time()
    shortcuts, shortcut_items = get_shortcuts("WHERE is_approved=1")
    return render_template("index.html", shortcuts=shortcuts, shortcut_items=shortcut_items)

@app.route("/my-shortcuts")
@login_required
def my_shortcuts():
    shortcuts, shortcut_items = get_shortcuts("WHERE user_id=" + str(session["user_id"]))
    return render_template("index.html", shortcuts=shortcuts, shortcut_items=shortcut_items)

@app.route("/view_shortcut", methods=["GET", "POST"])
def view_shortcut():
    con = sqlite3.connect(DB_LOCATION)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    if request.method == "GET":
        shortcut_id = request.args.get("id")
        if not shortcut_id:
            return redirect("/")
        if not shortcut_id.isdigit():
            return redirect("/")

        shortcut, shortcut_items = get_shortcuts("WHERE shortcuts.id=" + shortcut_id, False)
        if len(shortcut) != 1:
            return redirect("/")
        shortcut = shortcut[0]

        if shortcut["is_approved"] == 0:
            try:
                session["is_moderator"]
            except:
                if session["user_id"] != shortcut["user_id"]: return redirect("/")        

        return render_template("shortcut-info.html", shortcut=shortcut, shortcut_items=shortcut_items)
    elif request.method == "POST":
        submit_values = ["approve", "remove"]
        if "submit" in request.form:
            value = request.form["submit"]
            if not any(sub in value for sub in submit_values):
                return redirect("/")
            elif "approve" in value:
                try:
                    shortcut_id = int(value[len("approve"):])
                    cur.execute("UPDATE shortcuts SET is_approved=1 WHERE id=?", (shortcut_id,))
                    flash("Shortcut approved.")
                except:
                    return redirect("/")
            else:
                try:
                    shortcut_id = int(value[len("remove"):])
                    cur.execute("DELETE FROM shortcuts WHERE id=?", (shortcut_id,))
                    cur.execute("DELETE FROM shortcut_items WHERE shortcut_id=?", (shortcut_id,))
                    flash("Shortcut removed.")
                except:
                    return redirect("/")
        else:
            return redirect("/")
    con.commit()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            flash("Missing username.")
            return redirect(url_for("register"))
        if not password:
            flash("Missing password.")
            return redirect(url_for("register"))
        if len(username) > 16 or any(not (char.isalpha() or char.isdigit() or char in "-_") for char in username):
            flash("Username must be alphanumeric and contain only hyphens and underscores.")
            return redirect(url_for("register"))
        if not (len(password) >= 8 and any(char.isdigit() for char in password) and any(char.isupper() for char in password)):
            flash("Password does not meet requirements.")
            return redirect(url_for("register"))
        if password != confirmation:
            flash("Passwords do not match.")
            return redirect(url_for("register"))
        
        hash = generate_password_hash(password)
        con = sqlite3.connect(DB_LOCATION)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        try:
            id = (cur.execute("INSERT INTO users (username, hash, is_moderator) VALUES (?, ?, ?)", (username, hash, 0))).lastrowid
        except:
            flash("Username is already in use.")
            return redirect(url_for("register"))
        
        con.commit()
        
        session["user_id"] = (cur.execute("SELECT id FROM users WHERE username=?", [(username)])).fetchall()[0]["id"]

        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/shortcut-creation", methods=["GET", "POST"])
@login_required
def shortcut_creation():
    con = sqlite3.connect(DB_LOCATION)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    if request.method == "POST":
        items = request.form.getlist("item")
        course = request.form.get("course")
        percentage = request.form.get("percentage")
        video_url = request.form.get("video_url")
        description = request.form.get("description")

        if not course:
            flash("Course not selected.")
            return redirect(url_for("shortcut_creation"))
        if not percentage:
            flash("Missing percentage.")
            return redirect(url_for("shortcut_creation"))
        if not description:
            flash("Missing description.")
            return redirect(url_for("shortcut_creation"))
        if len(description) > 500:
            flash("Description too long.")
            return redirect(url_for("shortcut_creation"))
        try:
            percentage = int(percentage)
        except:
            flash("Percentage must be numerical.")
            return redirect(url_for("shortcut_creation"))
        if percentage > 100 or percentage < 1:
            flash("Percentage must be within range.")
            return redirect(url_for("shortcut_creation"))

        if video_url:
            if not check_video_url(video_url):
                flash("Video url not valid.")
                return redirect(url_for("shortcut_creation"))
            video_url = video_url.replace("watch?v=", "embed/")

        file = request.files["image"]
        filepath = None
        if file and file.filename != "" and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], SHORTCUTS_FOLDER, filename)
            file.save(filepath)
        if not filepath: filepath = (cur.execute("SELECT image_url FROM courses WHERE id=?", (course,))).fetchone()["image_url"]
        
        print(filepath)
        shortcut_id = (cur.execute("INSERT INTO shortcuts (percentage, course_id, video_url, user_id, image_path, description, is_approved, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (percentage, course, video_url, session["user_id"], filepath, description, 0, datetime.now()))).lastrowid
        for item_id in items:
            cur.execute("INSERT INTO shortcut_items (shortcut_id, item_id) VALUES (?, ?)", (shortcut_id, item_id))
        
        con.commit()

        flash("Success! Please wait for your shortcut to be approved by the moderators.")
        return redirect("/")
    else:
        cups = (cur.execute("SELECT * FROM cups")).fetchall()
        courses = (cur.execute("SELECT * FROM courses")).fetchall()
        items = (cur.execute("SELECT * FROM items")).fetchall()
        return render_template("shortcut-creation.html", cups=cups, courses=courses, items=items)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            flash("Missing username.")
            return redirect(url_for("login"))
        if not password:
            flash("Missing password.")
            return redirect(url_for("login"))
    
        con = sqlite3.connect(DB_LOCATION)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        user_info = (cur.execute("SELECT * FROM users WHERE username=?", (username,))).fetchall()
        if len(user_info) == 0:
            flash("User does not exist.")
            return redirect(url_for("login"))
        user_info = user_info[0]

        if not check_password_hash(user_info["hash"], password):
            flash("Incorrect username and/or password.")
            return redirect(url_for("login"))
        
        user_info = (cur.execute("SELECT * FROM users WHERE username=?", (username,))).fetchall()[0]
        session["user_id"] = user_info["id"]
        if user_info["is_moderator"] == 1:
            session["is_moderator"] = True

        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    session.clear()
    return redirect("/")

@app.route("/permissions", methods=["GET", "POST"])
@moderator_required
def permissions():
    con = sqlite3.connect(DB_LOCATION)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    if request.method == "POST":
        prode_values = ["Promote", "Demote"]
        prode = request.form.get("prode")
        user_pro = request.form.get("user_pro")
        user_de = request.form.get("user_de")
        if not prode or prode not in prode_values:
            flash("Promote/Demote value not provided.")
            return redirect(url_for("permissions"))
        if prode == "Promote":
            user = user_pro
        else:
            user = user_de
        if not user:
            flash("Username not provided.")
            return redirect(url_for("permissions"))

        user_info = (cur.execute("SELECT * FROM users WHERE username=?", (user,))).fetchall()
        if len(user_info) == 0:
            flash("User does not exist.")
            return redirect(url_for("permissions"))
        user_info = user_info[0]
        if user_info["id"] == session["user_id"]:
            flash("You cannot adjust your own permissions.")
            return redirect(url_for("permissions"))
        
        if prode == "Promote":
            cur.execute("UPDATE users SET is_moderator=? WHERE id=?", (1, user_info["id"]))
        else:
            cur.execute("UPDATE users SET is_moderator=? WHERE id=?", (0, user_info["id"]))
        
        con.commit()

        return redirect("/")
    else:
        users = (cur.execute("SELECT * FROM users WHERE id!=?", (session["user_id"],))).fetchall()
        regulars = [user for user in users if user["is_moderator"] == 0]
        moderators = [user for user in users if user["is_moderator"] == 1]
        
        return render_template("permissions.html", regulars=regulars, moderators=moderators)

@app.route("/course-creation", methods=["GET", "POST"])
@moderator_required
def course_creation():
    if request.method == "POST":
        name = request.form.get("course_name")
        length = request.form.get("course_length")
        url = request.form.get("image_url")
        cup = request.form.get("cup")
        ending_course = request.form.get("ending_track")
        ending_course_id = None

        if not name:
            flash("Missing course name.")
            return redirect(url_for("course_creation"))
        if not length:
            flash("Missing course length.")
            return redirect(url_for("course_creation"))
        try:
            length = int(length)
        except:
            flash("Length must be numeric.")
            return redirect(url_for("course_creation"))
        if not url:
            flash("Missing course url.")
            return redirect(url_for("course_creation"))
        if not cup:
            flash("Missing cup.")
            return redirect(url_for("course_creation"))
        
        con = sqlite3.connect(DB_LOCATION)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        if (ending_course):
            ending_course_id = (cur.execute("SELECT id FROM courses WHERE name = ?", [(ending_course)])).fetchall()
            if len(ending_course_id) == 0:
                flash("Ending course does not exist.")
                return redirect(url_for("course_creation"))
            
        existing = (cur.execute("SELECT ending_course_id FROM courses WHERE name = ?", [(name)])).fetchall()
        if len(existing) > 0 and existing[0]["ending_course_id"] == ending_course_id:
            flash("Course already exists.")
            return redirect(url_for("course_creation"))
        
        cup_id = (cur.execute("SELECT id FROM cups WHERE name = ?", [(cup)])).fetchall()
        if len(cup_id) == 0:
            flash("Cup does not exist.")
            return redirect(url_for("course_creation"))
        if (ending_course):
            cur.execute("INSERT INTO courses (name, length, image_url, cup_id, ending_course_id) VALUES (?, ?, ?, ?, ?)", (name, length, url, cup_id[0]["id"], ending_course_id[0]["id"]))
        else:
            cur.execute("INSERT INTO courses (name, length, image_url, cup_id) VALUES (?, ?, ?, ?)", (name, length, url, cup_id[0]["id"]))

        con.commit()

        return redirect("/")
    else:
        con = sqlite3.connect(DB_LOCATION)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cups=(cur.execute("SELECT name FROM cups")).fetchall()
        courses=(cur.execute("SELECT name FROM courses")).fetchall()
        return render_template("course-creation.html", cups=cups, courses=courses)

@app.route("/cup-creation", methods=["GET", "POST"])
@moderator_required
def cup_creation():
    if request.method == "POST":
        name = request.form.get("cup_name")
        if not name:
            flash("Missing cup name.")
            return redirect(url_for("cup_creation"))
        
        con = sqlite3.connect(DB_LOCATION)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        try:
            cur.execute("INSERT INTO cups (name) VALUES (?)", [(name)])
        except:
            flash("Cup already exists.")
            return redirect(url_for("cup_creation"))
        
        con.commit()

        return redirect("/")
    else:
        return render_template("cup-creation.html")

@app.route("/item-creation", methods=["GET", "POST"])
@moderator_required
def item_creation():
    if request.method == "POST":
        name = request.form.get("item_name")
        if not name:
            flash("Missing item name.")
            return redirect(url_for("item_creation"))
        if "file" not in request.files:
            flash("No file part.")
            return redirect(url_for("item_creation"))
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected.")
            return redirect(url_for("item_creation"))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], ITEMS_FOLDER, filename)
            file.save(filepath)
        
        con = sqlite3.connect(DB_LOCATION)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        try:
            cur.execute("INSERT INTO items (name, image_path) VALUES (?, ?)", (name, filepath))
        except:
            flash("Item name and/or filename already exists.")
            return redirect(url_for("item_creation"))
        con.commit()

        return redirect("/")
    else:
        return render_template("item-creation.html")

@app.route("/approve-shortcuts", methods=["GET", "POST"])
@moderator_required  
def approve_shortcuts():
    shortcuts, shortcut_items = get_shortcuts("WHERE is_approved=0")
    return render_template("index.html", shortcuts=shortcuts, shortcut_items=shortcut_items)

def get_shortcuts(where_prompt="", shorten_description=True):
    con = sqlite3.connect(DB_LOCATION)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    shortcuts = (cur.execute("SELECT shortcuts.id, " \
    "image_path, " \
    "description, " \
    "percentage, " \
    "video_url, " \
    "timestamp, " \
    "is_approved, " \
    "courses.name AS course_name, " \
    "users.id AS user_id, " \
    "users.username AS username " \
    "FROM shortcuts JOIN courses ON shortcuts.course_id=courses.id " \
    "JOIN users ON shortcuts.user_id=users.id " + where_prompt)).fetchall()
    
    shortcut_items = (cur.execute("SELECT shortcut_id, " \
    "items.image_path AS item_image_path, " \
    "items.name AS item_name " \
    "FROM shortcut_items JOIN items ON shortcut_items.item_id=items.id " \
    "JOIN shortcuts ON shortcuts.id = shortcut_id " + where_prompt)).fetchall()

    modified_shortcuts = []
    for shortcut in shortcuts:
        shortcut_dict = dict(shortcut)
        shortcut_dict["difference"] = humanize.naturaltime(datetime.now() - datetime.strptime(shortcut_dict["timestamp"], "%Y-%m-%d %H:%M:%S.%f"))
        if shorten_description:
            shortcut_dict["description"] = textwrap.shorten(shortcut_dict["description"], 60, placeholder="...")
        modified_shortcuts.append(shortcut_dict)
    
    return modified_shortcuts, shortcut_items

def check_video_url(video_url):
    checker_url = "https://www.youtube.com/oembed?url="
    full_url = checker_url + video_url

    request = requests.get(full_url)

    return request.status_code == 200

def update_database():
    media = MediaFileUpload(DB_LOCATION, resumable=True)
    service.files().update(fileId=DB_FILE_ID, media_body=media).execute()

if __name__ == "__main__":
    app.run(debug=True)
