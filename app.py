"""Employee Task Tracker - run with: python app.py"""
import io, mimetypes, os
import secrets, smtplib, ssl
from datetime import date, datetime, timedelta
from email.mime.text import MIMEText
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g, send_file
from werkzeug.security import check_password_hash, generate_password_hash
import models as db

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.teardown_appcontext(db.close_db)
db.init_db()

# If ADMIN_EMAIL is set and the admin account still has no email (e.g. an account created
# before email login was added), fill it in on startup. This is what lets a locked-out
# admin recover: set ADMIN_EMAIL on Render (or locally) and restart, no database access needed.
_admin_email = os.environ.get("ADMIN_EMAIL")
if _admin_email:
    with app.app_context():
        db.execute("UPDATE users SET email=? WHERE username=? AND (email IS NULL OR email='')",
                  (_admin_email.strip().lower(), os.environ.get("ADMIN_USERNAME", "admin").strip().lower()))

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@taskflow.local")
EMAIL_CONFIGURED = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)
CODE_TTL_MIN, RESEND_COOLDOWN_SEC, MAX_ATTEMPTS = 10, 30, 5

def send_code_email(to_email, name, code):
    """Emails a sign-in code. Returns True if it was sent. If SMTP isn't configured
    (e.g. running locally without setting the SMTP_* variables), returns False so the
    caller can fall back to showing the code on screen instead of emailing it."""
    if not EMAIL_CONFIGURED: return False
    msg = MIMEText(f"Hi {name},\n\nYour TaskFlow sign-in code is: {code}\n\nIt expires in {CODE_TTL_MIN} minutes. "
                    "If you didn't try to sign in, you can ignore this email.")
    msg["Subject"], msg["From"], msg["To"] = "Your TaskFlow sign-in code", SMTP_FROM, to_email
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return True
    except Exception as e:
        app.logger.error(f"Email send failed: {e}")
        return False

def issue_code(uid):
    code = f"{secrets.randbelow(1000000):06d}"
    now = datetime.now()
    db.execute("DELETE FROM login_codes WHERE user_id=?", (uid,))
    db.execute("INSERT INTO login_codes(user_id,code,expires_at,attempts,sent_at) VALUES(?,?,?,0,?)",
              (uid, code, (now + timedelta(minutes=CODE_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S")), returning=False)
    return code

STATUSES = ["Pending", "In Progress", "Completed"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]

def overdue():
    return f"t.status!='Completed' AND t.deadline<'{date.today().isoformat()}'"

def task_sql():
    return f"SELECT t.*, u.name AS assignee, CASE WHEN {overdue()} THEN 1 ELSE 0 END AS overdue, (SELECT COUNT(*) FROM files fl WHERE fl.task_id=t.id) AS file_count FROM tasks t JOIN users u ON u.id=t.assignee_id"

@app.before_request
def load_user():
    uid = session.get("uid")
    g.user = db.query("SELECT * FROM users WHERE id=? AND active=1", (uid,), one=True) if uid else None

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        return f(*a, **k) if g.user else redirect(url_for("login"))
    return w

def manager_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user["role"] != "manager": abort(403)
        return f(*a, **k)
    return w

@app.errorhandler(403)
@app.errorhandler(413)
@app.errorhandler(404)
def error(e):
    return render_template("error.html", e=e), e.code

def employees_list():
    return db.query("SELECT id,name FROM users WHERE role='employee' AND active=1 ORDER BY name")

def get_task(tid):
    t = db.query(task_sql() + " WHERE t.id=?", (tid,), one=True)
    if not t: abort(404)
    if g.user["role"] != "manager" and t["assignee_id"] != g.user["id"]: abort(403)
    return t

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("username", "").strip().lower()
        u = db.query("SELECT * FROM users WHERE (username=? OR email=?) AND active=1", (ident, ident), one=True)
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            if not u["email"]:
                flash("Your account has no email on file. Ask your manager to add one in People before you can sign in.", "error")
                return render_template("login.html")
            code = issue_code(u["id"])
            sent = send_code_email(u["email"], u["name"], code)
            session.clear(); session["pending_uid"] = u["id"]
            flash(f"We emailed a 6-digit code to {u['email']}." if sent else
                  f"Email isn't set up on this server yet, so here is your code: {code}", "" if sent else "warn")
            return redirect(url_for("verify"))
        flash("Invalid username/email or password.", "error")
    return render_template("login.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    uid = session.get("pending_uid")
    if not uid: return redirect(url_for("login"))
    u = db.query("SELECT * FROM users WHERE id=? AND active=1", (uid,), one=True)
    if not u: session.clear(); return redirect(url_for("login"))
    if request.method == "POST":
        if request.form.get("resend"):
            row = db.query("SELECT sent_at FROM login_codes WHERE user_id=?", (uid,), one=True)
            if row and (datetime.now() - datetime.strptime(row["sent_at"], "%Y-%m-%d %H:%M:%S")).total_seconds() < RESEND_COOLDOWN_SEC:
                flash("Please wait a few seconds before requesting another code.", "error")
            else:
                sent = send_code_email(u["email"], u["name"], issue_code(uid))
                flash(f"New code emailed to {u['email']}." if sent else f"Email isn't set up, so here is your new code: {issue_code(uid)}", "" if sent else "warn")
            return redirect(url_for("verify"))
        row = db.query("SELECT * FROM login_codes WHERE user_id=?", (uid,), one=True)
        if not row or datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
            flash("That code expired. Request a new one below.", "error")
        elif row["attempts"] >= MAX_ATTEMPTS:
            flash("Too many wrong attempts. Request a new code below.", "error")
        elif request.form.get("code", "").strip() == row["code"]:
            db.execute("DELETE FROM login_codes WHERE user_id=?", (uid,))
            session.clear(); session["uid"] = uid
            return redirect(url_for("dashboard"))
        else:
            db.execute("UPDATE login_codes SET attempts=attempts+1 WHERE user_id=?", (uid,))
            flash("That code isn't right. Try again.", "error")
    return render_template("verify.html", email=u["email"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    mgr = g.user["role"] == "manager"
    scope, args = ("WHERE 1=1", []) if mgr else ("WHERE t.assignee_id=?", [g.user["id"]])
    everything = db.query(f"{task_sql()} {scope}", args)
    stats = dict(total=len(everything), pending=sum(t["status"] == "Pending" for t in everything),
                 progress=sum(t["status"] == "In Progress" for t in everything),
                 done=sum(t["status"] == "Completed" for t in everything), overdue=sum(t["overdue"] for t in everything),
                 employees=len(employees_list()))
    f = {k: request.args.get(k, "") for k in ("employee", "status", "priority", "date_from", "date_to")}
    sql, a = f"{task_sql()} {scope}", list(args)
    if mgr and f["employee"].isdigit(): sql += " AND t.assignee_id=?"; a.append(f["employee"])
    if f["status"] == "Overdue": sql += f" AND {overdue()}"
    elif f["status"]: sql += " AND t.status=?"; a.append(f["status"])
    if f["priority"]: sql += " AND t.priority=?"; a.append(f["priority"])
    if f["date_from"]: sql += " AND t.deadline>=?"; a.append(f["date_from"])
    if f["date_to"]: sql += " AND t.deadline<=?"; a.append(f["date_to"])
    tasks = db.query(sql + " ORDER BY t.status='Completed', t.deadline", a)
    today = date.today().isoformat()
    ctx = dict(mgr=mgr, stats=stats, tasks=tasks, f=f, today=today, employees=employees_list(),
               statuses=STATUSES + ["Overdue"], priorities=PRIORITIES)
    if mgr:
        ctx["updates"] = db.query("SELECT d.*, u.name FROM daily_updates d JOIN users u ON u.id=d.user_id WHERE d.update_date=? ORDER BY u.name", (today,))
        ctx["missing"] = db.query("SELECT name FROM users WHERE role='employee' AND active=1 AND id NOT IN (SELECT user_id FROM daily_updates WHERE update_date=?)", (today,))
    else:
        ctx["submitted"] = db.query("SELECT 1 FROM daily_updates WHERE user_id=? AND update_date=?", (g.user["id"], today), one=True)
    return render_template("dashboard.html", **ctx)

@app.route("/tasks/new", methods=["GET", "POST"])
@app.route("/tasks/<int:tid>/edit", methods=["GET", "POST"])
@manager_required
def task_form(tid=None):
    task, form, uid = (get_task(tid) if tid else None), None, g.user["id"]
    if request.method == "POST":
        v = {k: request.form.get(k, "").strip() for k in ("title", "description", "assignee_id", "priority", "deadline")}
        who = db.query("SELECT name FROM users WHERE id=? AND role='employee' AND active=1", (v["assignee_id"],), one=True) if v["assignee_id"].isdigit() else None
        if not (v["title"] and who and v["deadline"] and v["priority"] in PRIORITIES):
            flash("Title, assignee, priority and deadline are required.", "error"); form = v
        elif task:
            if int(v["assignee_id"]) != task["assignee_id"]: db.log(tid, uid, "Reassigned", f"{task['assignee']} → {who['name']}")
            if v["priority"] != task["priority"]: db.log(tid, uid, "Priority changed", f"{task['priority']} → {v['priority']}")
            if v["deadline"] != task["deadline"]: db.log(tid, uid, "Deadline changed", f"{task['deadline']} → {v['deadline']}")
            db.execute("UPDATE tasks SET title=?,description=?,assignee_id=?,priority=?,deadline=? WHERE id=?",
                       (v["title"], v["description"], v["assignee_id"], v["priority"], v["deadline"], tid))
            flash("Task saved."); return redirect(url_for("task_detail", tid=tid))
        else:
            new = db.execute("INSERT INTO tasks(title,description,assignee_id,created_by,priority,deadline) VALUES(?,?,?,?,?,?)",
                             (v["title"], v["description"], v["assignee_id"], uid, v["priority"], v["deadline"]))
            db.log(new, uid, "Created", v["title"]); db.log(new, uid, "Assigned", "to " + who["name"])
            flash("Task created."); return redirect(url_for("task_detail", tid=new))
    return render_template("task_form.html", task=task, form=form, employees=employees_list(), priorities=PRIORITIES)

@app.route("/tasks/<int:tid>")
@login_required
def task_detail(tid):
    t = get_task(tid)
    comments = db.query("SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.user_id WHERE task_id=? ORDER BY c.id DESC", (tid,))
    history = db.query("SELECT a.*, u.name FROM activity a LEFT JOIN users u ON u.id=a.user_id WHERE task_id=? ORDER BY a.id DESC", (tid,))
    files = db.query("SELECT f.id, f.user_id, f.filename, f.size, f.stage, f.created_at, u.name AS uploader FROM files f JOIN users u ON u.id=f.user_id WHERE f.task_id=? ORDER BY f.id DESC", (tid,))
    return render_template("task_detail.html", t=t, comments=comments, history=history, statuses=STATUSES, files=files)

@app.post("/tasks/<int:tid>/update")
@login_required
def task_update(tid):
    t, uid = get_task(tid), g.user["id"]
    status = request.form.get("status", t["status"])
    if status not in STATUSES: abort(400)
    try: progress = max(0, min(100, int(request.form.get("progress", t["progress"]))))
    except ValueError: progress = t["progress"]
    if status == "Completed": progress = 100
    elif progress == 100: status = "Completed"
    done_at = (t["completed_at"] or datetime.now().strftime("%Y-%m-%d %H:%M")) if status == "Completed" else None
    if status != t["status"]:
        db.log(tid, uid, "Completed" if status == "Completed" else "Status changed", f"{t['status']} → {status}")
    if progress != t["progress"]: db.log(tid, uid, "Progress updated", f"{t['progress']}% → {progress}%")
    db.execute("UPDATE tasks SET status=?, progress=?, completed_at=? WHERE id=?", (status, progress, done_at, tid))
    body = request.form.get("comment", "").strip()
    if body:
        db.execute("INSERT INTO comments(task_id,user_id,body) VALUES(?,?,?)", (tid, uid, body))
        db.log(tid, uid, "Comment added", body[:80])
    flash("Task updated.")
    return redirect(url_for("task_detail", tid=tid))

@app.post("/tasks/<int:tid>/delete")
@manager_required
def task_delete(tid):
    get_task(tid); db.execute("DELETE FROM tasks WHERE id=?", (tid,))
    flash("Task deleted."); return redirect(url_for("dashboard"))

@app.route("/updates", methods=["GET", "POST"])
@login_required
def updates():
    mgr, today, uid = g.user["role"] == "manager", date.today().isoformat(), g.user["id"]
    if request.method == "POST":
        if mgr: abort(403)
        f = [request.form.get(k, "").strip() for k in ("worked_on", "completed", "in_progress", "blockers")]
        if not f[0]: flash("Describe what you worked on today.", "error")
        else:
            db.execute("""INSERT INTO daily_updates(user_id,update_date,worked_on,completed,in_progress,blockers) VALUES(?,?,?,?,?,?)
                ON CONFLICT(user_id,update_date) DO UPDATE SET worked_on=excluded.worked_on, completed=excluded.completed,
                in_progress=excluded.in_progress, blockers=excluded.blockers""", (uid, today, *f))
            flash("Daily update saved."); return redirect(url_for("updates"))
    if mgr:
        d, emp = request.args.get("date", today), request.args.get("employee", "")
        sql, a = "SELECT d.*, u.name FROM daily_updates d JOIN users u ON u.id=d.user_id WHERE 1=1", []
        if d: sql += " AND d.update_date=?"; a.append(d)
        if emp.isdigit(): sql += " AND d.user_id=?"; a.append(emp)
        missing = db.query("SELECT name FROM users WHERE role='employee' AND active=1 AND id NOT IN (SELECT user_id FROM daily_updates WHERE update_date=?)", (d,)) if d and not emp else []
        return render_template("updates.html", mgr=True, rows=db.query(sql + " ORDER BY d.update_date DESC, u.name", a),
                               missing=missing, d=d, emp=emp, employees=employees_list())
    mine = db.query("SELECT * FROM daily_updates WHERE user_id=? ORDER BY update_date DESC LIMIT 30", (uid,))
    return render_template("updates.html", mgr=False, rows=mine, today=today, cur=next((r for r in mine if r["update_date"] == today), None))

@app.route("/team")
@manager_required
def team():
    rows = db.query(f"""SELECT u.id, u.name, u.department, COUNT(t.id) AS total,
        COALESCE(SUM(CASE WHEN t.status='Completed' THEN 1 ELSE 0 END),0) AS done,
        COALESCE(SUM(CASE WHEN t.status='Pending' THEN 1 ELSE 0 END),0) AS pending,
        COALESCE(SUM(CASE WHEN t.status='In Progress' THEN 1 ELSE 0 END),0) AS active,
        COALESCE(SUM(CASE WHEN {overdue()} THEN 1 ELSE 0 END),0) AS overdue,
        MIN(CASE WHEN t.status!='Completed' THEN t.deadline END) AS next_deadline,
        COALESCE(ROUND(AVG(t.progress)),0) AS progress
        FROM users u LEFT JOIN tasks t ON t.assignee_id=u.id WHERE u.role='employee' AND u.active=1
        GROUP BY u.id, u.name, u.department ORDER BY u.name""")
    return render_template("team.html", rows=rows)

@app.route("/activity")
@manager_required
def activity():
    rows = db.query("""SELECT a.*, u.name, t.title FROM activity a LEFT JOIN users u ON u.id=a.user_id
        LEFT JOIN tasks t ON t.id=a.task_id ORDER BY a.id DESC LIMIT 100""")
    return render_template("activity.html", rows=rows)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = None
    if request.method == "POST":
        v = {k: request.form.get(k, "").strip() for k in ("name", "email", "current_password", "new_password")}
        v["email"] = v["email"].lower()
        dup = db.query("SELECT id FROM users WHERE email=? AND id!=?", (v["email"], g.user["id"]), one=True)
        if not v["name"] or "@" not in v["email"]:
            flash("Name and a valid email are required.", "error"); form = v
        elif dup:
            flash("That email is already used by another account.", "error"); form = v
        elif v["new_password"] and not check_password_hash(g.user["password_hash"], v["current_password"]):
            flash("Your current password is incorrect.", "error"); form = v
        elif v["new_password"] and len(v["new_password"]) < 6:
            flash("New password must be at least 6 characters.", "error"); form = v
        else:
            db.execute("UPDATE users SET name=?, email=? WHERE id=?", (v["name"], v["email"], g.user["id"]))
            if v["new_password"]: db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(v["new_password"]), g.user["id"]))
            flash("Profile updated." + (" Password changed." if v["new_password"] else ""))
            return redirect(url_for("profile"))
    return render_template("profile.html", form=form)

@app.route("/employees")
@manager_required
def staff():
    return render_template("employees.html", people=db.query("SELECT * FROM users ORDER BY active DESC, role, name"))

@app.route("/employees/new", methods=["GET", "POST"])
@app.route("/employees/<int:uid>/edit", methods=["GET", "POST"])
@manager_required
def staff_form(uid=None):
    person = db.query("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None
    if uid and not person: abort(404)
    form = None
    if request.method == "POST":
        v = {k: request.form.get(k, "").strip() for k in ("name", "email", "username", "department", "role", "password")}
        v["username"], v["email"] = v["username"].lower(), v["email"].lower()
        if not v["username"] and "@" in v["email"]: v["username"] = v["email"].split("@")[0]
        if v["role"] not in ("manager", "employee") or (person and person["id"] == g.user["id"]): v["role"] = person["role"] if person else "employee"
        dup = db.query("SELECT id FROM users WHERE (username=? OR email=?) AND id!=?", (v["username"], v["email"] or None, uid or 0), one=True)
        bad_email = ("@" not in v["email"]) if (v["email"] or not person) else False
        if not v["name"] or not v["username"] or bad_email or (not person and not v["password"]) or (v["password"] and len(v["password"]) < 6):
            flash("Name, a valid email and a password of at least 6 characters are required.", "error"); form = v
        elif dup:
            flash("That email or username is already in use.", "error"); form = v
        elif person:
            db.execute("UPDATE users SET name=?,email=?,username=?,department=?,role=? WHERE id=?", (v["name"], v["email"] or None, v["username"], v["department"], v["role"], uid))
            if v["password"]: db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(v["password"]), uid))
            flash("Person saved."); return redirect(url_for("staff"))
        else:
            db.execute("INSERT INTO users(name,username,email,password_hash,role,department) VALUES(?,?,?,?,?,?)",
                       (v["name"], v["username"], v["email"], generate_password_hash(v["password"]), v["role"], v["department"]))
            flash(f"{v['name']} was added and can sign in now."); return redirect(url_for("staff"))
    return render_template("employee_form.html", person=person, form=form)

@app.post("/employees/<int:uid>/toggle")
@manager_required
def staff_toggle(uid):
    if uid == g.user["id"]: abort(403)
    db.execute("UPDATE users SET active = 1 - active WHERE id=?", (uid,))
    flash("Account updated. Their tasks and history are kept."); return redirect(url_for("staff"))

# ---------- file uploads (stored in the database so they survive Render redeploys) ----------
ALLOWED = {"pdf", "png", "jpg", "jpeg", "gif", "webp", "txt", "csv", "md", "json", "log", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "zip"}
IMAGES, TEXTS, MAX_FILE = {"png", "jpg", "jpeg", "gif", "webp"}, {"txt", "csv", "md", "json", "log"}, 10 * 1024 * 1024
STAGES = ["Work in progress", "Completed work"]

def ext(name): return name.rsplit(".", 1)[-1].lower() if "." in name else ""
def kind(name):
    e = ext(name)
    return "image" if e in IMAGES else "pdf" if e == "pdf" else "text" if e in TEXTS else None
app.jinja_env.globals["kind"] = kind

@app.template_filter("filesize")
def filesize(n): return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{max(1, round(n / 1024))} KB"

def get_file(fid):
    f = db.query("SELECT f.id, f.task_id, f.user_id, f.filename, f.size, f.stage, f.created_at, u.name AS uploader FROM files f JOIN users u ON u.id=f.user_id WHERE f.id=?", (fid,), one=True)
    if not f: abort(404)
    return f, get_task(f["task_id"])  # get_task enforces who may see it

@app.post("/tasks/<int:tid>/upload")
@login_required
def file_upload(tid):
    get_task(tid)
    stage = request.form.get("stage") if request.form.get("stage") in STAGES else STAGES[0]
    saved = 0
    for up in request.files.getlist("files"):
        name = os.path.basename((up.filename or "").replace(chr(92), "/")).strip()[:150]
        if not name: continue
        data = up.read()
        if ext(name) not in ALLOWED: flash(f"'{name}' was skipped: that file type isn't allowed.", "error")
        elif len(data) > MAX_FILE: flash(f"'{name}' was skipped: it is larger than 10 MB.", "error")
        elif data:
            db.execute("INSERT INTO files(task_id,user_id,filename,size,stage,data) VALUES(?,?,?,?,?,?)", (tid, g.user["id"], name, len(data), stage, db.blob(data)))
            db.log(tid, g.user["id"], "File uploaded", f"{name} ({stage})"); saved += 1
    if saved: flash(f"{saved} file(s) uploaded.")
    return redirect(url_for("task_detail", tid=tid))

@app.route("/files/<int:fid>")
@login_required
def file_view(fid):
    f, t = get_file(fid)
    k, text = kind(f["filename"]), None
    if k == "text":
        row = db.query("SELECT data FROM files WHERE id=?", (fid,), one=True)
        text = bytes(row["data"])[:100000].decode("utf-8", "replace")
    return render_template("file_view.html", f=f, t=t, kind=k, text=text)

def send(fid, attach):
    f, _ = get_file(fid)
    row = db.query("SELECT data FROM files WHERE id=?", (fid,), one=True)
    k = kind(f["filename"])
    mime = "text/plain; charset=utf-8" if k == "text" else mimetypes.guess_type(f["filename"])[0] or "application/octet-stream"
    r = send_file(io.BytesIO(bytes(row["data"])), mimetype=mime, as_attachment=attach or not k, download_name=f["filename"])
    r.headers["X-Content-Type-Options"] = "nosniff"
    return r

@app.route("/files/<int:fid>/raw")
@login_required
def file_raw(fid): return send(fid, False)

@app.route("/files/<int:fid>/download")
@login_required
def file_download(fid): return send(fid, True)

@app.post("/files/<int:fid>/delete")
@login_required
def file_delete(fid):
    f, t = get_file(fid)
    if g.user["role"] != "manager" and f["user_id"] != g.user["id"]: abort(403)
    db.execute("DELETE FROM files WHERE id=?", (fid,)); db.log(t["id"], g.user["id"], "File deleted", f["filename"])
    flash("File deleted."); return redirect(url_for("task_detail", tid=t["id"]))

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=int(os.environ.get("PORT", 5000)))
