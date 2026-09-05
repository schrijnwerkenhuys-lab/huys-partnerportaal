import os
import shutil
import smtplib
from email.message import EmailMessage
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", str(BASE_DIR / "uploads")))
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

def database_url():
    url = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'huys.db'}")
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
db = SQLAlchemy(app)
ALLOWED_EXTENSIONS = {"pdf","png","jpg","jpeg","webp","doc","docx","xls","xlsx","dwg"}

class Company(db.Model):
    id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(160),nullable=False,unique=True)
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); company_id=db.Column(db.Integer,db.ForeignKey("company.id"),nullable=True); name=db.Column(db.String(120),nullable=False); email=db.Column(db.String(180),unique=True,nullable=False); password_hash=db.Column(db.String(255),nullable=False); role=db.Column(db.String(30),nullable=False,default="partner_user"); company=db.relationship("Company")
class Project(db.Model):
    id=db.Column(db.Integer,primary_key=True); company_id=db.Column(db.Integer,db.ForeignKey("company.id"),nullable=False,index=True); title=db.Column(db.String(180),nullable=False); reference=db.Column(db.String(120)); address=db.Column(db.String(255)); contact_name=db.Column(db.String(160)); phone=db.Column(db.String(80)); desired_date=db.Column(db.String(30)); job_type=db.Column(db.String(100)); priority=db.Column(db.String(30),nullable=False,default="Normaal"); description=db.Column(db.Text); status=db.Column(db.String(60),nullable=False,default="Nieuw"); company=db.relationship("Company"); documents=db.relationship("Document",backref="project",cascade="all, delete-orphan")
class Document(db.Model):
    id=db.Column(db.Integer,primary_key=True); project_id=db.Column(db.Integer,db.ForeignKey("project.id"),nullable=False,index=True); original_name=db.Column(db.String(255),nullable=False); stored_name=db.Column(db.String(255),nullable=False)

def current_user():
    uid=session.get("user_id"); return db.session.get(User,uid) if uid else None
def login_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not current_user(): return redirect(url_for("login"))
        return fn(*args,**kwargs)
    return wrapper
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        u=current_user()
        if not u or u.role!="huys_admin": abort(403)
        return fn(*args,**kwargs)
    return wrapper
def can_access_project(p):
    u=current_user(); return bool(u and (u.role=="huys_admin" or u.company_id==p.company_id))
def project_or_404(pid):
    p=db.session.get(Project,pid)
    if not p or not can_access_project(p): abort(404)
    return p
def allowed(filename): return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

def create_partner(company_name,name,email,password):
    if Company.query.filter_by(name=company_name).first(): return "Dit partnerbedrijf bestaat al."
    if User.query.filter_by(email=email).first(): return "Dit e-mailadres is al in gebruik."
    c=Company(name=company_name); db.session.add(c); db.session.flush()
    db.session.add(User(company_id=c.id,name=name,email=email,password_hash=generate_password_hash(password),role="partner_admin")); db.session.commit()
    return None

def reset_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="huys-password-reset")

def reset_token_for(user):
    return reset_serializer().dumps({"uid":user.id,"hash":user.password_hash})

def user_from_reset_token(token):
    try:
        data=reset_serializer().loads(token,max_age=3600)
    except (BadSignature,SignatureExpired):
        return None
    user=db.session.get(User,data.get("uid"))
    if not user or user.password_hash!=data.get("hash"):
        return None
    return user

def send_reset_email(user):
    host=os.environ.get("SMTP_HOST","").strip(); port=int(os.environ.get("SMTP_PORT","587")); username=os.environ.get("SMTP_USERNAME","").strip(); password=os.environ.get("SMTP_PASSWORD",""); sender=os.environ.get("SMTP_FROM",username).strip(); use_tls=os.environ.get("SMTP_USE_TLS","1")=="1"
    if not host or not sender:
        app.logger.error("SMTP is niet geconfigureerd; wachtwoordresetmail kon niet worden verstuurd.")
        return False
    token=reset_token_for(user)
    base=os.environ.get("PUBLIC_BASE_URL","").rstrip("/")
    path=url_for("reset_password",token=token)
    reset_url=f"{base}{path}" if base else url_for("reset_password",token=token,_external=True)
    msg=EmailMessage(); msg["Subject"]="Wachtwoord opnieuw instellen - HUYS Partnerportaal"; msg["From"]=sender; msg["To"]=user.email
    msg.set_content(f"Beste {user.name},\n\nJe hebt gevraagd om je wachtwoord voor het HUYS Partnerportaal opnieuw in te stellen.\n\nGebruik deze link binnen 1 uur:\n{reset_url}\n\nHeb je dit niet aangevraagd? Dan hoef je niets te doen.\n\nMet vriendelijke groet,\nSchrijnwerken HUYS")
    try:
        with smtplib.SMTP(host,port,timeout=15) as server:
            if use_tls: server.starttls()
            if username and password: server.login(username,password)
            server.send_message(msg)
        return True
    except Exception:
        app.logger.exception("Fout bij versturen wachtwoordresetmail")
        return False

@app.context_processor
def inject_user(): return {"me":current_user()}
@app.route("/health")
def health(): return {"status":"ok"},200
@app.route("/")
def index(): return redirect(url_for("dashboard") if current_user() else url_for("login"))
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); password=request.form.get("password",""); u=User.query.filter_by(email=email).first()
        if u and check_password_hash(u.password_hash,password): session.clear(); session["user_id"]=u.id; return redirect(url_for("dashboard"))
        flash("Ongeldige login.","error")
    return render_template("login.html")
@app.route("/forgot-password",methods=["GET","POST"])
def forgot_password():
    if current_user(): return redirect(url_for("dashboard"))
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); user=User.query.filter_by(email=email).first()
        if user: send_reset_email(user)
        flash("Als dit e-mailadres bij ons bekend is, ontvang je een e-mail met een resetlink.","success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")
@app.route("/reset-password/<token>",methods=["GET","POST"])
def reset_password(token):
    if current_user(): return redirect(url_for("dashboard"))
    user=user_from_reset_token(token)
    if not user:
        flash("Deze resetlink is ongeldig of verlopen. Vraag een nieuwe link aan.","error"); return redirect(url_for("forgot_password"))
    if request.method=="POST":
        password=request.form.get("password",""); confirm=request.form.get("confirm_password","")
        if len(password)<8: flash("Het wachtwoord moet minstens 8 tekens bevatten.","error")
        elif password!=confirm: flash("De wachtwoorden zijn niet gelijk.","error")
        else:
            user.password_hash=generate_password_hash(password); db.session.commit(); flash("Je wachtwoord is gewijzigd. Je kunt nu aanmelden.","success"); return redirect(url_for("login"))
    return render_template("reset_password.html")
@app.route("/register",methods=["GET","POST"])
def register():
    if current_user(): return redirect(url_for("dashboard"))
    if request.method=="POST":
        company_name=request.form.get("company_name","").strip(); name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower(); password=request.form.get("password",""); confirm=request.form.get("confirm_password","")
        if not company_name or not name or not email or len(password)<8:
            flash("Vul alle velden in. Het wachtwoord moet minstens 8 tekens bevatten.","error")
        elif password!=confirm:
            flash("De wachtwoorden zijn niet gelijk.","error")
        else:
            error=create_partner(company_name,name,email,password)
            if error: flash(error,"error")
            else: flash("Account aangemaakt. Je kunt nu aanmelden.","success"); return redirect(url_for("login"))
    return render_template("register.html")
@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))
@app.route("/dashboard")
@login_required
def dashboard():
    u=current_user(); q=Project.query if u.role=="huys_admin" else Project.query.filter_by(company_id=u.company_id); projects=q.order_by(Project.id.desc()).all(); stats={"active":sum(p.status not in ("Afgewerkt","Gefactureerd","Geweigerd") for p in projects),"new":sum(p.status=="Nieuw" for p in projects),"info":sum(p.status=="Wacht op info" for p in projects),"done":sum(p.status=="Afgewerkt" for p in projects)}; return render_template("dashboard.html",projects=projects,stats=stats)
@app.route("/projects/new",methods=["GET","POST"])
@login_required
def new_project():
    u=current_user()
    if u.role=="huys_admin": return redirect(url_for("dashboard"))
    if request.method=="POST":
        title=request.form.get("title","").strip()
        if not title: flash("Projectnaam is verplicht.","error"); return render_template("new_project.html")
        p=Project(company_id=u.company_id,title=title,reference=request.form.get("reference","").strip(),address=request.form.get("address","").strip(),contact_name=request.form.get("contact_name","").strip(),phone=request.form.get("phone","").strip(),desired_date=request.form.get("desired_date","").strip(),job_type=request.form.get("job_type","").strip(),priority=request.form.get("priority","Normaal"),description=request.form.get("description","").strip(),status="Nieuw"); db.session.add(p); db.session.flush()
        for f in request.files.getlist("documents"):
            if not f or not f.filename or not allowed(f.filename): continue
            original=secure_filename(f.filename); folder=UPLOAD_ROOT/str(u.company_id)/str(p.id); folder.mkdir(parents=True,exist_ok=True); stored=f"{p.id}_{len(p.documents)+1}_{original}"; f.save(folder/stored); db.session.add(Document(project_id=p.id,original_name=original,stored_name=stored))
        db.session.commit(); flash("Werf succesvol ingediend en wacht op beoordeling door HUYS.","success"); return redirect(url_for("project_detail",project_id=p.id))
    return render_template("new_project.html")
@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id): return render_template("project_detail.html",project=project_or_404(project_id))
@app.route("/projects/<int:project_id>/status",methods=["POST"])
@admin_required
def change_status(project_id):
    p=db.session.get(Project,project_id)
    if not p: abort(404)
    statuses=["Nieuw","Bekijken","Wacht op info","Goedgekeurd","Geweigerd","Ingepland","In uitvoering","Afgewerkt","Gefactureerd"]; status=request.form.get("status")
    if status not in statuses: abort(400)
    p.status=status; db.session.commit(); flash(f"Werfstatus gewijzigd naar {status}.","success"); return redirect(url_for("project_detail",project_id=p.id))
@app.route("/projects/<int:project_id>/accept",methods=["POST"])
@admin_required
def accept_project(project_id):
    p=db.session.get(Project,project_id)
    if not p: abort(404)
    p.status="Goedgekeurd"; db.session.commit(); flash("Werf geaccepteerd.","success"); return redirect(url_for("project_detail",project_id=p.id))
@app.route("/projects/<int:project_id>/reject",methods=["POST"])
@admin_required
def reject_project(project_id):
    p=db.session.get(Project,project_id)
    if not p: abort(404)
    p.status="Geweigerd"; db.session.commit(); flash("Werf geweigerd.","success"); return redirect(url_for("project_detail",project_id=p.id))
@app.route("/documents/<int:doc_id>")
@login_required
def download_document(doc_id):
    d=db.session.get(Document,doc_id)
    if not d or not can_access_project(d.project): abort(404)
    return send_from_directory(UPLOAD_ROOT/str(d.project.company_id)/str(d.project.id),d.stored_name,as_attachment=True,download_name=d.original_name)
@app.route("/admin/companies",methods=["GET","POST"])
@admin_required
def companies():
    if request.method=="POST":
        company_name=request.form.get("company_name","").strip(); name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        if not company_name or not name or not email or len(password)<8: flash("Vul alle velden correct in. Wachtwoord minimaal 8 tekens.","error"); return redirect(url_for("companies"))
        error=create_partner(company_name,name,email,password)
        if error: flash(error,"error")
        else: flash("Partner en gebruiker succesvol aangemaakt.","success")
        return redirect(url_for("companies"))
    rows=[{"company":c,"users":User.query.filter_by(company_id=c.id).count(),"projects":Project.query.filter_by(company_id=c.id).count()} for c in Company.query.order_by(Company.name).all()]; return render_template("companies.html",rows=rows)
@app.route("/admin/companies/<int:company_id>/delete",methods=["POST"])
@admin_required
def delete_company(company_id):
    c=db.session.get(Company,company_id)
    if not c: abort(404)
    company_name=c.name; projects=Project.query.filter_by(company_id=c.id).all()
    for p in projects: db.session.delete(p)
    User.query.filter_by(company_id=c.id).delete(synchronize_session=False)
    db.session.delete(c); db.session.commit()
    shutil.rmtree(UPLOAD_ROOT/str(company_id),ignore_errors=True)
    flash(f"Partner {company_name} en alle gekoppelde accounts en werven zijn verwijderd.","success"); return redirect(url_for("companies"))
@app.errorhandler(403)
def forbidden(_): return render_template("error.html",code=403,message="Geen toegang."),403
@app.errorhandler(404)
def not_found(_): return render_template("error.html",code=404,message="Niet gevonden of geen toegang."),404

def seed_demo_data():
    if Company.query.count(): return
    a=Company(name="Bouwbedrijf De Smet"); b=Company(name="Construct Groep"); db.session.add_all([a,b]); db.session.flush(); db.session.add_all([User(name="Demo De Smet",email="desmet@demo.be",password_hash=generate_password_hash("demo1234"),role="partner_admin",company_id=a.id),User(name="Demo Construct",email="construct@demo.be",password_hash=generate_password_hash("demo1234"),role="partner_admin",company_id=b.id)]); db.session.commit()
def bootstrap_admin():
    email=os.environ.get("ADMIN_EMAIL","").strip().lower(); password=os.environ.get("ADMIN_PASSWORD",""); name=os.environ.get("ADMIN_NAME","HUYS Admin").strip() or "HUYS Admin"
    if not email or not password or User.query.filter_by(role="huys_admin").first(): return
    db.session.add(User(name=name,email=email,password_hash=generate_password_hash(password),role="huys_admin",company_id=None)); db.session.commit()
with app.app_context():
    db.create_all()
    if os.environ.get("SEED_DEMO_DATA","0")=="1": seed_demo_data()
    bootstrap_admin()
if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")),debug=os.environ.get("FLASK_DEBUG","0")=="1")
