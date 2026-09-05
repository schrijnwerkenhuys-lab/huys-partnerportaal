import os
import shutil
import json
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import inspect, text
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
    id=db.Column(db.Integer,primary_key=True); company_id=db.Column(db.Integer,db.ForeignKey("company.id"),nullable=False,index=True); title=db.Column(db.String(180),nullable=False); reference=db.Column(db.String(120)); address=db.Column(db.String(255)); contact_name=db.Column(db.String(160)); phone=db.Column(db.String(80)); desired_date=db.Column(db.String(30)); start_date=db.Column(db.String(30)); job_type=db.Column(db.String(100)); priority=db.Column(db.String(30),nullable=False,default="Normaal"); description=db.Column(db.Text); status=db.Column(db.String(60),nullable=False,default="Nieuw"); company=db.relationship("Company"); documents=db.relationship("Document",backref="project",cascade="all, delete-orphan"); messages=db.relationship("ProjectMessage",backref="project",cascade="all, delete-orphan",order_by="ProjectMessage.id")
class Document(db.Model):
    id=db.Column(db.Integer,primary_key=True); project_id=db.Column(db.Integer,db.ForeignKey("project.id"),nullable=False,index=True); original_name=db.Column(db.String(255),nullable=False); stored_name=db.Column(db.String(255),nullable=False)
class ProjectMessage(db.Model):
    id=db.Column(db.Integer,primary_key=True); project_id=db.Column(db.Integer,db.ForeignKey("project.id"),nullable=False,index=True); user_id=db.Column(db.Integer,db.ForeignKey("user.id"),nullable=True); author_name=db.Column(db.String(120),nullable=False); author_role=db.Column(db.String(30),nullable=False); message=db.Column(db.Text,nullable=False); created_at=db.Column(db.DateTime,nullable=False,default=datetime.utcnow); user=db.relationship("User")

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

def save_project_documents(project, files):
    saved=0
    folder=UPLOAD_ROOT/str(project.company_id)/str(project.id)
    folder.mkdir(parents=True,exist_ok=True)
    for f in files:
        if not f or not f.filename or not allowed(f.filename): continue
        original=secure_filename(f.filename)
        if not original: continue
        number=Document.query.filter_by(project_id=project.id).count()+saved+1
        stored=f"{project.id}_{number}_{original}"
        f.save(folder/stored)
        db.session.add(Document(project_id=project.id,original_name=original,stored_name=stored))
        saved+=1
    return saved

def update_project_from_form(project):
    title=request.form.get("title","").strip()
    if not title: return False
    project.title=title
    project.reference=request.form.get("reference","").strip()
    project.address=request.form.get("address","").strip()
    project.contact_name=request.form.get("contact_name","").strip()
    project.phone=request.form.get("phone","").strip()
    project.desired_date=request.form.get("desired_date","").strip()
    project.job_type=request.form.get("job_type","").strip()
    project.priority=request.form.get("priority","Normaal")
    project.description=request.form.get("description","").strip()
    return True

def create_partner(company_name,name,email,password):
    if Company.query.filter_by(name=company_name).first(): return "Dit partnerbedrijf bestaat al."
    if User.query.filter_by(email=email).first(): return "Dit e-mailadres is al in gebruik."
    c=Company(name=company_name); db.session.add(c); db.session.flush()
    db.session.add(User(company_id=c.id,name=name,email=email,password_hash=generate_password_hash(password),role="partner_admin")); db.session.commit()
    return None

def send_email(recipients,subject,body):
    recipients=sorted({r.strip().lower() for r in recipients if r and r.strip()})
    api_key=os.environ.get("RESEND_API_KEY","").strip()
    sender=os.environ.get("RESEND_FROM","HUYS Partnerportaal <onboarding@resend.dev>").strip()
    if not recipients or not api_key or not sender:
        app.logger.error("Resend is niet volledig geconfigureerd; e-mail kon niet worden verstuurd.")
        return False
    try:
        for recipient in recipients:
            payload=json.dumps({"from":sender,"to":[recipient],"subject":subject,"text":body}).encode("utf-8")
            req=urllib.request.Request(
                "https://api.resend.com/emails",
                data=payload,
                headers={"Authorization":f"Bearer {api_key}","Content-Type":"application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req,timeout=15) as response:
                if response.status < 200 or response.status >= 300:
                    app.logger.error("Resend gaf status %s voor %s",response.status,recipient)
                    return False
        return True
    except urllib.error.HTTPError as exc:
        detail=exc.read().decode("utf-8",errors="replace")
        app.logger.error("Resend HTTP-fout %s: %s",exc.code,detail)
        return False
    except Exception:
        app.logger.exception("Fout bij versturen e-mail via Resend")
        return False

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
    token=reset_token_for(user)
    base=os.environ.get("PUBLIC_BASE_URL","").rstrip("/")
    path=url_for("reset_password",token=token)
    reset_url=f"{base}{path}" if base else url_for("reset_password",token=token,_external=True)
    body=f"Beste {user.name},\n\nJe hebt gevraagd om je wachtwoord voor het HUYS Partnerportaal opnieuw in te stellen.\n\nGebruik deze link binnen 1 uur:\n{reset_url}\n\nHeb je dit niet aangevraagd? Dan hoef je niets te doen.\n\nMet vriendelijke groet,\nSchrijnwerken HUYS"
    return send_email([user.email],"Wachtwoord opnieuw instellen - HUYS Partnerportaal",body)

def project_recipients(project):
    users=User.query.filter((User.role=="huys_admin") | (User.company_id==project.company_id)).all()
    return [u.email for u in users if u.email]

def send_project_message_email(project,entry):
    base=os.environ.get("PUBLIC_BASE_URL","").rstrip("/")
    path=url_for("project_detail",project_id=project.id)
    project_url=f"{base}{path}" if base else url_for("project_detail",project_id=project.id,_external=True)
    role="HUYS" if entry.author_role=="huys_admin" else project.company.name
    subject=f"Nieuw werfverslag - {project.title}"
    body=f"Er is een nieuw bericht toegevoegd aan de werf.\n\nWerf: {project.title}\nPartner: {project.company.name}\nVan: {entry.author_name} ({role})\n\nBericht / werfverslag:\n{entry.message}\n\nBekijk de werf:\n{project_url}\n\nMet vriendelijke groet,\nSchrijnwerken HUYS"
    return send_email(project_recipients(project),subject,body)

def ensure_schema():
    inspector=inspect(db.engine)
    if "project" in inspector.get_table_names():
        columns={c["name"] for c in inspector.get_columns("project")}
        if "start_date" not in columns:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE project ADD COLUMN start_date VARCHAR(30)"))

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
        save_project_documents(p,request.files.getlist("documents"))
        db.session.commit(); flash("Werf succesvol ingediend en wacht op beoordeling door HUYS.","success"); return redirect(url_for("project_detail",project_id=p.id))
    return render_template("new_project.html")
@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id): return render_template("project_detail.html",project=project_or_404(project_id))
@app.route("/projects/<int:project_id>/edit",methods=["GET","POST"])
@login_required
def edit_project(project_id):
    p=project_or_404(project_id)
    if request.method=="POST":
        if not update_project_from_form(p):
            flash("Project / klant is verplicht.","error"); return render_template("edit_project.html",project=p)
        save_project_documents(p,request.files.getlist("documents"))
        db.session.commit(); flash("Werfgegevens zijn aangepast.","success"); return redirect(url_for("project_detail",project_id=p.id))
    return render_template("edit_project.html",project=p)
@app.route("/projects/<int:project_id>/documents/add",methods=["POST"])
@login_required
def add_project_documents(project_id):
    p=project_or_404(project_id)
    saved=save_project_documents(p,request.files.getlist("documents"))
    if saved:
        db.session.commit(); flash(f"{saved} bijlage(n) toegevoegd.","success")
    else:
        db.session.rollback(); flash("Geen geldige bijlagen geselecteerd.","error")
    return redirect(url_for("project_detail",project_id=p.id))
@app.route("/projects/<int:project_id>/communication",methods=["POST"])
@login_required
def add_project_message(project_id):
    p=project_or_404(project_id); u=current_user(); message=request.form.get("message","").strip()
    if not message:
        flash("Vul een bericht of werfverslag in.","error"); return redirect(url_for("project_detail",project_id=p.id))
    if len(message)>10000:
        flash("Het bericht is te lang. Gebruik maximaal 10.000 tekens.","error"); return redirect(url_for("project_detail",project_id=p.id))
    entry=ProjectMessage(project_id=p.id,user_id=u.id,author_name=u.name,author_role=u.role,message=message)
    db.session.add(entry); db.session.commit()
    mailed=send_project_message_email(p,entry)
    if mailed: flash("Bericht / werfverslag opgeslagen en per e-mail verstuurd.","success")
    else: flash("Bericht / werfverslag opgeslagen, maar de e-mail kon niet worden verstuurd.","error")
    return redirect(url_for("project_detail",project_id=p.id))
@app.route("/projects/<int:project_id>/start-date",methods=["POST"])
@admin_required
def set_start_date(project_id):
    p=db.session.get(Project,project_id)
    if not p: abort(404)
    p.start_date=request.form.get("start_date","").strip()
    db.session.commit(); flash("Effectieve startdatum opgeslagen.","success"); return redirect(url_for("project_detail",project_id=p.id))
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
    ensure_schema()
    if os.environ.get("SEED_DEMO_DATA","0")=="1": seed_demo_data()
    bootstrap_admin()
if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")),debug=os.environ.get("FLASK_DEBUG","0")=="1")
