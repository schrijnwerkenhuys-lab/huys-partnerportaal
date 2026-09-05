import os
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", str(BASE_DIR / "uploads")))
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'huys.db'}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {"pdf","png","jpg","jpeg","webp","doc","docx","xls","xlsx","dwg"}

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, unique=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(180), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="partner_user")
    company = db.relationship("Company")

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    reference = db.Column(db.String(120), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    contact_name = db.Column(db.String(160), nullable=True)
    phone = db.Column(db.String(80), nullable=True)
    desired_date = db.Column(db.String(30), nullable=True)
    job_type = db.Column(db.String(100), nullable=True)
    priority = db.Column(db.String(30), nullable=False, default="Normaal")
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(60), nullable=False, default="Nieuw")
    company = db.relationship("Company")
    documents = db.relationship("Document", backref="project", cascade="all, delete-orphan")

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)

def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user(): return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user.role != "huys_admin": abort(403)
        return fn(*args, **kwargs)
    return wrapper

def can_access_project(project):
    user = current_user()
    if not user: return False
    if user.role == "huys_admin": return True
    return user.company_id == project.company_id

def project_or_404(project_id):
    project = db.session.get(Project, project_id)
    if not project or not can_access_project(project): abort(404)
    return project

def allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.context_processor
def inject_user(): return {"me": current_user()}

@app.route("/health")
def health(): return {"status":"ok"}, 200

@app.route("/")
def index(): return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower(); password = request.form.get("password","")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear(); session["user_id"] = user.id; return redirect(url_for("dashboard"))
        flash("Ongeldige login.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user=current_user(); q=Project.query if user.role=="huys_admin" else Project.query.filter_by(company_id=user.company_id)
    projects=q.order_by(Project.id.desc()).all()
    stats={"active":sum(1 for p in projects if p.status not in ("Afgewerkt","Gefactureerd")),"new":sum(1 for p in projects if p.status=="Nieuw"),"info":sum(1 for p in projects if p.status=="Wacht op info"),"done":sum(1 for p in projects if p.status=="Afgewerkt")}
    return render_template("dashboard.html",projects=projects,stats=stats)

@app.route("/projects/new",methods=["GET","POST"])
@login_required
def new_project():
    user=current_user()
    if user.role=="huys_admin": return redirect(url_for("dashboard"))
    if request.method=="POST":
        title=request.form.get("title","").strip()
        if not title: flash("Projectnaam is verplicht.","error"); return render_template("new_project.html")
        p=Project(company_id=user.company_id,title=title,reference=request.form.get("reference","").strip(),address=request.form.get("address","").strip(),contact_name=request.form.get("contact_name","").strip(),phone=request.form.get("phone","").strip(),desired_date=request.form.get("desired_date","").strip(),job_type=request.form.get("job_type","").strip(),priority=request.form.get("priority","Normaal"),description=request.form.get("description","").strip(),status="Nieuw")
        db.session.add(p); db.session.flush()
        for f in request.files.getlist("documents"):
            if not f or not f.filename: continue
            if not allowed(f.filename): continue
            original=secure_filename(f.filename); company_dir=UPLOAD_ROOT/str(user.company_id)/str(p.id); company_dir.mkdir(parents=True,exist_ok=True); stored=f"{p.id}_{len(p.documents)+1}_{original}"; f.save(company_dir/stored); db.session.add(Document(project_id=p.id,original_name=original,stored_name=stored))
        db.session.commit(); flash("Werf succesvol ingediend.","success"); return redirect(url_for("project_detail",project_id=p.id))
    return render_template("new_project.html")

@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id): return render_template("project_detail.html",project=project_or_404(project_id))

@app.route("/projects/<int:project_id>/status",methods=["POST"])
@admin_required
def change_status(project_id):
    p=db.session.get(Project,project_id)
    if not p: abort(404)
    statuses=["Nieuw","Bekijken","Wacht op info","Goedgekeurd","Ingepland","In uitvoering","Afgewerkt","Gefactureerd"]
    status=request.form.get("status")
    if status not in statuses: abort(400)
    p.status=status; db.session.commit(); return redirect(url_for("project_detail",project_id=p.id))

@app.route("/documents/<int:doc_id>")
@login_required
def download_document(doc_id):
    doc=db.session.get(Document,doc_id)
    if not doc or not can_access_project(doc.project): abort(404)
    folder=UPLOAD_ROOT/str(doc.project.company_id)/str(doc.project.id)
    return send_from_directory(folder,doc.stored_name,as_attachment=True,download_name=doc.original_name)

@app.route("/admin/companies")
@admin_required
def companies():
    rows=[]
    for c in Company.query.order_by(Company.name).all(): rows.append({"company":c,"users":User.query.filter_by(company_id=c.id).count(),"projects":Project.query.filter_by(company_id=c.id).count()})
    return render_template("companies.html",rows=rows)

@app.errorhandler(403)
def forbidden(_): return render_template("error.html",code=403,message="Geen toegang."),403
@app.errorhandler(404)
def not_found(_): return render_template("error.html",code=404,message="Niet gevonden of geen toegang."),404

def seed_demo_data():
    if Company.query.count(): return
    a=Company(name="Bouwbedrijf De Smet"); b=Company(name="Construct Groep"); db.session.add_all([a,b]); db.session.flush()
    db.session.add_all([User(name="Demo De Smet",email="desmet@demo.be",password_hash=generate_password_hash("demo1234"),role="partner_admin",company_id=a.id),User(name="Demo Construct",email="construct@demo.be",password_hash=generate_password_hash("demo1234"),role="partner_admin",company_id=b.id)])
    db.session.commit()

def bootstrap_admin():
    email=os.environ.get("ADMIN_EMAIL","").strip().lower(); password=os.environ.get("ADMIN_PASSWORD",""); name=os.environ.get("ADMIN_NAME","HUYS Admin").strip() or "HUYS Admin"
    if not email or not password or User.query.filter_by(role="huys_admin").first(): return
    db.session.add(User(name=name,email=email,password_hash=generate_password_hash(password),role="huys_admin",company_id=None)); db.session.commit()

with app.app_context():
    db.create_all()
    if os.environ.get("SEED_DEMO_DATA","0")=="1": seed_demo_data()
    bootstrap_admin()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")),debug=os.environ.get("FLASK_DEBUG","0")=="1")
