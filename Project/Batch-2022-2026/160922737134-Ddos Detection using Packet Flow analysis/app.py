import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from detector.packet_analyzer import analyze_packet_text
import random

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_file, abort
)
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user
)
from werkzeug.utils import secure_filename

from models.db_models import db, User, AnalysisRun
from utils.paths import get_app_base_dir, ensure_runtime_dirs
from utils.security import hash_password, verify_password
from detector.packet_analyzer import analyze_packet_text
from detector.risk import risk_level_from_score
from utils.evidence_ledger import EvidenceLedger
from utils.pdf_report import build_pdf_report
from utils.notifications import alert_simulation


ALLOWED_EXTENSIONS = {".txt", ".log", ".csv"}

def _safe_join_upload(base_dir: Path, filename: str) -> Path:
    """
    Prevent path traversal. Only allow file access inside uploads/ with a safe filename.
    """
    safe = secure_filename(filename)
    p = (base_dir / "uploads" / safe).resolve()
    if (base_dir / "uploads").resolve() not in p.parents:
        raise ValueError("Unsafe path")
    return p


def _generate_synthetic_packetflow_csv():
    """
    Randomly generates LOW, MEDIUM, HIGH, or CRITICAL traffic scenario
    for realistic DDoS detection demonstration.
    """

    from datetime import datetime, timedelta
    import random

    now = datetime.utcnow().replace(microsecond=0)
    victim_ip = "10.0.0.5"

    scenario = random.choice(["low", "medium", "high", "critical"])

    print(f"Generated scenario: {scenario.upper()}")

    lines = []

    # LOW RISK (normal traffic)
    if scenario == "low":

        sources = [f"192.168.1.{i}" for i in range(10, 40)]

        for i in range(random.randint(150, 300)):

            ts = now + timedelta(seconds=i // 10)

            src = random.choice(sources)

            dst = random.choice(["10.0.0.8", "10.0.0.9"])

            proto = random.choice(["TCP", "UDP"])

            length = random.choice([60, 120])

            flags = "ACK" if proto == "TCP" else ""

            lines.append(
                f"{ts.isoformat()},{src},{dst},{proto},{length},{flags}"
            )

    # MEDIUM RISK (moderate suspicious)
    elif scenario == "medium":

        sources = [f"203.0.113.{i}" for i in range(1, 50)]

        for i in range(random.randint(500, 800)):

            ts = now + timedelta(seconds=i // 8)

            src = random.choice(sources)

            dst = victim_ip

            proto = "TCP"

            length = 60

            flags = random.choice(["SYN", "ACK"])

            lines.append(
                f"{ts.isoformat()},{src},{dst},{proto},{length},{flags}"
            )

    # HIGH RISK (strong attack)
    elif scenario == "high":

        sources = [f"198.51.100.{i}" for i in range(1, 100)]

        for i in range(random.randint(1000, 1500)):

            ts = now + timedelta(milliseconds=i * 2)

            src = random.choice(sources)

            dst = victim_ip

            proto = "TCP"

            length = 60

            flags = "SYN"

            lines.append(
                f"{ts.isoformat()},{src},{dst},{proto},{length},{flags}"
            )

    # CRITICAL RISK (burst DDoS)
    else:

        sources = [f"10.10.10.{i}" for i in range(1, 200)]

        burst_start = now + timedelta(seconds=5)

        for i in range(random.randint(2000, 3000)):

            ts = burst_start + timedelta(milliseconds=random.randint(0, 200))

            src = random.choice(sources)

            dst = victim_ip

            proto = "TCP"

            length = 60

            flags = "SYN"

            lines.append(
                f"{ts.isoformat()},{src},{dst},{proto},{length},{flags}"
            )

    random.shuffle(lines)

    header = "timestamp,src_ip,dst_ip,protocol,length,flags"

    return header + "\n" + "\n".join(lines) + "\n"

def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")

    base_dir = get_app_base_dir()
    ensure_runtime_dirs(base_dir)

    db_path = base_dir / "data.db"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path.as_posix()}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["UPLOAD_FOLDER"] = (base_dir / "uploads").as_posix()
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return db.session.get(User, int(user_id))
        except Exception:
            return None

    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print("[DB INIT ERROR]", e)

    ledger = EvidenceLedger(base_dir / "ledger.json")

    @app.get("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            try:
                username = (request.form.get("username") or "").strip()
                password = request.form.get("password") or ""
                confirm = request.form.get("confirm") or ""

                if not username or not password:
                    flash("Username and password are required.", "warning")
                    return render_template("register.html")

                if len(password) < 8:
                    flash("Password must be at least 8 characters.", "warning")
                    return render_template("register.html")

                if password != confirm:
                    flash("Passwords do not match.", "warning")
                    return render_template("register.html")

                existing = User.query.filter_by(username=username).first()
                if existing:
                    flash("Username already exists.", "warning")
                    return render_template("register.html")

                user = User(username=username, password_hash=hash_password(password))
                db.session.add(user)
                db.session.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            except Exception as e:
                print("[REGISTER ERROR]", e)
                db.session.rollback()
                flash("Registration failed due to an internal error.", "danger")

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            try:
                username = (request.form.get("username") or "").strip()
                password = request.form.get("password") or ""

                user = User.query.filter_by(username=username).first()
                if not user or not verify_password(user.password_hash, password):
                    flash("Invalid username or password.", "danger")
                    return render_template("login.html")

                login_user(user)
                flash("Welcome back!", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                print("[LOGIN ERROR]", e)
                flash("Login failed due to an internal error.", "danger")

        return render_template("login.html")

    @app.get("/logout")
    @login_required
    def logout():
        try:
            logout_user()
            flash("Logged out.", "info")
        except Exception as e:
            print("[LOGOUT ERROR]", e)
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        try:
            total_runs = AnalysisRun.query.filter_by(user_id=current_user.id).count()
            recent_runs = (
                AnalysisRun.query.filter_by(user_id=current_user.id)
                .order_by(AnalysisRun.created_at.desc())
                .limit(30)
                .all()
            )

            risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
            for r in recent_runs:
                risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1

            day_counts = {}
            for r in recent_runs:
                day = r.created_at.strftime("%Y-%m-%d")
                day_counts[day] = day_counts.get(day, 0) + 1

            days_sorted = sorted(day_counts.keys())
            day_values = [day_counts[d] for d in days_sorted]

            last_run = (
                AnalysisRun.query.filter_by(user_id=current_user.id)
                .order_by(AnalysisRun.created_at.desc())
                .first()
            )

            summary_cards = {
                "total_runs": total_runs,
                "critical_runs": AnalysisRun.query.filter_by(user_id=current_user.id, risk_level="Critical").count(),
                "high_runs": AnalysisRun.query.filter_by(user_id=current_user.id, risk_level="High").count(),
                "last_risk": last_run.risk_level if last_run else "N/A",
            }

            return render_template(
                "dashboard.html",
                summary_cards=summary_cards,
                risk_counts=risk_counts,
                days_sorted=days_sorted,
                day_values=day_values,
                recent_runs=recent_runs[:10],
            )
        except Exception as e:
            print("[DASHBOARD ERROR]", e)
            flash("Dashboard failed to load, but the app is still running.", "warning")
            return render_template("dashboard.html",
                                   summary_cards={"total_runs": 0, "critical_runs": 0, "high_runs": 0, "last_risk": "N/A"},
                                   risk_counts={"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                                   days_sorted=[],
                                   day_values=[],
                                   recent_runs=[])

    # ✅ NEW: Data Generator (creates a CSV in uploads/)
    @app.get("/data-generator")
    @login_required
    def data_generator():
        try:
            base_dir2 = get_app_base_dir()
            csv_text = _generate_synthetic_packetflow_csv()
            name = f"generated_packetflow_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            p = _safe_join_upload(base_dir2, name)
            p.write_text(csv_text, encoding="utf-8")

            flash(f"Data Generator created: {name}. You can analyze it immediately.", "success")
            return redirect(url_for("analyze", generated=name))
        except Exception as e:
            print("[DATA GENERATOR ERROR]", e)
            flash("Could not generate data due to an internal error.", "danger")
            return redirect(url_for("analyze"))

    # ✅ NEW: Download generated/uploaded file from uploads/
    @app.get("/download/<path:filename>")
    @login_required
    def download_file(filename: str):
        try:
            base_dir2 = get_app_base_dir()
            p = _safe_join_upload(base_dir2, filename)
            if not p.exists():
                abort(404)
            return send_file(p, as_attachment=True, download_name=p.name)
        except Exception as e:
            print("[DOWNLOAD ERROR]", e)
            flash("Could not download the file.", "danger")
            return redirect(url_for("history"))

    @app.route("/analyze", methods=["GET", "POST"])
    @login_required
    def analyze():
        # ✅ Prefill textarea from generated file if provided
        initial_text = ""
        generated = request.args.get("generated")
        if generated:
            try:
                base_dir2 = get_app_base_dir()
                p = _safe_join_upload(base_dir2, generated)
                if p.exists():
                    initial_text = p.read_text(encoding="utf-8", errors="ignore")
                    flash("Loaded generated dataset into the text box. Click Run Analysis.", "info")
                else:
                    flash("Generated file not found.", "warning")
            except Exception as e:
                print("[ANALYZE PREFILL ERROR]", e)
                flash("Could not load generated file.", "warning")

        if request.method == "POST":
            try:
                input_mode = request.form.get("input_mode", "text")
                raw_text = ""
                filename_saved = None

                if input_mode == "file":
                    f = request.files.get("file")
                    if not f or not f.filename:
                        flash("Please choose a file to upload.", "warning")
                        return render_template("analyze.html", initial_text=initial_text, generated=generated)

                    ext = Path(f.filename).suffix.lower()
                    if ext not in ALLOWED_EXTENSIONS:
                        flash("Invalid file type. Use .txt, .log, or .csv", "warning")
                        return render_template("analyze.html", initial_text=initial_text, generated=generated)

                    safe_name = secure_filename(f.filename)
                    upload_path = Path(app.config["UPLOAD_FOLDER"]) / f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{safe_name}"
                    f.save(upload_path)
                    filename_saved = upload_path.name
                    raw_text = upload_path.read_text(encoding="utf-8", errors="ignore")

                else:
                    raw_text = request.form.get("packet_text", "")

                if not raw_text.strip():
                    flash("Please provide packet text or upload a file.", "warning")
                    return render_template("analyze.html", initial_text=initial_text, generated=generated)

                analysis = analyze_packet_text(raw_text)

                score = float(analysis.get("risk_score", 0.0))
                risk_level = risk_level_from_score(score)

                if risk_level in ("High", "Critical"):
                    alert_simulation(risk_level, analysis)

                run = AnalysisRun(
                    user_id=current_user.id,
                    source=filename_saved or (generated if generated else "text-input"),
                    risk_score=score,
                    risk_level=risk_level,
                    result_json=json.dumps(analysis, ensure_ascii=False),
                )
                db.session.add(run)
                db.session.commit()

                try:
                    chain_info = ledger.append_run(run_id=run.id, analysis_obj=analysis)
                    run.evidence_hash = chain_info["hash"]
                    run.prev_hash = chain_info["prev_hash"]
                    run.chain_index = chain_info["index"]
                    db.session.commit()
                except Exception as e:
                    print("[LEDGER ERROR]", e)

                flash("Analysis completed.", "success")
                return redirect(url_for("result", run_id=run.id))

            except Exception as e:
                print("[ANALYZE ERROR]", e)
                db.session.rollback()
                flash("Analysis failed due to an internal error. Try again with simpler input.", "danger")

        return render_template("analyze.html", initial_text=initial_text, generated=generated)

    @app.get("/result/<int:run_id>")
    @login_required
    def result(run_id: int):
        try:
            run = AnalysisRun.query.filter_by(id=run_id, user_id=current_user.id).first()
            if not run:
                flash("Result not found.", "warning")
                return redirect(url_for("history"))

            analysis = {}
            try:
                analysis = json.loads(run.result_json or "{}")
            except Exception:
                analysis = {}

            return render_template("result.html", run=run, analysis=analysis)
        except Exception as e:
            print("[RESULT ERROR]", e)
            flash("Could not load the result page.", "warning")
            return render_template("error.html", message="Result page error.")

    @app.get("/history")
    @login_required
    def history():
        try:
            runs = (
                AnalysisRun.query.filter_by(user_id=current_user.id)
                .order_by(AnalysisRun.created_at.desc())
                .all()
            )
            return render_template("history.html", runs=runs)
        except Exception as e:
            print("[HISTORY ERROR]", e)
            flash("History failed to load.", "warning")
            return render_template("history.html", runs=[])

    @app.get("/report/<int:run_id>")
    @login_required
    def report(run_id: int):
        try:
            run = AnalysisRun.query.filter_by(id=run_id, user_id=current_user.id).first()
            if not run:
                flash("Report target not found.", "warning")
                return redirect(url_for("history"))

            try:
                analysis = json.loads(run.result_json or "{}")
            except Exception:
                analysis = {}

            base_dir2 = get_app_base_dir()
            reports_dir = base_dir2 / "uploads"
            reports_dir.mkdir(parents=True, exist_ok=True)
            pdf_path = reports_dir / f"ddos_report_run_{run.id}.pdf"

            build_pdf_report(pdf_path=pdf_path, run=run, analysis=analysis)

            return send_file(
                pdf_path,
                as_attachment=True,
                download_name=f"ddos_report_run_{run.id}.pdf",
                mimetype="application/pdf",
            )
        except Exception as e:
            print("[REPORT ERROR]", e)
            flash("Could not generate the PDF report.", "danger")
            return redirect(url_for("result", run_id=run_id))

    @app.errorhandler(413)
    def too_large(_e):
        flash("Uploaded file is too large (max 10MB).", "warning")
        return redirect(url_for("analyze"))

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", message="Page not found (404)."), 404

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", message="Internal server error (500)."), 500

    @app.get("/live_capture")
    @login_required
    def live_capture():

        try:

            raw_text = capture_live_packets(100)

            if not raw_text.strip():
                flash("No packets captured.", "warning")
                return redirect(url_for("dashboard"))

            analysis = analyze_packet_text(raw_text)

            score = float(analysis.get("risk_score", 0.0))
            risk_level = risk_level_from_score(score)

            run = AnalysisRun(
                user_id=current_user.id,
                source="live-capture",
                risk_score=score,
                risk_level=risk_level,
                result_json=json.dumps(analysis),
            )

            db.session.add(run)
            db.session.commit()

            flash("Live capture completed.", "success")

            return redirect(url_for("result", run_id=run.id))

        except Exception as e:

            print(e)

            flash("Live capture failed.", "danger")

            return redirect(url_for("dashboard"))

    return app


if __name__ == "__main__":
    import threading
    import webbrowser
    import time

    app = create_app()
    url = "http://127.0.0.1:5000"

    def open_browser():
        # Small delay to ensure server is ready
        time.sleep(1.5)
        try:
            webbrowser.open(url)
        except Exception as e:
            print("[BROWSER OPEN ERROR]", e)

    # Open browser in separate thread (prevents blocking)
    threading.Thread(target=open_browser, daemon=True).start()

    print("\nStarting PacketFlow Guard...")
    print(f"Opening browser at {url}\n")

    app.run(host="127.0.0.1", port=5000, debug=False)