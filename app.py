import os
import re
import json
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort, jsonify,
    send_from_directory,
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from sqlalchemy import inspect, text
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import cloudinary.utils

from models import (
    db, User, Escalation, Comment, SavedReportView, Attachment,
    ROLES, STANDARD_ROLES, ROLE_FOR_RECRUITER_FIELD, ROLE_FOR_SALES_REP_FIELD, ROLE_FOR_COMPLIANCE_FIELD,
    ESCALATION_TYPES, CLINICAL_TYPES, SUBTYPES_BY_TYPE, YES_NO, STATUS_VALUES, OPEN_STATUSES, CLOSED_STATUSES,
    BEST_TIME_SLOTS, TIME_ZONES, REPORT_FIELDS,
)
from email_utils import (
    send_action_needed_email, send_new_escalation_email,
    send_mention_email, send_new_comment_email,
    send_welcome_email, send_password_reset_email,
    send_status_changed_email,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///escalations.db").replace(
    "postgres://", "postgresql://", 1
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads"))
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB per request

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

CLOUDINARY_CONFIGURED = bool(
    os.environ.get("CLOUDINARY_CLOUD_NAME")
    and os.environ.get("CLOUDINARY_API_KEY")
    and os.environ.get("CLOUDINARY_API_SECRET")
)
if CLOUDINARY_CONFIGURED:
    cloudinary.config(
        cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
        api_key=os.environ.get("CLOUDINARY_API_KEY"),
        api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
        secure=True,
    )

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def base_url():
    return os.environ.get("APP_BASE_URL", request.url_root.rstrip("/"))


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def manager_or_admin(user):
    return user.role in ("Admin", "Manager")


def save_uploaded_file(file_storage, confidential=False):
    """Save an uploaded werkzeug FileStorage.

    Returns (original_filename, stored_value, storage_type) or None.
    - If Cloudinary is configured: uploads there so files survive redeploys.
      Confidential files use Cloudinary's "authenticated" delivery type, which
      requires a cryptographically signed URL to access - a bare/guessed link
      will NOT work, so this preserves the confidential-access restriction.
    - If Cloudinary is not configured: falls back to local disk (ephemeral -
      lost on every redeploy/restart, but keeps the app usable without setup).
    """
    if not file_storage or not file_storage.filename:
        return None
    original_name = secure_filename(file_storage.filename)
    if not original_name:
        return None

    if CLOUDINARY_CONFIGURED:
        public_id = f"toa-escalations/{uuid.uuid4().hex}"
        upload_type = "authenticated" if confidential else "upload"
        cloudinary.uploader.upload(
            file_storage, resource_type="raw", public_id=public_id,
            type=upload_type, use_filename=False, unique_filename=False,
        )
        if confidential:
            return original_name, public_id, "cloudinary_authenticated"
        url, _ = cloudinary.utils.cloudinary_url(public_id, resource_type="raw", type="upload", secure=True)
        return original_name, url, "cloudinary_public"

    stored_name = f"{uuid.uuid4().hex}_{original_name}"
    file_storage.save(os.path.join(app.config["UPLOAD_FOLDER"], stored_name))
    return original_name, stored_name, "local"


def serve_stored_file(stored_value, storage_type, filename):
    """Redirect/serve a previously-uploaded file regardless of where it lives."""
    if storage_type == "cloudinary_public":
        return redirect(stored_value)
    if storage_type == "cloudinary_authenticated":
        url, _ = cloudinary.utils.cloudinary_url(
            stored_value, resource_type="raw", type="authenticated", sign_url=True, secure=True
        )
        return redirect(url)
    return send_from_directory(app.config["UPLOAD_FOLDER"], stored_value,
                                as_attachment=True, download_name=filename)


def recruiter_options():
    return User.query.filter_by(role=ROLE_FOR_RECRUITER_FIELD).order_by(User.first_name).all()


def sales_rep_options():
    return User.query.filter_by(role=ROLE_FOR_SALES_REP_FIELD).order_by(User.first_name).all()


def compliance_options():
    return User.query.filter_by(role=ROLE_FOR_COMPLIANCE_FIELD).order_by(User.first_name).all()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter(db.func.lower(User.email) == email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("my_open_escalations"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter(db.func.lower(User.email) == email).first()
        if user:
            user.reset_token = secrets.token_urlsafe(32)
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=2)
            db.session.commit()
            send_password_reset_email(user, base_url(), user.reset_token)
        # Always show the same message, whether or not the email exists,
        # so we don't reveal which emails are registered.
        flash("If that email exists in our system, a password reset link has been sent.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    token_valid = bool(user and user.reset_token_expires and user.reset_token_expires >= datetime.utcnow())

    if not token_valid:
        flash("This link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", token=token)
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        flash("Your password has been set. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def home():
    return redirect(url_for("my_open_escalations"))


# ---------------------------------------------------------------------------
# 1. Create an Escalation
# ---------------------------------------------------------------------------
@app.route("/escalations/new", methods=["GET", "POST"])
@login_required
def new_escalation():
    recruiters = recruiter_options()
    sales_reps = sales_rep_options()
    compliance_specialists = compliance_options()
    all_users = User.query.order_by(User.first_name).all()

    if request.method == "POST":
        f = request.form

        subtype = f.get("subtype") or None
        if f.get("type") not in CLINICAL_TYPES:
            subtype = None

        esc = Escalation(
            type=f.get("type"),
            subtype=subtype,
            candidate=f.get("candidate", "").strip(),
            facility=f.get("facility", "").strip(),
            assignment_url=f.get("assignment_url", "").strip(),
            discussed_with_manager=f.get("discussed_with_manager"),
            clinical_call_required=f.get("clinical_call_required") or None,
            status="Open",
            recruiter_id=f.get("recruiter_id") or None,
            sales_rep_id=f.get("sales_rep_id") or None,
            compliance_specialist_id=f.get("compliance_specialist_id") or None,
            details=f.get("details") or None,
            action_to_id=f.get("action_to_id") or None,
            action_item=f.get("action_item") or None,
            danger_of_cancelling=f.get("danger_of_cancelling") or None,
            escalated_to_client=bool(f.get("escalated_to_client")),
            best_day_to_call=f.get("best_day_to_call") or None,
            best_time_to_call=f.get("best_time_to_call") or None,
            time_zone=f.get("time_zone") or None,
            created_by_id=current_user.id,
        )

        # Required field validation
        required_missing = []
        for label, val in [
            ("Type", esc.type), ("Candidate", esc.candidate),
            ("Facility", esc.facility), ("Assignment URL", esc.assignment_url),
            ("Discussed with Coast Manager", esc.discussed_with_manager),
            ("Recruiter", esc.recruiter_id), ("Sales Rep", esc.sales_rep_id),
            ("Compliance Specialist", esc.compliance_specialist_id),
        ]:
            if not val:
                required_missing.append(label)
        if esc.type in CLINICAL_TYPES and not esc.subtype:
            required_missing.append("Subtype")

        if required_missing:
            flash(f"Please fill out required field(s): {', '.join(required_missing)}", "error")
            return render_template("escalation_form.html", esc=None, form=f,
                                    recruiters=recruiters, sales_reps=sales_reps, compliance_specialists=compliance_specialists,
                                    types=ESCALATION_TYPES, clinical_types=CLINICAL_TYPES, subtypes_by_type=SUBTYPES_BY_TYPE,
                                    yes_no=YES_NO, statuses=STATUS_VALUES,
                                    best_times=BEST_TIME_SLOTS, time_zones=TIME_ZONES, mode="create")

        # VR2: Best Day to Call Traveler requires Best Time + Time Zone
        if esc.best_day_to_call and not (esc.best_time_to_call and esc.time_zone):
            flash("Please select Best Time to Call Traveler and the Time Zone field to save the record.", "error")
            return render_template("escalation_form.html", esc=None, form=f,
                                    recruiters=recruiters, sales_reps=sales_reps, compliance_specialists=compliance_specialists,
                                    types=ESCALATION_TYPES, clinical_types=CLINICAL_TYPES, subtypes_by_type=SUBTYPES_BY_TYPE,
                                    yes_no=YES_NO, statuses=STATUS_VALUES,
                                    best_times=BEST_TIME_SLOTS, time_zones=TIME_ZONES, mode="create")

        # Auto-set Recruiter Manager from the Recruiter's manager on their User record
        recruiter = db.session.get(User, int(esc.recruiter_id)) if esc.recruiter_id else None
        if recruiter and recruiter.manager_id:
            esc.recruiter_manager_id = recruiter.manager_id

        db.session.add(esc)
        db.session.commit()

        # Attachments uploaded at creation time
        for file_storage in request.files.getlist("attachments"):
            saved = save_uploaded_file(file_storage, confidential=False)
            if saved:
                original_name, stored_value, storage_type = saved
                db.session.add(Attachment(
                    escalation_id=esc.id, uploaded_by_id=current_user.id,
                    filename=original_name, stored_name=stored_value, storage_type=storage_type, is_confidential=False,
                ))
        db.session.commit()

        # Email automation #2: notify Recruiter, Sales Rep, Compliance Specialist, Recruiter Manager
        recipients = {esc.recruiter, esc.sales_rep, esc.compliance_specialist, esc.recruiter_manager}
        for u in recipients:
            if u:
                send_new_escalation_email(u, esc, base_url())

        flash(f"Escalation #{esc.id} created.", "success")
        return redirect(url_for("view_escalation", escalation_id=esc.id))

    return render_template("escalation_form.html", esc=None, form={},
                            recruiters=recruiters, sales_reps=sales_reps, compliance_specialists=compliance_specialists,
                            types=ESCALATION_TYPES, clinical_types=CLINICAL_TYPES, subtypes_by_type=SUBTYPES_BY_TYPE,
                            yes_no=YES_NO, statuses=STATUS_VALUES,
                            best_times=BEST_TIME_SLOTS, time_zones=TIME_ZONES, mode="create")


# ---------------------------------------------------------------------------
# 2. My Open Escalations
# ---------------------------------------------------------------------------
@app.route("/escalations/mine")
@login_required
def my_open_escalations():
    uid = current_user.id
    escalations = Escalation.query.filter(
        Escalation.status.in_(OPEN_STATUSES),
        db.or_(
            Escalation.recruiter_id == uid,
            Escalation.sales_rep_id == uid,
            Escalation.compliance_specialist_id == uid,
            Escalation.recruiter_manager_id == uid,
            Escalation.action_to_id == uid,
        ),
    ).order_by(Escalation.created_at.desc()).all()
    return render_template("my_open_escalations.html", escalations=escalations)


# ---------------------------------------------------------------------------
# 3. All Escalations (+ filters)
# ---------------------------------------------------------------------------
@app.route("/escalations")
@login_required
def all_escalations():
    users = User.query.order_by(User.first_name).all()
    query = Escalation.query

    user_filter = request.args.get("user_id", type=int)
    user_role_filter = request.args.get("user_role", default="any")  # recruiter/sales_rep/compliance/any
    status_filter = request.args.get("status", default="")

    if user_filter:
        if user_role_filter == "recruiter":
            query = query.filter(Escalation.recruiter_id == user_filter)
        elif user_role_filter == "sales_rep":
            query = query.filter(Escalation.sales_rep_id == user_filter)
        elif user_role_filter == "compliance":
            query = query.filter(Escalation.compliance_specialist_id == user_filter)
        else:  # any
            query = query.filter(db.or_(
                Escalation.recruiter_id == user_filter,
                Escalation.sales_rep_id == user_filter,
                Escalation.compliance_specialist_id == user_filter,
            ))

    if status_filter:
        query = query.filter(Escalation.status == status_filter)

    escalations = query.order_by(Escalation.created_at.desc()).all()
    return render_template(
        "all_escalations.html", escalations=escalations, users=users, statuses=STATUS_VALUES,
        user_filter=user_filter, user_role_filter=user_role_filter, status_filter=status_filter,
    )


# ---------------------------------------------------------------------------
# Escalation detail / edit / chatter
# ---------------------------------------------------------------------------
def parse_mentions(body, users):
    mentioned = []
    for u in users:
        if f"@{u.full_name}" in body:
            mentioned.append(u)
    return mentioned


@app.route("/escalations/<int:escalation_id>", methods=["GET", "POST"])
@login_required
def view_escalation(escalation_id):
    esc = db.session.get(Escalation, escalation_id) or abort(404)
    recruiters = recruiter_options()
    sales_reps = sales_rep_options()
    compliance_specialists = compliance_options()
    all_users = User.query.order_by(User.first_name).all()
    can_manage = manager_or_admin(current_user)

    if request.method == "POST":
        f = request.form
        old_action_to_id = esc.action_to_id
        old_action_item = esc.action_item
        old_status = esc.status

        new_action_to_id = f.get("action_to_id") or None
        new_action_item = f.get("action_item") or None
        new_best_day = f.get("best_day_to_call") or None
        new_best_time = f.get("best_time_to_call") or None
        new_time_zone = f.get("time_zone") or None

        # Status field: only Manager/Admin may change it at all. Disabled selects
        # aren't submitted by browsers, so a missing/unchanged "status" key from a
        # legitimate page just means "no change". A raw request that tries to sneak
        # a different value in from a non-manager is explicitly rejected below.
        submitted_status = f.get("status")
        if can_manage:
            new_status = submitted_status or old_status
        else:
            new_status = old_status
            if submitted_status and submitted_status != old_status:
                flash("You do not have access to update the Status field.", "error")
                return redirect(url_for("view_escalation", escalation_id=escalation_id))

        # VR1: Action To changed but Action Item not changed -> block
        if str(new_action_to_id) != str(old_action_to_id) and new_action_item == old_action_item:
            flash("Please update the Action Item for the person you are updating the Action To field.", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        # VR2: Best Day to Call filled requires Best Time + Time Zone
        if new_best_day and not (new_best_time and new_time_zone):
            flash("Please select Best Time to Call Traveler and the Time Zone field to save the record.", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        new_type = f.get("type", esc.type)
        new_subtype = f.get("subtype") or None
        if new_type not in CLINICAL_TYPES:
            new_subtype = None
        elif not new_subtype:
            flash("Please select a Subtype for this Clinical escalation.", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        # Apply updates
        esc.type = new_type
        esc.subtype = new_subtype
        esc.candidate = f.get("candidate", esc.candidate)
        esc.facility = f.get("facility", esc.facility)
        esc.assignment_url = f.get("assignment_url", esc.assignment_url)
        esc.discussed_with_manager = f.get("discussed_with_manager", esc.discussed_with_manager)
        esc.clinical_call_required = f.get("clinical_call_required") or None
        esc.status = new_status
        esc.recruiter_id = f.get("recruiter_id") or esc.recruiter_id
        esc.sales_rep_id = f.get("sales_rep_id") or esc.sales_rep_id
        esc.compliance_specialist_id = f.get("compliance_specialist_id") or esc.compliance_specialist_id
        esc.details = f.get("details") or None
        esc.action_to_id = new_action_to_id
        esc.action_item = new_action_item
        esc.danger_of_cancelling = f.get("danger_of_cancelling") or None
        esc.escalated_to_client = bool(f.get("escalated_to_client"))
        esc.best_day_to_call = new_best_day
        esc.best_time_to_call = new_best_time
        esc.time_zone = new_time_zone
        esc.complaint_outcome = f.get("complaint_outcome") or None
        esc.clinical_team_save = bool(f.get("clinical_team_save"))
        esc.facility_resolution = f.get("facility_resolution") or None
        esc.is_traveler_canceled = f.get("is_traveler_canceled") or None

        # Confidential Information - Manager/Admin only, ignore silently for anyone else
        if can_manage and "confidential_notes" in f:
            esc.confidential_notes = f.get("confidential_notes") or None

        db.session.commit()

        # Confidential attachment upload (Manager/Admin only)
        if can_manage:
            for file_storage in request.files.getlist("confidential_attachments"):
                saved = save_uploaded_file(file_storage, confidential=True)
                if saved:
                    original_name, stored_value, storage_type = saved
                    db.session.add(Attachment(
                        escalation_id=esc.id, uploaded_by_id=current_user.id,
                        filename=original_name, stored_name=stored_value, storage_type=storage_type, is_confidential=True,
                    ))
            db.session.commit()

        # Regular (non-confidential) attachment upload - anyone with access to the record
        for file_storage in request.files.getlist("attachments"):
            saved = save_uploaded_file(file_storage, confidential=False)
            if saved:
                original_name, stored_value, storage_type = saved
                db.session.add(Attachment(
                    escalation_id=esc.id, uploaded_by_id=current_user.id,
                    filename=original_name, stored_name=stored_value, storage_type=storage_type, is_confidential=False,
                ))
        db.session.commit()

        # Email automation #1: Action To changed -> notify new Action To user
        if str(new_action_to_id) != str(old_action_to_id) and esc.action_to:
            send_action_needed_email(esc.action_to, esc, base_url())

        # Email automation: Status changed -> notify Recruiter, Sales Rep, Compliance Specialist
        if new_status != old_status:
            for u in {esc.recruiter, esc.sales_rep, esc.compliance_specialist}:
                if u:
                    send_status_changed_email(u, esc, new_status, base_url())

        flash("Escalation updated.", "success")
        return redirect(url_for("view_escalation", escalation_id=escalation_id))

    return render_template(
        "escalation_detail.html", esc=esc,
        recruiters=recruiters, sales_reps=sales_reps, compliance_specialists=compliance_specialists,
        all_users=all_users,
        types=ESCALATION_TYPES, clinical_types=CLINICAL_TYPES, subtypes_by_type=SUBTYPES_BY_TYPE,
        yes_no=YES_NO, statuses=STATUS_VALUES,
        best_times=BEST_TIME_SLOTS, time_zones=TIME_ZONES,
        can_manage=can_manage,
    )


@app.route("/escalations/<int:escalation_id>/comment", methods=["POST"])
@login_required
def add_comment(escalation_id):
    esc = db.session.get(Escalation, escalation_id) or abort(404)
    body = request.form.get("body", "").strip()
    attachment = save_uploaded_file(request.files.get("attachment"), confidential=False)
    if not body and not attachment:
        return redirect(url_for("view_escalation", escalation_id=escalation_id))

    comment = Comment(escalation_id=esc.id, user_id=current_user.id, body=body or "(attachment)")
    if attachment:
        comment.attachment_filename, comment.attachment_stored_name, comment.attachment_storage_type = attachment
    db.session.add(comment)
    db.session.commit()

    users = User.query.all()
    mentioned = parse_mentions(body, users)
    for u in mentioned:
        if u.id != current_user.id:
            send_mention_email(u, esc, current_user, base_url())

    # Notify everyone who has previously commented + the record creator, excluding author & already-mentioned
    prior_commenter_ids = {c.user_id for c in esc.comments}
    notify_ids = prior_commenter_ids | ({esc.created_by_id} if esc.created_by_id else set())
    notify_ids.discard(current_user.id)
    mentioned_ids = {u.id for u in mentioned}
    for uid in notify_ids - mentioned_ids:
        u = db.session.get(User, uid)
        if u:
            send_new_comment_email(u, esc, current_user, base_url())

    return redirect(url_for("view_escalation", escalation_id=escalation_id))


@app.route("/attachments/<int:attachment_id>/download")
@login_required
def download_attachment(attachment_id):
    attachment = db.session.get(Attachment, attachment_id) or abort(404)
    if attachment.is_confidential and not manager_or_admin(current_user):
        abort(403)
    return serve_stored_file(attachment.stored_name, attachment.storage_type or "local", attachment.filename)


@app.route("/comments/<int:comment_id>/attachment")
@login_required
def download_comment_attachment(comment_id):
    comment = db.session.get(Comment, comment_id) or abort(404)
    if not comment.attachment_stored_name:
        abort(404)
    return serve_stored_file(comment.attachment_stored_name, comment.attachment_storage_type or "local", comment.attachment_filename)


# ---------------------------------------------------------------------------
# 4. Reporting
# ---------------------------------------------------------------------------
OPERATORS = ["equals", "not equals", "contains", "is empty", "is not empty"]


def apply_condition(esc, field_key, operator, value):
    actual = getattr(esc, field_key, None)
    if operator == "is empty":
        return actual in (None, "", False)
    if operator == "is not empty":
        return actual not in (None, "", False)
    actual_str = "" if actual is None else str(actual)
    if operator == "equals":
        return actual_str.lower() == str(value).lower()
    if operator == "not equals":
        return actual_str.lower() != str(value).lower()
    if operator == "contains":
        return str(value).lower() in actual_str.lower()
    return True


@app.route("/reporting", methods=["GET"])
@login_required
def reporting():
    all_escalations_list = Escalation.query.order_by(Escalation.created_at.desc()).all()

    selected_fields = request.args.getlist("fields") or [k for _, k in REPORT_FIELDS[:8]]
    logic = request.args.get("logic", "AND")
    type_filter = request.args.get("type_filter", "")
    status_filter = request.args.get("status_filter", "")

    # Dynamic filter rows: filter_field_0, filter_op_0, filter_val_0, ...
    filters = []
    i = 0
    while f"filter_field_{i}" in request.args:
        filters.append({
            "field": request.args.get(f"filter_field_{i}"),
            "operator": request.args.get(f"filter_op_{i}"),
            "value": request.args.get(f"filter_val_{i}", ""),
        })
        i += 1

    results = all_escalations_list
    if type_filter:
        results = [e for e in results if e.type == type_filter]
    if status_filter:
        results = [e for e in results if e.status == status_filter]

    if filters:
        filtered = []
        for e in results:
            outcomes = [apply_condition(e, flt["field"], flt["operator"], flt["value"]) for flt in filters if flt["field"]]
            if not outcomes:
                filtered.append(e)
                continue
            ok = all(outcomes) if logic == "AND" else any(outcomes)
            if ok:
                filtered.append(e)
        results = filtered

    saved_views = SavedReportView.query.order_by(SavedReportView.name).all()

    return render_template(
        "reporting.html",
        escalations=results,
        report_fields=REPORT_FIELDS,
        selected_fields=selected_fields,
        operators=OPERATORS,
        filters=filters,
        logic=logic,
        type_filter=type_filter,
        status_filter=status_filter,
        types=ESCALATION_TYPES,
        statuses=STATUS_VALUES,
        saved_views=saved_views,
        users_by_id={u.id: u.full_name for u in User.query.all()},
    )


@app.route("/reporting/save", methods=["POST"])
@login_required
def save_report_view():
    name = request.form.get("view_name", "").strip()
    if not name:
        flash("Please provide a name to save this report view.", "error")
        return redirect(url_for("reporting"))

    fields = request.form.getlist("fields")
    logic = request.form.get("logic", "AND")
    type_filter = request.form.get("type_filter", "")
    status_filter = request.form.get("status_filter", "")

    filters = []
    i = 0
    while f"filter_field_{i}" in request.form:
        filters.append({
            "field": request.form.get(f"filter_field_{i}"),
            "operator": request.form.get(f"filter_op_{i}"),
            "value": request.form.get(f"filter_val_{i}", ""),
        })
        i += 1

    view = SavedReportView(
        name=name,
        created_by_id=current_user.id,
        fields_json=json.dumps(fields),
        filters_json=json.dumps({"filters": filters, "type_filter": type_filter, "status_filter": status_filter}),
        logic=logic,
    )
    db.session.add(view)
    db.session.commit()
    flash(f"Saved report view '{name}'.", "success")
    return redirect(url_for("reporting"))


@app.route("/reporting/view/<int:view_id>")
@login_required
def load_report_view(view_id):
    view = db.session.get(SavedReportView, view_id) or abort(404)
    fields = json.loads(view.fields_json)
    payload = json.loads(view.filters_json)
    query_parts = [f"fields={f}" for f in fields]
    query_parts.append(f"logic={view.logic}")
    if payload.get("type_filter"):
        query_parts.append(f"type_filter={payload['type_filter']}")
    if payload.get("status_filter"):
        query_parts.append(f"status_filter={payload['status_filter']}")
    for idx, flt in enumerate(payload.get("filters", [])):
        query_parts.append(f"filter_field_{idx}={flt.get('field','')}")
        query_parts.append(f"filter_op_{idx}={flt.get('operator','')}")
        query_parts.append(f"filter_val_{idx}={flt.get('value','')}")
    return redirect(url_for("reporting") + "?" + "&".join(query_parts))


# ---------------------------------------------------------------------------
# 5. Manage Users (Admin only)
# ---------------------------------------------------------------------------
@app.route("/users")
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.first_name).all()
    return render_template("manage_users.html", users=users, roles=ROLES)


@app.route("/users/new", methods=["POST"])
@login_required
@admin_required
def create_user():
    f = request.form
    user = User(
        first_name=f.get("first_name", "").strip(),
        last_name=f.get("last_name", "").strip(),
        email=f.get("email", "").strip().lower(),
        role=f.get("role") or "Recruiter",
        manager_id=f.get("manager_id") or None,
    )
    # Set an unusable random password until the user sets their own via the welcome email
    user.set_password(secrets.token_urlsafe(16))
    user.reset_token = secrets.token_urlsafe(32)
    user.reset_token_expires = datetime.utcnow() + timedelta(days=7)
    db.session.add(user)
    db.session.commit()
    send_welcome_email(user, base_url(), user.reset_token)
    flash(f"User {user.full_name} created. A welcome email has been sent so they can set their password.", "success")
    return redirect(url_for("manage_users"))


@app.route("/users/<int:user_id>/edit", methods=["POST"])
@login_required
@admin_required
def edit_user(user_id):
    user = db.session.get(User, user_id) or abort(404)
    f = request.form
    user.first_name = f.get("first_name", user.first_name)
    user.last_name = f.get("last_name", user.last_name)
    user.email = f.get("email", user.email).strip().lower()
    user.role = f.get("role", user.role)
    manager_id = f.get("manager_id") or None
    user.manager_id = int(manager_id) if manager_id and int(manager_id) != user.id else None
    db.session.commit()
    flash(f"User {user.full_name} updated.", "success")
    return redirect(url_for("manage_users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id) or abort(404)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("manage_users"))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("manage_users"))


# ---------------------------------------------------------------------------
# CLI helper: seed an initial admin so the app is usable on first deploy
# ---------------------------------------------------------------------------
@app.cli.command("seed-admin")
def seed_admin():
    email = os.environ.get("SEED_ADMIN_EMAIL", "eitan.margolis1@gmail.com")
    if User.query.filter_by(email=email).first():
        print("Admin already exists.")
        return
    admin = User(first_name="Eitan", last_name="Margolis", email=email, role="Admin")
    admin.set_password(os.environ.get("SEED_ADMIN_PASSWORD", "ChangeMe123!"))
    db.session.add(admin)
    db.session.commit()
    print(f"Seeded admin {email}")


def _sync_missing_columns():
    """Best-effort auto-migration: add any model columns that exist in the
    Python models but are missing from the live database table, and relax
    NOT NULL constraints on columns the model now marks nullable. Avoids
    needing a full migration tool for additive/loosening schema changes."""
    inspector = inspect(db.engine)
    for model in [User, Escalation, Comment, SavedReportView, Attachment]:
        table_name = model.__tablename__
        if not inspector.has_table(table_name):
            continue
        existing_cols_info = {c["name"]: c for c in inspector.get_columns(table_name)}
        for col in model.__table__.columns:
            if col.name not in existing_cols_info:
                try:
                    col_type = col.type.compile(db.engine.dialect)
                    with db.engine.connect() as conn:
                        conn.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN "{col.name}" {col_type}'))
                        conn.commit()
                    print(f"Auto-migration: added missing column {table_name}.{col.name}")
                except Exception as exc:  # noqa: BLE001
                    print(f"Auto-migration: could not add column {table_name}.{col.name}: {exc}")
            else:
                db_col = existing_cols_info[col.name]
                if col.nullable and not db_col.get("nullable", True):
                    try:
                        with db.engine.connect() as conn:
                            conn.execute(text(f'ALTER TABLE "{table_name}" ALTER COLUMN "{col.name}" DROP NOT NULL'))
                            conn.commit()
                        print(f"Auto-migration: relaxed NOT NULL on {table_name}.{col.name}")
                    except Exception as exc:  # noqa: BLE001
                        print(f"Auto-migration: could not relax NOT NULL on {table_name}.{col.name}: {exc}")


with app.app_context():
    db.create_all()
    _sync_missing_columns()
    _seed_email = os.environ.get("SEED_ADMIN_EMAIL")
    if _seed_email and not User.query.filter_by(email=_seed_email).first():
        _admin = User(first_name="Admin", last_name="User", email=_seed_email, role="Admin")
        _admin.set_password(os.environ.get("SEED_ADMIN_PASSWORD", "ChangeMe123!"))
        db.session.add(_admin)
        db.session.commit()
        print(f"Seeded admin {_seed_email}")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
