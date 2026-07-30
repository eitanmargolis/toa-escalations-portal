import os
import re
import json
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort, jsonify,
    send_from_directory, session,
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from sqlalchemy import inspect, text
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import cloudinary.utils
import bleach

from models import (
    db, User, Escalation, Comment, SavedReportView, Attachment, Mention, MigrationFlag,
    ROLES, STANDARD_ROLES, ROLE_FOR_RECRUITER_FIELD, ROLE_FOR_SALES_REP_FIELD, ROLE_FOR_COMPLIANCE_FIELD,
    ROLE_FOR_PAYROLL_SPECIALIST_FIELD, ROLE_FOR_AC_FIELD, RETIRED_ROLE_COMPLIANCE_SPECIALIST,
    ESCALATION_TYPES, ALL_ESCALATION_TYPES_FOR_DISPLAY, CLINICAL_TYPES, SUBTYPES_BY_TYPE, YES_NO,
    STATUS_VALUES, OPEN_STATUSES, CLOSED_STATUSES, STATUS_VALUES_BY_TYPE,
    REQUIRED_SUBTYPE_TYPES, DISCUSSED_WITH_MANAGER_NOT_REQUIRED_TYPES,
    TYPE_COMPLIANCE, TYPE_PAYROLL, TYPE_CONTRACT, TYPE_PRESTART,
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
    # "Director" carries the old manager-tier permission set (renamed from
    # "Manager" in item 11). The NEW scoped "Manager" role added in this
    # batch is standard-tier and intentionally excluded here.
    return user.role in ("Admin", "Director")


def manager_or_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not manager_or_admin(current_user):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


# Well-known service accounts auto-assigned to specific escalation types.
PAYROLL_TEAM_EMAIL = "payroll@coastmedicalservice.com"
CLINICAL_LIAISON_EMAIL = "clinical@coastmedicalservice.com"

# Tags/attrs allowed in rich-text fields (Details/What Happened + Discussion
# comments) - anything else (including <script>) is stripped on save.
RICH_TEXT_ALLOWED_TAGS = ["p", "br", "ul", "ol", "li", "b", "strong", "i", "em", "u", "div", "span"]
RICH_TEXT_ALLOWED_ATTRS = {}


def sanitize_html(raw_html):
    """Strip dangerous tags/attributes from user-submitted rich text (contenteditable HTML)."""
    if not raw_html:
        return raw_html
    cleaned = bleach.clean(
        raw_html, tags=RICH_TEXT_ALLOWED_TAGS, attributes=RICH_TEXT_ALLOWED_ATTRS, strip=True,
    )
    return cleaned.strip() or None


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


def payroll_specialist_options():
    return User.query.filter_by(role=ROLE_FOR_PAYROLL_SPECIALIST_FIELD).order_by(User.first_name).all()


def ac_options():
    return User.query.filter_by(role=ROLE_FOR_AC_FIELD).order_by(User.first_name).all()


def clinical_liaison_options():
    # Clinical Liaison is filled by leadership - eligible list includes
    # Director (the renamed manager-tier role) and Admin.
    return User.query.filter(User.role.in_(["Director", "Admin"])).order_by(User.first_name).all()


def get_payroll_team_user():
    return User.query.filter(db.func.lower(User.email) == PAYROLL_TEAM_EMAIL).first()


def get_clinical_liaison_user():
    return User.query.filter(db.func.lower(User.email) == CLINICAL_LIAISON_EMAIL).first()


def derive_manager_id(user_id):
    """Reusable helper (items 2d/6b): look up whatever User is set as the
    `manager` of the given user id. Returns None (never crashes) if the user
    doesn't exist or has no manager set. NOT hardcoded to any specific person -
    always follows the live manager_id relationship."""
    if not user_id:
        return None
    u = db.session.get(User, int(user_id))
    return u.manager_id if u else None


def derive_ac_id(submitted_ac_id, sales_rep_id):
    """AC auto-derivation (item 10c): use an explicitly submitted AC value if
    present, otherwise re-derive from the selected Sales Rep's assigned AC -
    mirroring the Recruiter Manager auto-set-from-Recruiter's-manager pattern."""
    if submitted_ac_id:
        return int(submitted_ac_id)
    if not sales_rep_id:
        return None
    u = db.session.get(User, int(sales_rep_id))
    return u.assigned_ac_id if u else None


def payroll_specialist_applicable(esc_type, esc_subtype):
    """Item 7c: Payroll Specialist section (dropdown + free-text 'Assigned' box,
    auto-assign, and email recipients) applies to Payroll & Timekeeping OR to
    Contract escalations whose Subtype is specifically 'Pay Changes'."""
    return esc_type == TYPE_PAYROLL or (esc_type == TYPE_CONTRACT and esc_subtype == "Pay Changes")


def compliance_specialist_hidden_for_type(esc_type):
    """Compliance Specialist (the top-level field) is hidden entirely for
    Clinical types (pre-existing behavior) and, as of item 4e, for
    Payroll & Timekeeping too."""
    return esc_type in CLINICAL_TYPES or esc_type == TYPE_PAYROLL


def subtype_required_for_type(esc_type):
    return esc_type in CLINICAL_TYPES or esc_type in REQUIRED_SUBTYPE_TYPES


def discussed_with_manager_required_for_type(esc_type):
    return esc_type not in DISCUSSED_WITH_MANAGER_NOT_REQUIRED_TYPES


def status_options_for_type(esc_type, current_status=None):
    """Per-type restricted status picklist (items 2f/4d), with the record's
    current stored value always included so legacy/out-of-range values still
    display correctly even if they're no longer selectable as a NEW choice."""
    allowed = STATUS_VALUES_BY_TYPE.get(esc_type, STATUS_VALUES)
    if current_status and current_status not in allowed:
        return allowed + [current_status]
    return allowed


def validate_status_for_type(esc_type, old_status, new_status):
    """Server-side guard for items 2f/4d: a NEW status selection must come from
    the type's restricted list, but a value that's unchanged from what's
    already stored is always allowed through (so legacy records don't break)."""
    if new_status == old_status:
        return True
    allowed = STATUS_VALUES_BY_TYPE.get(esc_type, STATUS_VALUES)
    return new_status in allowed


def visible_user_ids_for(user):
    """Item 11c: users with the NEW scoped 'Manager' role get expanded
    visibility in My Open/My Closed Escalations - their own tagged records,
    PLUS records where a direct report (a user whose manager_id points at
    them) is tagged. Every other role keeps the existing self-only behavior."""
    if user.role == "Manager":
        reports = User.query.filter_by(manager_id=user.id).all()
        return {user.id} | {u.id for u in reports}
    return {user.id}


def status_css_class(status):
    mapping = {
        "Open": "status-green",
        "Clinical Acknowledged": "status-blue",
        "In Process": "status-yellow",
        "Clinical Call Complete": "status-blue",
        "Needs Follow Up": "status-yellow",
        "Closed - Resolved": "status-red",
        "Closed - Canceled": "status-red",
        "Investigating": "status-yellow",
        "Information Needed": "status-yellow",
    }
    return mapping.get(status, "status-green")


app.jinja_env.filters["status_css_class"] = status_css_class


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
    session.pop("impersonator_id", None)
    logout_user()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Admin impersonation ("Log in as user") - lets an Admin view the portal
# exactly as another user sees it, to verify their access/permissions.
# ---------------------------------------------------------------------------
@app.route("/users/<int:user_id>/impersonate", methods=["POST"])
@login_required
@admin_required
def impersonate_user(user_id):
    if session.get("impersonator_id"):
        flash("You're already viewing as another user. Return to your Admin account first.", "error")
        return redirect(url_for("manage_users"))

    target = db.session.get(User, user_id) or abort(404)
    if target.id == current_user.id:
        flash("You're already logged in as yourself.", "error")
        return redirect(url_for("manage_users"))

    session["impersonator_id"] = current_user.id
    login_user(target)
    flash(f"You are now viewing the portal as {target.full_name}.", "success")
    return redirect(url_for("my_open_escalations"))


@app.route("/users/stop-impersonating", methods=["POST"])
@login_required
def stop_impersonating():
    impersonator_id = session.pop("impersonator_id", None)
    if not impersonator_id:
        flash("You're not currently viewing as another user.", "error")
        return redirect(url_for("my_open_escalations"))

    admin_user = db.session.get(User, impersonator_id)
    if not admin_user or not admin_user.is_admin():
        # Safety net: if the original admin account is gone/no longer an
        # admin, don't strand the session in an odd state - just log out.
        logout_user()
        flash("Returned to login.", "success")
        return redirect(url_for("login"))

    login_user(admin_user)
    flash("You're back in your own Admin account.", "success")
    return redirect(url_for("manage_users"))


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
    payroll_specialists = payroll_specialist_options()
    clinical_liaisons = clinical_liaison_options()
    acs = ac_options()
    all_users = User.query.order_by(User.first_name).all()
    sales_rep_ac_map = {u.id: u.assigned_ac_id for u in sales_reps}

    def render_form(f):
        return render_template("escalation_form.html", esc=None, form=f,
                                recruiters=recruiters, sales_reps=sales_reps, compliance_specialists=compliance_specialists,
                                payroll_specialists=payroll_specialists, clinical_liaisons=clinical_liaisons,
                                acs=acs, sales_rep_ac_map=sales_rep_ac_map,
                                all_users=all_users,
                                types=ESCALATION_TYPES, clinical_types=CLINICAL_TYPES, subtypes_by_type=SUBTYPES_BY_TYPE,
                                yes_no=YES_NO, statuses=STATUS_VALUES,
                                best_times=BEST_TIME_SLOTS, time_zones=TIME_ZONES, mode="create")

    if request.method == "POST":
        f = request.form
        esc_type = f.get("type")

        subtype = f.get("subtype") or None
        if not subtype_required_for_type(esc_type):
            subtype = None

        # Compliance Specialist is removed from the page layout entirely for
        # Clinical types and (as of item 4e) Payroll & Timekeeping, so never
        # persist a value for those types even if one was somehow submitted.
        compliance_specialist_id = f.get("compliance_specialist_id") or None
        if compliance_specialist_hidden_for_type(esc_type):
            compliance_specialist_id = None

        payroll_applicable = payroll_specialist_applicable(esc_type, subtype)

        # Fields hidden entirely for Compliance & Credentialing (item 2c)
        if esc_type == TYPE_COMPLIANCE:
            clinical_call_required = None
            danger_of_cancelling = None
            escalated_to_client = False
            best_day_to_call = None
            best_time_to_call = None
            time_zone = None
        else:
            clinical_call_required = f.get("clinical_call_required") or None
            danger_of_cancelling = f.get("danger_of_cancelling") or None
            escalated_to_client = bool(f.get("escalated_to_client"))
            best_day_to_call = f.get("best_day_to_call") or None
            best_time_to_call = f.get("best_time_to_call") or None
            time_zone = f.get("time_zone") or None

        # Fields hidden entirely for Payroll & Timekeeping (item 4e) -
        # Discussed with Coast Manager, Clinical Call Required, Best Day/Time/Zone.
        discussed_with_manager = f.get("discussed_with_manager") or None
        if esc_type == TYPE_PAYROLL:
            discussed_with_manager = None
            clinical_call_required = None
            best_day_to_call = None
            best_time_to_call = None
            time_zone = None

        # DNR fields - Clinical types only (item 1)
        if esc_type in CLINICAL_TYPES:
            dnr_facility = bool(f.get("dnr_facility"))
            dnr_facility_notes = (f.get("dnr_facility_notes") or None) if dnr_facility else None
            dnr_msp = bool(f.get("dnr_msp"))
            dnr_msp_notes = (f.get("dnr_msp_notes") or None) if dnr_msp else None
            dnr_hospital_system = bool(f.get("dnr_hospital_system"))
            dnr_hospital_system_notes = (f.get("dnr_hospital_system_notes") or None) if dnr_hospital_system else None
        else:
            dnr_facility = dnr_msp = dnr_hospital_system = False
            dnr_facility_notes = dnr_msp_notes = dnr_hospital_system_notes = None

        # Compliance & Credentialing detail fields (item 2e)
        if esc_type == TYPE_COMPLIANCE:
            coast_deadline = f.get("coast_deadline") or None
            facility_deadline = f.get("facility_deadline") or None
            pushed_start = bool(f.get("pushed_start"))
            pushed_start_notes = f.get("pushed_start_notes") or None
        else:
            coast_deadline = facility_deadline = pushed_start_notes = None
            pushed_start = False

        # Payroll & Timekeeping detail fields (item 4c)
        if esc_type == TYPE_PAYROLL:
            we_date = f.get("we_date") or None
            date_to_be_paid = f.get("date_to_be_paid") or None
        else:
            we_date = date_to_be_paid = None

        # Payroll Specialist "Assigned" free-text (item 4b/7c)
        payroll_specialist_assigned = f.get("payroll_specialist_assigned") or None if payroll_applicable else None

        # Pre-Start fields (item 6b)
        if esc_type == TYPE_PRESTART:
            prestart_compliance_specialist_id = f.get("prestart_compliance_specialist_id") or None
        else:
            prestart_compliance_specialist_id = None

        sales_rep_id = f.get("sales_rep_id") or None
        ac_id = derive_ac_id(f.get("ac_id"), sales_rep_id)

        esc = Escalation(
            type=esc_type,
            subtype=subtype,
            candidate=f.get("candidate", "").strip(),
            facility=f.get("facility", "").strip(),
            assignment_url=f.get("assignment_url", "").strip(),
            discussed_with_manager=discussed_with_manager,
            clinical_call_required=clinical_call_required,
            status="Open",
            recruiter_id=f.get("recruiter_id") or None,
            sales_rep_id=sales_rep_id,
            ac_id=ac_id,
            compliance_specialist_id=compliance_specialist_id,
            payroll_specialist_id=f.get("payroll_specialist_id") or None if payroll_applicable else None,
            payroll_specialist_assigned=payroll_specialist_assigned,
            clinical_liaison_id=f.get("clinical_liaison_id") or None,
            prestart_compliance_specialist_id=prestart_compliance_specialist_id,
            details=sanitize_html(f.get("details")),
            action_to_id=f.get("action_to_id") or None,
            action_item=f.get("action_item") or None,
            danger_of_cancelling=danger_of_cancelling,
            escalated_to_client=escalated_to_client,
            best_day_to_call=best_day_to_call,
            best_time_to_call=best_time_to_call,
            time_zone=time_zone,
            coast_deadline=coast_deadline,
            facility_deadline=facility_deadline,
            pushed_start=pushed_start,
            pushed_start_notes=pushed_start_notes,
            we_date=we_date,
            date_to_be_paid=date_to_be_paid,
            dnr_facility=dnr_facility,
            dnr_facility_notes=dnr_facility_notes,
            dnr_msp=dnr_msp,
            dnr_msp_notes=dnr_msp_notes,
            dnr_hospital_system=dnr_hospital_system,
            dnr_hospital_system_notes=dnr_hospital_system_notes,
            created_by_id=current_user.id,
        )

        # Required field validation
        required_missing = []
        for label, val in [
            ("Type", esc.type), ("Candidate", esc.candidate),
            ("Facility", esc.facility), ("Assignment URL", esc.assignment_url),
            ("Recruiter", esc.recruiter_id), ("Sales Rep", esc.sales_rep_id),
            ("Details/What Happened?", esc.details),
        ]:
            if not val:
                required_missing.append(label)
        if discussed_with_manager_required_for_type(esc.type) and not esc.discussed_with_manager:
            required_missing.append("Discussed with Coast Manager")
        # Compliance Specialist is not required for Clinical types or Payroll & Timekeeping.
        if not compliance_specialist_hidden_for_type(esc.type) and not esc.compliance_specialist_id:
            required_missing.append("Compliance Specialist")
        if subtype_required_for_type(esc.type) and not esc.subtype:
            required_missing.append("Subtype")
        if esc.type == TYPE_COMPLIANCE:
            if not esc.coast_deadline:
                required_missing.append("Coast Deadline")
            if not esc.facility_deadline:
                required_missing.append("Facility Deadline")
        if esc.type == TYPE_PAYROLL and not esc.we_date:
            required_missing.append("WE Date")
        if esc.dnr_facility and not esc.dnr_facility_notes:
            required_missing.append("DNR Facility Notes")
        if esc.dnr_msp and not esc.dnr_msp_notes:
            required_missing.append("DNR MSP Notes")
        if esc.dnr_hospital_system and not esc.dnr_hospital_system_notes:
            required_missing.append("DNR Hospital System Notes")

        if required_missing:
            flash(f"Please fill out required field(s): {', '.join(required_missing)}", "error")
            return render_form(f)

        # VR2: Best Day to Call Traveler requires Best Time + Time Zone
        if esc.best_day_to_call and not (esc.best_time_to_call and esc.time_zone):
            flash("Please select Best Time to Call Traveler and the Time Zone field to save the record.", "error")
            return render_form(f)

        # Auto-set Recruiter Manager from the Recruiter's manager on their User record
        recruiter = db.session.get(User, int(esc.recruiter_id)) if esc.recruiter_id else None
        if recruiter and recruiter.manager_id:
            esc.recruiter_manager_id = recruiter.manager_id

        # Auto-set Payroll Specialist -> "Payroll Team" user (Payroll & Timekeeping,
        # or Contract escalations whose Subtype is "Pay Changes" - item 7c)
        if payroll_applicable and not esc.payroll_specialist_id:
            payroll_team = get_payroll_team_user()
            if payroll_team:
                esc.payroll_specialist_id = payroll_team.id

        # Auto-set Clinical Liaison -> Lauren Redig for Clinical escalations
        if esc.type in CLINICAL_TYPES and not esc.clinical_liaison_id:
            liaison = get_clinical_liaison_user()
            if liaison:
                esc.clinical_liaison_id = liaison.id
            # If she isn't found in the User table, just skip - don't crash creation.

        # Auto-derive Compliance Manager / Pre-Start Compliance Manager (items 2d/6b)
        if esc.type == TYPE_COMPLIANCE:
            esc.compliance_manager_id = derive_manager_id(esc.compliance_specialist_id)
        if esc.type == TYPE_PRESTART:
            esc.prestart_compliance_manager_id = derive_manager_id(esc.prestart_compliance_specialist_id)

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

        # Email automation #2: notify Recruiter, Sales Rep, AC, Compliance Specialist, Recruiter Manager,
        # plus the Payroll Specialist (Payroll & Timekeeping / Contract+Pay Changes) and/or Clinical Liaison (Clinical types).
        recipients = {esc.recruiter, esc.sales_rep, esc.ac, esc.compliance_specialist, esc.recruiter_manager}
        if payroll_applicable:
            recipients.add(esc.payroll_specialist)
        if esc.type in CLINICAL_TYPES:
            recipients.add(esc.clinical_liaison)
        for u in recipients:
            if u:
                send_new_escalation_email(u, esc, base_url())

        flash(f"Escalation #{esc.id} created.", "success")
        return redirect(url_for("view_escalation", escalation_id=esc.id))

    return render_template("escalation_form.html", esc=None, form={},
                            recruiters=recruiters, sales_reps=sales_reps, compliance_specialists=compliance_specialists,
                            payroll_specialists=payroll_specialists, clinical_liaisons=clinical_liaisons,
                            acs=acs, sales_rep_ac_map=sales_rep_ac_map,
                            all_users=all_users,
                            types=ESCALATION_TYPES, clinical_types=CLINICAL_TYPES, subtypes_by_type=SUBTYPES_BY_TYPE,
                            yes_no=YES_NO, statuses=STATUS_VALUES,
                            best_times=BEST_TIME_SLOTS, time_zones=TIME_ZONES, mode="create")


# ---------------------------------------------------------------------------
# 2. My Open Escalations
# ---------------------------------------------------------------------------
@app.route("/escalations/mine")
@login_required
def my_open_escalations():
    uids = visible_user_ids_for(current_user)
    escalations = Escalation.query.filter(
        Escalation.status.notin_(CLOSED_STATUSES),
        db.or_(
            Escalation.recruiter_id.in_(uids),
            Escalation.sales_rep_id.in_(uids),
            Escalation.compliance_specialist_id.in_(uids),
            Escalation.recruiter_manager_id.in_(uids),
            Escalation.action_to_id.in_(uids),
            Escalation.payroll_specialist_id.in_(uids),
            Escalation.clinical_liaison_id.in_(uids),
        ),
    ).order_by(Escalation.created_at.desc()).all()
    return render_template("my_open_escalations.html", escalations=escalations)


# ---------------------------------------------------------------------------
# 2b. My Closed Escalations (item 9)
# ---------------------------------------------------------------------------
@app.route("/escalations/mine/closed")
@login_required
def my_closed_escalations():
    uids = visible_user_ids_for(current_user)
    escalations = Escalation.query.filter(
        Escalation.status.in_(CLOSED_STATUSES),
        db.or_(
            Escalation.recruiter_id.in_(uids),
            Escalation.sales_rep_id.in_(uids),
            Escalation.clinical_liaison_id.in_(uids),
            Escalation.compliance_specialist_id.in_(uids),
            Escalation.payroll_specialist_id.in_(uids),
        ),
    ).order_by(Escalation.created_at.desc()).all()
    return render_template("my_closed_escalations.html", escalations=escalations)


# ---------------------------------------------------------------------------
# 2c. My Mentions (item 8)
# ---------------------------------------------------------------------------
@app.route("/escalations/mine/mentions")
@login_required
def my_mentions():
    escalation_ids = [
        row[0] for row in
        db.session.query(Mention.escalation_id).filter_by(mentioned_user_id=current_user.id).distinct().all()
    ]
    escalations = Escalation.query.filter(Escalation.id.in_(escalation_ids)).order_by(Escalation.created_at.desc()).all()
    return render_template("my_mentions.html", escalations=escalations)


# ---------------------------------------------------------------------------
# 3. All Escalations (+ filters)
# ---------------------------------------------------------------------------
@app.route("/escalations")
@login_required
@manager_or_admin_required
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
    payroll_specialists = payroll_specialist_options()
    clinical_liaisons = clinical_liaison_options()
    acs = ac_options()
    all_users = User.query.order_by(User.first_name).all()
    sales_rep_ac_map = {u.id: u.assigned_ac_id for u in sales_reps}
    can_manage = manager_or_admin(current_user)

    if request.method == "POST":
        f = request.form
        old_action_to_id = esc.action_to_id
        old_action_item = esc.action_item
        old_status = esc.status
        old_type = esc.type

        new_action_to_id = f.get("action_to_id") or None
        new_action_item = f.get("action_item") or None

        new_type = f.get("type", esc.type)
        new_subtype = f.get("subtype") or None
        if not subtype_required_for_type(new_type):
            new_subtype = None
        elif not new_subtype:
            flash("Please select a Subtype for this escalation type.", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        payroll_applicable = payroll_specialist_applicable(new_type, new_subtype)

        if new_type == TYPE_COMPLIANCE:
            new_clinical_call_required = None
            new_danger_of_cancelling = None
            new_escalated_to_client = False
            new_best_day = None
            new_best_time = None
            new_time_zone = None
        else:
            new_clinical_call_required = f.get("clinical_call_required") or None
            new_danger_of_cancelling = f.get("danger_of_cancelling") or None
            new_escalated_to_client = bool(f.get("escalated_to_client"))
            new_best_day = f.get("best_day_to_call") or None
            new_best_time = f.get("best_time_to_call") or None
            new_time_zone = f.get("time_zone") or None

        new_discussed_with_manager = f.get("discussed_with_manager") or None
        if new_type == TYPE_PAYROLL:
            new_discussed_with_manager = None
            new_clinical_call_required = None
            new_best_day = None
            new_best_time = None
            new_time_zone = None

        # Status field: only Manager/Admin (Director/Admin) may change it at all.
        # Disabled selects aren't submitted by browsers, so a missing/unchanged
        # "status" key from a legitimate page just means "no change". A raw
        # request that tries to sneak a different value in from a non-manager
        # is explicitly rejected below.
        submitted_status = f.get("status")
        if can_manage:
            new_status = submitted_status or old_status
        else:
            new_status = old_status
            if submitted_status and submitted_status != old_status:
                flash("You do not have access to update the Status field.", "error")
                return redirect(url_for("view_escalation", escalation_id=escalation_id))

        # Items 2f/4d: a NEW status selection must be valid for the (possibly
        # just-changed) Type; a value unchanged from what's already stored is
        # always allowed, so legacy out-of-range values persist untouched.
        if not validate_status_for_type(new_type, old_status, new_status):
            allowed = STATUS_VALUES_BY_TYPE.get(new_type, STATUS_VALUES)
            flash(f"'{new_status}' is not a valid Status for the {new_type} type. Allowed: {', '.join(allowed)}", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        # VR1: Action To changed but Action Item not changed -> block
        if str(new_action_to_id) != str(old_action_to_id) and new_action_item == old_action_item:
            flash("Please update the Action Item for the person you are updating the Action To field.", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        # VR2: Best Day to Call filled requires Best Time + Time Zone
        if new_best_day and not (new_best_time and new_time_zone):
            flash("Please select Best Time to Call Traveler and the Time Zone field to save the record.", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        if discussed_with_manager_required_for_type(new_type) and not new_discussed_with_manager:
            flash("Please fill out required field: Discussed with Coast Manager", "error")
            return redirect(url_for("view_escalation", escalation_id=escalation_id))

        if new_type == TYPE_COMPLIANCE:
            new_coast_deadline = f.get("coast_deadline") or None
            new_facility_deadline = f.get("facility_deadline") or None
            if not new_coast_deadline or not new_facility_deadline:
                flash("Please fill out required field(s): Coast Deadline, Facility Deadline", "error")
                return redirect(url_for("view_escalation", escalation_id=escalation_id))
            new_pushed_start = bool(f.get("pushed_start"))
            new_pushed_start_notes = f.get("pushed_start_notes") or None
        else:
            new_coast_deadline = new_facility_deadline = new_pushed_start_notes = None
            new_pushed_start = False

        if new_type == TYPE_PAYROLL:
            new_we_date = f.get("we_date") or None
            if not new_we_date:
                flash("Please fill out required field: WE Date", "error")
                return redirect(url_for("view_escalation", escalation_id=escalation_id))
            new_date_to_be_paid = f.get("date_to_be_paid") or None
        else:
            new_we_date = new_date_to_be_paid = None

        if new_type in CLINICAL_TYPES:
            new_dnr_facility = bool(f.get("dnr_facility"))
            new_dnr_facility_notes = (f.get("dnr_facility_notes") or None) if new_dnr_facility else None
            new_dnr_msp = bool(f.get("dnr_msp"))
            new_dnr_msp_notes = (f.get("dnr_msp_notes") or None) if new_dnr_msp else None
            new_dnr_hospital_system = bool(f.get("dnr_hospital_system"))
            new_dnr_hospital_system_notes = (f.get("dnr_hospital_system_notes") or None) if new_dnr_hospital_system else None
            if new_dnr_facility and not new_dnr_facility_notes:
                flash("Please fill out required field: DNR Facility Notes", "error")
                return redirect(url_for("view_escalation", escalation_id=escalation_id))
            if new_dnr_msp and not new_dnr_msp_notes:
                flash("Please fill out required field: DNR MSP Notes", "error")
                return redirect(url_for("view_escalation", escalation_id=escalation_id))
            if new_dnr_hospital_system and not new_dnr_hospital_system_notes:
                flash("Please fill out required field: DNR Hospital System Notes", "error")
                return redirect(url_for("view_escalation", escalation_id=escalation_id))
        else:
            new_dnr_facility = new_dnr_msp = new_dnr_hospital_system = False
            new_dnr_facility_notes = new_dnr_msp_notes = new_dnr_hospital_system_notes = None

        # Apply updates
        esc.type = new_type
        esc.subtype = new_subtype
        esc.candidate = f.get("candidate", esc.candidate)
        esc.facility = f.get("facility", esc.facility)
        esc.assignment_url = f.get("assignment_url", esc.assignment_url)
        esc.discussed_with_manager = new_discussed_with_manager
        esc.clinical_call_required = new_clinical_call_required
        esc.status = new_status
        esc.recruiter_id = f.get("recruiter_id") or esc.recruiter_id
        esc.sales_rep_id = f.get("sales_rep_id") or esc.sales_rep_id
        esc.ac_id = derive_ac_id(f.get("ac_id"), esc.sales_rep_id)
        if compliance_specialist_hidden_for_type(new_type):
            esc.compliance_specialist_id = None
        else:
            esc.compliance_specialist_id = f.get("compliance_specialist_id") or esc.compliance_specialist_id
        if payroll_applicable:
            esc.payroll_specialist_id = f.get("payroll_specialist_id") or esc.payroll_specialist_id
            esc.payroll_specialist_assigned = f.get("payroll_specialist_assigned") or esc.payroll_specialist_assigned
        else:
            esc.payroll_specialist_id = None
            esc.payroll_specialist_assigned = None
        esc.clinical_liaison_id = f.get("clinical_liaison_id") or esc.clinical_liaison_id
        if new_type == TYPE_PRESTART:
            esc.prestart_compliance_specialist_id = f.get("prestart_compliance_specialist_id") or esc.prestart_compliance_specialist_id
        else:
            esc.prestart_compliance_specialist_id = None
        esc.details = sanitize_html(f.get("details"))
        esc.action_to_id = new_action_to_id
        esc.action_item = new_action_item
        esc.danger_of_cancelling = new_danger_of_cancelling
        esc.escalated_to_client = new_escalated_to_client
        esc.best_day_to_call = new_best_day
        esc.best_time_to_call = new_best_time
        esc.time_zone = new_time_zone
        esc.coast_deadline = new_coast_deadline
        esc.facility_deadline = new_facility_deadline
        esc.pushed_start = new_pushed_start
        esc.pushed_start_notes = new_pushed_start_notes
        esc.we_date = new_we_date
        esc.date_to_be_paid = new_date_to_be_paid
        esc.dnr_facility = new_dnr_facility
        esc.dnr_facility_notes = new_dnr_facility_notes
        esc.dnr_msp = new_dnr_msp
        esc.dnr_msp_notes = new_dnr_msp_notes
        esc.dnr_hospital_system = new_dnr_hospital_system
        esc.dnr_hospital_system_notes = new_dnr_hospital_system_notes
        esc.complaint_outcome = f.get("complaint_outcome") or None
        esc.clinical_team_save = bool(f.get("clinical_team_save"))
        esc.facility_resolution = f.get("facility_resolution") or None
        esc.is_traveler_canceled = f.get("is_traveler_canceled") or None

        # Confidential Information - Manager/Admin (Director/Admin) only, ignore silently for anyone else
        if can_manage and "confidential_notes" in f:
            esc.confidential_notes = f.get("confidential_notes") or None

        # Auto-set Payroll Specialist -> "Payroll Team" user
        if payroll_applicable and not esc.payroll_specialist_id:
            payroll_team = get_payroll_team_user()
            if payroll_team:
                esc.payroll_specialist_id = payroll_team.id

        # Auto-set Clinical Liaison -> Lauren Redig for Clinical escalations
        if esc.type in CLINICAL_TYPES and not esc.clinical_liaison_id:
            liaison = get_clinical_liaison_user()
            if liaison:
                esc.clinical_liaison_id = liaison.id

        # Auto-derive Compliance Manager / Pre-Start Compliance Manager (items 2d/6b)
        if esc.type == TYPE_COMPLIANCE:
            esc.compliance_manager_id = derive_manager_id(esc.compliance_specialist_id)
        else:
            esc.compliance_manager_id = None
        if esc.type == TYPE_PRESTART:
            esc.prestart_compliance_manager_id = derive_manager_id(esc.prestart_compliance_specialist_id)
        else:
            esc.prestart_compliance_manager_id = None

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

        # Email automation: Status changed -> notify Recruiter, Sales Rep, AC, Compliance Specialist,
        # plus the Payroll Specialist (Payroll & Timekeeping / Contract+Pay Changes) and/or Clinical Liaison (Clinical types).
        if new_status != old_status:
            status_recipients = {esc.recruiter, esc.sales_rep, esc.ac, esc.compliance_specialist}
            if payroll_applicable:
                status_recipients.add(esc.payroll_specialist)
            if esc.type in CLINICAL_TYPES:
                status_recipients.add(esc.clinical_liaison)
            for u in status_recipients:
                if u:
                    send_status_changed_email(u, esc, new_status, base_url())

        flash("Escalation updated.", "success")
        return redirect(url_for("view_escalation", escalation_id=escalation_id))

    return render_template(
        "escalation_detail.html", esc=esc,
        recruiters=recruiters, sales_reps=sales_reps, compliance_specialists=compliance_specialists,
        payroll_specialists=payroll_specialists, clinical_liaisons=clinical_liaisons,
        acs=acs, sales_rep_ac_map=sales_rep_ac_map,
        all_users=all_users,
        types=ALL_ESCALATION_TYPES_FOR_DISPLAY, clinical_types=CLINICAL_TYPES, subtypes_by_type=SUBTYPES_BY_TYPE,
        yes_no=YES_NO, statuses=status_options_for_type(esc.type, esc.status),
        status_values_by_type=STATUS_VALUES_BY_TYPE, all_statuses=STATUS_VALUES,
        best_times=BEST_TIME_SLOTS, time_zones=TIME_ZONES,
        can_manage=can_manage,
    )


@app.route("/escalations/<int:escalation_id>/comment", methods=["POST"])
@login_required
def add_comment(escalation_id):
    esc = db.session.get(Escalation, escalation_id) or abort(404)
    raw_body = request.form.get("body", "").strip()
    body = sanitize_html(raw_body) or ""
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
        # Persist a Mention row for every match (item 8), regardless of self-mention,
        # so "My Mentions" reflects exactly what parse_mentions() detected.
        db.session.add(Mention(escalation_id=esc.id, comment_id=comment.id, mentioned_user_id=u.id))
    db.session.commit()

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
@manager_or_admin_required
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
        types=ALL_ESCALATION_TYPES_FOR_DISPLAY,
        statuses=STATUS_VALUES,
        saved_views=saved_views,
        users_by_id={u.id: u.full_name for u in User.query.all()},
    )


@app.route("/reporting/save", methods=["POST"])
@login_required
@manager_or_admin_required
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
@manager_or_admin_required
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
    acs = ac_options()
    return render_template("manage_users.html", users=users, roles=ROLES, acs=acs)


@app.route("/users/new", methods=["POST"])
@login_required
@admin_required
def create_user():
    f = request.form
    role = f.get("role") or "Recruiter"
    assigned_ac_id = f.get("assigned_ac_id") or None
    user = User(
        first_name=f.get("first_name", "").strip(),
        last_name=f.get("last_name", "").strip(),
        email=f.get("email", "").strip().lower(),
        role=role,
        manager_id=f.get("manager_id") or None,
        assigned_ac_id=assigned_ac_id if role == "Account Manager" else None,
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
    if user.role == "Account Manager":
        assigned_ac_id = f.get("assigned_ac_id") or None
        user.assigned_ac_id = int(assigned_ac_id) if assigned_ac_id and int(assigned_ac_id) != user.id else None
    else:
        user.assigned_ac_id = None
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
    for model in [User, Escalation, Comment, SavedReportView, Attachment, Mention, MigrationFlag]:
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

    # Auto-seed the "Payroll Team" service user so Payroll & Timekeeping escalations
    # always have someone to auto-assign as Payroll Specialist. Matched by email,
    # created with a random unusable password (same pattern as create_user()/seed-admin).
    if not User.query.filter(db.func.lower(User.email) == PAYROLL_TEAM_EMAIL).first():
        _payroll_team = User(first_name="Payroll", last_name="Team", email=PAYROLL_TEAM_EMAIL, role="Payroll")
        _payroll_team.set_password(secrets.token_urlsafe(16))
        db.session.add(_payroll_team)
        db.session.commit()
        print(f"Seeded service user {PAYROLL_TEAM_EMAIL}")

    # One-time data migration (item 11a): every existing user with role="Manager"
    # becomes role="Director" (the renamed manager-tier role). Guarded by a
    # MigrationFlag marker row so it runs exactly once, ever - this is what lets
    # someone be freely assigned the NEW scoped "Manager" role afterwards
    # without this migration wrongly renaming them back to Director on a
    # later boot.
    if not db.session.get(MigrationFlag, "manager_to_director_rename"):
        _legacy_managers = User.query.filter_by(role="Manager").all()
        for _u in _legacy_managers:
            _u.role = "Director"
        db.session.add(MigrationFlag(key="manager_to_director_rename"))
        db.session.commit()
        print(f"Auto-migration: renamed {len(_legacy_managers)} Manager-role user(s) to Director.")

    # One-time data migration: the "Compliance Specialist" role has been
    # retired and merged into "Compliance" - every existing user with that
    # role becomes role="Compliance". Guarded by its own MigrationFlag marker
    # so it only ever runs once, same pattern as the Manager->Director rename
    # above (and for the same reason: "Compliance Specialist" could otherwise
    # theoretically be re-added as a role name later without this migration
    # firing again unexpectedly).
    if not db.session.get(MigrationFlag, "compliance_specialist_to_compliance_rename"):
        _legacy_compliance_specialists = User.query.filter_by(role=RETIRED_ROLE_COMPLIANCE_SPECIALIST).all()
        for _u in _legacy_compliance_specialists:
            _u.role = "Compliance"
        db.session.add(MigrationFlag(key="compliance_specialist_to_compliance_rename"))
        db.session.commit()
        print(f"Auto-migration: renamed {len(_legacy_compliance_specialists)} Compliance Specialist-role user(s) to Compliance.")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
