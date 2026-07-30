from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ---------------------------------------------------------------------------
# Picklist values (single source of truth - used by forms, validation, filters)
# ---------------------------------------------------------------------------
# "Director" carries the old manager-tier permissions (status changes,
# Confidential section, Reporting/All Escalations tabs). "Manager" is a NEW
# standard-tier role added in this batch (see item 11) whose only special
# behavior is expanded visibility into their direct reports' records.
ROLES = [
    "Admin", "Director", "Manager", "Recruiter", "Account Manager",
    "Payroll", "Compliance", "AC",
]

# Roles that are NOT Admin/Director - i.e. everyday portal users (identical page access)
STANDARD_ROLES = [
    "Recruiter", "Account Manager", "Payroll", "Compliance", "Manager", "AC",
]

# The "Compliance Specialist" role has been retired and merged into "Compliance"
# (existing users are migrated to "Compliance" on boot - see the one-time
# migration in app.py). Kept here only so the boot-time migration and any
# legacy-data lookups know what the old role string was.
RETIRED_ROLE_COMPLIANCE_SPECIALIST = "Compliance Specialist"

# Which portal role fills which Escalation lookup field
ROLE_FOR_RECRUITER_FIELD = "Recruiter"
ROLE_FOR_SALES_REP_FIELD = "Account Manager"
ROLE_FOR_COMPLIANCE_FIELD = "Compliance"
ROLE_FOR_PAYROLL_SPECIALIST_FIELD = "Payroll"
ROLE_FOR_AC_FIELD = "AC"

# Type values retired from the CREATE form's picklist but still valid data on
# older existing records (kept out of ESCALATION_TYPES so they don't appear as
# selectable options for NEW escalations).
RETIRED_ESCALATION_TYPES = [
    "Performance & Conduct", "Attendance", "Other",
    "Scheduling & Hours", "Housing & Travel",
]

ESCALATION_TYPES = [
    "Clinical - Traveler Initiated",
    "Clinical - Client Initiated",
    "Compliance & Credentialing",
    "Payroll & Timekeeping",
    "Contract & Extension",
    "Personal (Yellow Flag)",
    "Pre-Start",
    "Contract",
]

# Full set of type values valid for DISPLAY purposes (new + retired) - used on
# the detail/edit page so old records don't lose their Type option/value.
ALL_ESCALATION_TYPES_FOR_DISPLAY = ESCALATION_TYPES + RETIRED_ESCALATION_TYPES

CLINICAL_TYPES = ["Clinical - Traveler Initiated", "Clinical - Client Initiated"]

TYPE_COMPLIANCE = "Compliance & Credentialing"
TYPE_PAYROLL = "Payroll & Timekeeping"
TYPE_CONTRACT = "Contract"
TYPE_PRESTART = "Pre-Start"

SUBTYPES_BY_TYPE = {
    "Clinical - Traveler Initiated": [
        "Personal", "Unit Concern", "Patient Care", "Pre-Start Cancel", "Relias Coaching", "Other",
    ],
    "Clinical - Client Initiated": [
        "Patient Care", "Professionalism", "Attendance", "Other",
    ],
    TYPE_COMPLIANCE: [
        "PPW", "PPW MIA", "Expiring Items", "Licensing",
    ],
    TYPE_PAYROLL: [
        "Paycheck Error", "Late", "Reimbursements", "Timekeeping",
    ],
    TYPE_CONTRACT: [
        "Shift/Scheduling", "Pay Changes",
    ],
}

# Types (besides Clinical) for which Subtype is a required field.
REQUIRED_SUBTYPE_TYPES = [TYPE_COMPLIANCE, TYPE_PAYROLL, TYPE_CONTRACT]

# Types for which "Discussed with Coast Manager?" is NOT a required field
# (it's required for every other type by default).
DISCUSSED_WITH_MANAGER_NOT_REQUIRED_TYPES = [TYPE_COMPLIANCE, TYPE_PAYROLL]

YES_NO = ["Yes", "No"]

STATUS_VALUES = [
    "Open",
    "Clinical Acknowledged",
    "In Process",
    "Clinical Call Complete",
    "Needs Follow Up",
    "Closed - Resolved",
    "Closed - Canceled",
]

# Per-type restricted status picklists. Types not present here fall back to
# the full STATUS_VALUES list. Existing/legacy records whose current status
# value isn't in the type's restricted list are still allowed to display and
# save unchanged (see app.py validation) - this only restricts NEW selections.
STATUS_VALUES_BY_TYPE = {
    TYPE_COMPLIANCE: ["Open", "Closed - Resolved", "Closed - Canceled"],
    TYPE_PAYROLL: ["Open", "Investigating", "Information Needed", "Closed - Resolved"],
}

# Statuses that keep a record in "My Open Escalations"
CLOSED_STATUSES = ["Closed - Resolved", "Closed - Canceled"]
OPEN_STATUSES = [s for s in STATUS_VALUES if s not in CLOSED_STATUSES]

BEST_TIME_SLOTS = [
    "8:00 AM - 9:00 AM",
    "9:00 AM - 10:00 AM",
    "10:00 AM - 11:00 AM",
    "11:00 AM - 12:00 PM",
    "12:00 PM - 1:00 PM",
    "1:00 PM - 2:00 PM",
    "2:00 PM - 3:00 PM",
    "3:00 PM - 4:00 PM",
    "4:00 PM - 5:00 PM",
]

TIME_ZONES = [
    "Pacific Standard Time",
    "Central Standard Time",
    "Eastern Standard Time",
    "Mountain Standard Time",
    "Alaska Standard Time",
    "Hawaii Standard Time",
]

# Fields available for the Reporting tab column/filter picker (label -> Escalation attr)
REPORT_FIELDS = [
    ("Escalation ID", "id"),
    ("Created At", "created_at"),
    ("Type", "type"),
    ("Subtype", "subtype"),
    ("Candidate", "candidate"),
    ("Facility", "facility"),
    ("Assignment URL", "assignment_url"),
    ("Discussed with Coast Manager", "discussed_with_manager"),
    ("Clinical Call Required", "clinical_call_required"),
    ("Status", "status"),
    ("Recruiter", "recruiter_id"),
    ("Sales Rep", "sales_rep_id"),
    ("AC", "ac_id"),
    ("Compliance Specialist", "compliance_specialist_id"),
    ("Recruiter Manager", "recruiter_manager_id"),
    ("Payroll Specialist", "payroll_specialist_id"),
    ("Payroll Specialist Assigned", "payroll_specialist_assigned"),
    ("Clinical Liaison", "clinical_liaison_id"),
    ("Compliance Manager", "compliance_manager_id"),
    ("Details/What Happened?", "details"),
    ("Action To", "action_to_id"),
    ("Action Item", "action_item"),
    ("Danger of Cancelling?", "danger_of_cancelling"),
    ("Escalated to Client", "escalated_to_client"),
    ("Best Day to Call Traveler", "best_day_to_call"),
    ("Best Time to Call Traveler", "best_time_to_call"),
    ("Time Zone", "time_zone"),
    ("Coast Deadline", "coast_deadline"),
    ("Facility Deadline", "facility_deadline"),
    ("Pushed Start?", "pushed_start"),
    ("Pushed Start Notes", "pushed_start_notes"),
    ("WE Date", "we_date"),
    ("Date to be paid", "date_to_be_paid"),
    ("Pre-Start Compliance Specialist", "prestart_compliance_specialist_id"),
    ("Pre-Start Compliance Manager", "prestart_compliance_manager_id"),
    ("DNR Facility", "dnr_facility"),
    ("DNR Facility Notes", "dnr_facility_notes"),
    ("DNR MSP", "dnr_msp"),
    ("DNR MSP Notes", "dnr_msp_notes"),
    ("DNR Hospital System", "dnr_hospital_system"),
    ("DNR Hospital System Notes", "dnr_hospital_system_notes"),
    ("Escalation Outcome", "complaint_outcome"),
    ("Clinical Team Save", "clinical_team_save"),
    ("Facility Resolution", "facility_resolution"),
    ("Is Traveler Canceled?", "is_traveler_canceled"),
]


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(30), nullable=False, default="Recruiter")  # Admin / Director / Manager / Recruiter / Account Manager / Compliance Specialist / Payroll / Compliance / AC
    manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    manager = db.relationship("User", remote_side=[id], foreign_keys=[manager_id])

    # Only meaningful for Account Manager-role users (the Sales Rep field) -
    # which AC-role user is this Account Manager's assigned AC. Not enforced
    # at the DB level; conditionally shown/hidden in Manage Users via JS.
    assigned_ac_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assigned_ac = db.relationship("User", remote_side=[id], foreign_keys=[assigned_ac_id])

    invite_token = db.Column(db.String(64), nullable=True)
    reset_token = db.Column(db.String(64), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def is_admin(self):
        return self.role == "Admin"

    def is_director(self):
        return self.role == "Director"

    # Kept for backward compatibility with any older callers checking for the
    # scoped "Manager" role specifically (NOT the manager-tier permission set -
    # that's now is_director()/is_manager_or_admin()).
    def is_manager(self):
        return self.role == "Manager"

    def is_manager_or_admin(self):
        """Manager-tier permission check (status changes, Confidential section,
        Reporting/All Escalations tabs). Renamed conceptually to Director in
        this batch, but the method name is kept so templates/call sites don't
        need to change."""
        return self.role in ("Admin", "Director")


class MigrationFlag(db.Model):
    """One-time-migration marker table. A row with a given key existing means
    that migration has already run and must never run again - this is what
    makes the boot-time Manager->Director rename (item 11a) safe to run on
    every boot without re-renaming users who are legitimately given the NEW
    scoped "Manager" role after the migration has already happened once."""
    __tablename__ = "migration_flags"
    key = db.Column(db.String(100), primary_key=True)
    ran_at = db.Column(db.DateTime, default=datetime.utcnow)


class Mention(db.Model):
    """Tracks each time a user is @mentioned in a Discussion comment, so the
    'My Mentions' tab can look these up directly instead of re-parsing comment
    bodies. Populated at the same time parse_mentions() fires mention emails."""
    __tablename__ = "mentions"
    id = db.Column(db.Integer, primary_key=True)
    escalation_id = db.Column(db.Integer, db.ForeignKey("escalations.id"), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey("comments.id"), nullable=True)
    mentioned_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Escalation(db.Model):
    __tablename__ = "escalations"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_by = db.relationship("User", foreign_keys=[created_by_id])

    # --- Information ---
    type = db.Column(db.String(50), nullable=False)
    subtype = db.Column(db.String(50), nullable=True)
    candidate = db.Column(db.String(255), nullable=False)
    client = db.Column(db.String(255), nullable=True)  # deprecated field, kept for backward compatibility - no longer on the page layout
    facility = db.Column(db.String(255), nullable=False)
    assignment_url = db.Column(db.String(500), nullable=False)
    discussed_with_manager = db.Column(db.String(10), nullable=True)
    clinical_call_required = db.Column(db.String(10), nullable=True)
    status = db.Column(db.String(30), nullable=False, default="Open")

    # --- Related Users ---
    recruiter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recruiter = db.relationship("User", foreign_keys=[recruiter_id])

    sales_rep_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    sales_rep = db.relationship("User", foreign_keys=[sales_rep_id])

    ac_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # auto-set from Sales Rep's assigned AC
    ac = db.relationship("User", foreign_keys=[ac_id])

    compliance_specialist_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # not required for Clinical types
    compliance_specialist = db.relationship("User", foreign_keys=[compliance_specialist_id])

    recruiter_manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    recruiter_manager = db.relationship("User", foreign_keys=[recruiter_manager_id])

    payroll_specialist_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # auto-set for Payroll & Timekeeping type (and Contract/Pay Changes)
    payroll_specialist = db.relationship("User", foreign_keys=[payroll_specialist_id])
    payroll_specialist_assigned = db.Column(db.String(255), nullable=True)  # free-text: which person on the Payroll Team

    clinical_liaison_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # auto-set for Clinical types
    clinical_liaison = db.relationship("User", foreign_keys=[clinical_liaison_id])

    # Compliance Manager (Compliance & Credentialing type) - auto-derived from
    # the selected Compliance Specialist's manager. Dynamic, never hardcoded.
    compliance_manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    compliance_manager = db.relationship("User", foreign_keys=[compliance_manager_id])

    # Pre-Start type: a separate Compliance Specialist/Manager pair, distinct
    # from the top-level Compliance Specialist field used by other types.
    prestart_compliance_specialist_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    prestart_compliance_specialist = db.relationship("User", foreign_keys=[prestart_compliance_specialist_id])
    prestart_compliance_manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    prestart_compliance_manager = db.relationship("User", foreign_keys=[prestart_compliance_manager_id])

    # --- Escalation Detail ---
    details = db.Column(db.Text, nullable=True)
    action_to_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action_to = db.relationship("User", foreign_keys=[action_to_id])
    action_item = db.Column(db.Text, nullable=True)
    danger_of_cancelling = db.Column(db.String(10), nullable=True)
    escalated_to_client = db.Column(db.Boolean, default=False)
    best_day_to_call = db.Column(db.String(20), nullable=True)  # date string
    best_time_to_call = db.Column(db.String(30), nullable=True)
    time_zone = db.Column(db.String(40), nullable=True)

    # Compliance & Credentialing type only
    coast_deadline = db.Column(db.String(20), nullable=True)  # date string
    facility_deadline = db.Column(db.String(20), nullable=True)  # date string
    pushed_start = db.Column(db.Boolean, default=False)
    pushed_start_notes = db.Column(db.Text, nullable=True)

    # Payroll & Timekeeping type only
    we_date = db.Column(db.String(20), nullable=True)  # date string
    date_to_be_paid = db.Column(db.String(20), nullable=True)  # date string

    # --- Confidential Information (Manager/Admin, i.e. Director/Admin, only) ---
    confidential_notes = db.Column(db.Text, nullable=True)

    # --- Resolution ---
    complaint_outcome = db.Column(db.Text, nullable=True)  # label renamed to "Escalation Outcome"; column kept as-is
    clinical_team_save = db.Column(db.Boolean, default=False)
    facility_resolution = db.Column(db.Text, nullable=True)
    is_traveler_canceled = db.Column(db.String(10), nullable=True)

    # DNR fields - Clinical types only
    dnr_facility = db.Column(db.Boolean, default=False)
    dnr_facility_notes = db.Column(db.Text, nullable=True)
    dnr_msp = db.Column(db.Boolean, default=False)
    dnr_msp_notes = db.Column(db.Text, nullable=True)
    dnr_hospital_system = db.Column(db.Boolean, default=False)
    dnr_hospital_system_notes = db.Column(db.Text, nullable=True)

    comments = db.relationship("Comment", backref="escalation", cascade="all, delete-orphan", order_by="Comment.created_at")
    attachments = db.relationship("Attachment", backref="escalation", cascade="all, delete-orphan", order_by="Attachment.uploaded_at")

    def user_ids_involved(self):
        return {self.recruiter_id, self.sales_rep_id, self.compliance_specialist_id,
                self.recruiter_manager_id, self.action_to_id,
                self.payroll_specialist_id, self.clinical_liaison_id, self.ac_id}

    def closed_escalation_user_ids(self):
        """The 5-field set used for 'My Closed Escalations' (item 9) - distinct
        from user_ids_involved(), which is the broader 7-field set used by
        My Open Escalations."""
        return {self.recruiter_id, self.sales_rep_id, self.clinical_liaison_id,
                self.compliance_specialist_id, self.payroll_specialist_id}


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    escalation_id = db.Column(db.Integer, db.ForeignKey("escalations.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User")
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    attachment_filename = db.Column(db.String(255), nullable=True)
    attachment_stored_name = db.Column(db.String(255), nullable=True)
    attachment_storage_type = db.Column(db.String(30), nullable=True, default="local")


class Attachment(db.Model):
    __tablename__ = "attachments"
    id = db.Column(db.Integer, primary_key=True)
    escalation_id = db.Column(db.Integer, db.ForeignKey("escalations.id"), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    uploaded_by = db.relationship("User")
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    storage_type = db.Column(db.String(30), nullable=True, default="local")
    is_confidential = db.Column(db.Boolean, default=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class SavedReportView(db.Model):
    __tablename__ = "saved_report_views"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_by = db.relationship("User")
    fields_json = db.Column(db.Text, nullable=False)   # list of REPORT_FIELDS keys
    filters_json = db.Column(db.Text, nullable=False)  # list of {field, operator, value}
    logic = db.Column(db.String(10), nullable=False, default="AND")  # AND / OR
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
