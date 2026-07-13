from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ---------------------------------------------------------------------------
# Picklist values (single source of truth - used by forms, validation, filters)
# ---------------------------------------------------------------------------
ROLES = ["Admin", "Manager", "User"]

ESCALATION_TYPES = [
    "Clinical",
    "Compliance & Credentialing",
    "Payroll & Timekeeping",
    "Performance & Conduct",
    "Attendance",
    "Scheduling & Hours",
    "Housing & Travel",
    "Contract & Extension",
    "Other",
]

YES_NO = ["Yes", "No"]

STATUS_VALUES = [
    "Open",
    "Pending Approval",
    "Clinical Acknowledged",
    "Approved",
    "Denied",
    "Closed - Resolved",
    "Closed - Canceled",
]

# Statuses that keep a record in "My Open Escalations"
OPEN_STATUSES = ["Open", "Pending Approval", "Clinical Acknowledged"]

# Statuses only Manager/Admin can set
CLOSED_STATUSES = ["Denied", "Closed - Resolved", "Closed - Canceled"]

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
    "Hawaii Standard Time",
]

# Fields available for the Reporting tab column/filter picker (label -> Escalation attr)
REPORT_FIELDS = [
    ("Escalation ID", "id"),
    ("Created At", "created_at"),
    ("Type", "type"),
    ("Candidate", "candidate"),
    ("Client", "client"),
    ("Facility", "facility"),
    ("Assignment URL", "assignment_url"),
    ("Discussed with Manager", "discussed_with_manager"),
    ("Clinical Call Required", "clinical_call_required"),
    ("Status", "status"),
    ("Recruiter", "recruiter_id"),
    ("Sales Rep", "sales_rep_id"),
    ("Compliance Specialist", "compliance_specialist_id"),
    ("Recruiter Manager", "recruiter_manager_id"),
    ("Details/What Happened?", "details"),
    ("Action To", "action_to_id"),
    ("Action Item", "action_item"),
    ("Danger of Cancelling?", "danger_of_cancelling"),
    ("Escalated to Client", "escalated_to_client"),
    ("Best Day to Call Traveler", "best_day_to_call"),
    ("Best Time to Call Traveler", "best_time_to_call"),
    ("Time Zone", "time_zone"),
    ("Complaint Outcome", "complaint_outcome"),
    ("Clinical Team Save", "clinical_team_save"),
    ("Facility Resolution", "facility_resolution"),
    ("Cancel?", "cancel"),
    ("Is Traveler Canceled?", "is_traveler_canceled"),
]


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), nullable=False, default="User")  # Admin / Manager / User
    manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    manager = db.relationship("User", remote_side=[id])
    invite_token = db.Column(db.String(64), nullable=True)
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

    def is_manager(self):
        return self.role == "Manager"


class Escalation(db.Model):
    __tablename__ = "escalations"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_by = db.relationship("User", foreign_keys=[created_by_id])

    # --- Information ---
    type = db.Column(db.String(50), nullable=False)
    candidate = db.Column(db.String(255), nullable=False)
    client = db.Column(db.String(255), nullable=False)
    facility = db.Column(db.String(255), nullable=False)
    assignment_url = db.Column(db.String(500), nullable=False)
    discussed_with_manager = db.Column(db.String(10), nullable=False)
    clinical_call_required = db.Column(db.String(10), nullable=True)
    status = db.Column(db.String(30), nullable=False, default="Open")

    recruiter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recruiter = db.relationship("User", foreign_keys=[recruiter_id])

    sales_rep_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    sales_rep = db.relationship("User", foreign_keys=[sales_rep_id])

    compliance_specialist_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    compliance_specialist = db.relationship("User", foreign_keys=[compliance_specialist_id])

    recruiter_manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    recruiter_manager = db.relationship("User", foreign_keys=[recruiter_manager_id])

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

    # --- Resolution ---
    complaint_outcome = db.Column(db.Text, nullable=True)
    clinical_team_save = db.Column(db.Boolean, default=False)
    facility_resolution = db.Column(db.Text, nullable=True)
    cancel = db.Column(db.Boolean, default=False)
    is_traveler_canceled = db.Column(db.String(10), nullable=True)

    comments = db.relationship("Comment", backref="escalation", cascade="all, delete-orphan", order_by="Comment.created_at")

    def user_ids_involved(self):
        return {self.recruiter_id, self.sales_rep_id, self.compliance_specialist_id,
                self.recruiter_manager_id, self.action_to_id}


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    escalation_id = db.Column(db.Integer, db.ForeignKey("escalations.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User")
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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
