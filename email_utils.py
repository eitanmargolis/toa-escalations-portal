"""
Email sending via Microsoft 365 / Microsoft Graph, matching the pattern used
in the Feature Request portal. Uses app-only auth (client credentials) with
MS_TENANT_ID / MS_CLIENT_ID / MS_CLIENT_SECRET / MS_SENDER_UPN env vars.

If those env vars are not set (e.g. local dev), emails are printed to the
console instead of sent, so the app still runs without failing.
"""
import os
import requests

MS_TENANT_ID = os.environ.get("MS_TENANT_ID")
MS_CLIENT_ID = os.environ.get("MS_CLIENT_ID")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET")
MS_SENDER_UPN = os.environ.get("MS_SENDER_UPN")

_token_cache = {"token": None}


def _get_graph_token():
    if not all([MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET]):
        return None
    url = f"https://login.microsoftonline.com/{MS_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": MS_CLIENT_ID,
        "client_secret": MS_CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]


def send_email(to_email, subject, html_body):
    """Send an email via Graph; falls back to console logging if not configured."""
    if not all([MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET, MS_SENDER_UPN]):
        print(f"[email:not-configured] To: {to_email} | Subject: {subject}\n{html_body}\n")
        return False
    try:
        token = _get_graph_token()
        url = f"https://graph.microsoft.com/v1.0/users/{MS_SENDER_UPN}/sendMail"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "message": {
                "subject": subject,
                "body": {"contentType": "HTML", "content": html_body},
                "toRecipients": [{"emailAddress": {"address": to_email}}],
            },
            "saveToSentItems": "true",
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[email:error] Failed to send to {to_email}: {exc}")
        return False


def send_action_needed_email(action_to_user, escalation, base_url):
    link = f"{base_url}/escalations/{escalation.id}"
    subject = "Your Action is Needed for this Escalation Record"
    body = f"""
    <p>Hi {action_to_user.first_name},</p>
    <p>Please take a look at this Escalation Record. Your action is needed.</p>
    <p><b>Escalation ID:</b> {escalation.id}<br/>
    <b>Candidate:</b> {escalation.candidate}<br/>
    <b>Facility:</b> {escalation.facility}<br/>
    <b>Action Item:</b> {escalation.action_item or ''}</p>
    <p><a href="{link}">Click HERE to view this Escalation Record</a></p>
    """
    send_email(action_to_user.email, subject, body)


def send_new_escalation_email(recipient_user, escalation, base_url):
    link = f"{base_url}/escalations/{escalation.id}"
    subject = f"New Escalation Record Created for {escalation.candidate}"
    body = f"""
    <p>Hi Team,</p>
    <p>Please see this new Escalation Record created for {escalation.candidate}'s placement at {escalation.facility}</p>
    <p><b>Type:</b> {escalation.type}<br/>
    <b>Details/What Happened?:</b> {escalation.details or ''}<br/>
    <b>Danger of Cancelling:</b> {escalation.danger_of_cancelling or ''}</p>
    <p><a href="{link}">Click HERE to view the Escalation record.</a></p>
    """
    send_email(recipient_user.email, subject, body)


def send_mention_email(mentioned_user, escalation, comment_author, base_url):
    link = f"{base_url}/escalations/{escalation.id}"
    subject = f"You were mentioned on Escalation #{escalation.id}"
    body = f"""
    <p>Hi {mentioned_user.first_name},</p>
    <p>{comment_author.full_name} mentioned you on Escalation #{escalation.id} ({escalation.candidate} - {escalation.facility}).</p>
    <p><a href="{link}" style="display:inline-block;padding:10px 18px;background:#002c54;color:#ffffff;text-decoration:none;border-radius:6px;">View Escalation Record</a></p>
    """
    send_email(mentioned_user.email, subject, body)


def send_new_comment_email(recipient_user, escalation, comment_author, base_url):
    link = f"{base_url}/escalations/{escalation.id}"
    subject = f"New Comment on Escalation #{escalation.id}"
    body = f"""
    <p>Hi {recipient_user.first_name},</p>
    <p>{comment_author.full_name} posted a new comment on Escalation #{escalation.id} ({escalation.candidate} - {escalation.facility}).</p>
    <p><a href="{link}">Click HERE to view this Escalation Record</a></p>
    """
    send_email(recipient_user.email, subject, body)


def send_welcome_email(user, base_url, token):
    link = f"{base_url}/reset-password/{token}"
    subject = "Welcome to the Coast Medical Service TOA Escalations Portal"
    body = f"""
    <p>Hi {user.first_name},</p>
    <p>An account has been created for you on the Coast Medical Service TOA Escalations Portal.</p>
    <p><a href="{link}">Click HERE to set your password</a> and log in for the first time.</p>
    <p>This link expires in 7 days.</p>
    """
    send_email(user.email, subject, body)


def send_password_reset_email(user, base_url, token):
    link = f"{base_url}/reset-password/{token}"
    subject = "Reset Your Password - TOA Escalations Portal"
    body = f"""
    <p>Hi {user.first_name},</p>
    <p>We received a request to reset your password on the TOA Escalations Portal.</p>
    <p><a href="{link}">Click HERE to reset your password</a>.</p>
    <p>This link expires in 2 hours. If you didn't request this, you can safely ignore this email.</p>
    """
    send_email(user.email, subject, body)


def send_status_changed_email(recipient_user, escalation, new_status, base_url):
    link = f"{base_url}/escalations/{escalation.id}"
    subject = f"Status Updated for {escalation.candidate}'s Escalation"
    body = f"""
    <p>Hi {recipient_user.first_name},</p>
    <p>The status of this Escalation Record has been updated.</p>
    <p><b>Type:</b> {escalation.type}<br/>
    <b>Candidate:</b> {escalation.candidate}<br/>
    <b>Placement URL:</b> {escalation.assignment_url}<br/>
    <b>New Status:</b> {new_status}</p>
    <p><a href="{link}" style="display:inline-block;padding:10px 18px;background:#002c54;color:#ffffff;text-decoration:none;border-radius:6px;">View Escalation Record</a></p>
    """
    send_email(recipient_user.email, subject, body)
