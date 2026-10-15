"""
INOUTX Website — Flask Backend with Contact Form API & Automatic Email Notifications
====================================================================================
Provides:
1. Static asset and frontend serving for INOUTX website.
2. Secure POST /api/contact endpoint for contact and enquiry form submissions.
3. Automated notification email to inoutx.testing@gmail.com with Reply-To set to visitor.
4. Automated confirmation email to the visitor's submitted email address.
5. Email header injection protection, input sanitization, rate limiting, and bot honeypot.
"""

import os
import re
import html
import socket
import logging
from datetime import datetime, timezone
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("inoutx-backend")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
CORS(app)  # Allow cross-origin requests from dev servers (e.g., port 8089, 5500, or file://)

# In-memory IP rate limiter (IP -> list of submission timestamps)
SUBMISSION_HISTORY = {}
RATE_LIMIT_WINDOW_SECONDS = 600  # 10 minutes
RATE_LIMIT_MAX_SUBMISSIONS = 5

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def get_client_ip():
    """Retrieve the real client IP, respecting forward headers if behind a proxy."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def is_rate_limited(ip: str) -> bool:
    """Check if the IP has exceeded maximum submissions within the time window."""
    now = datetime.now(timezone.utc).timestamp()
    timestamps = SUBMISSION_HISTORY.get(ip, [])
    # Filter timestamps within the active window
    valid_timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]
    SUBMISSION_HISTORY[ip] = valid_timestamps
    return len(valid_timestamps) >= RATE_LIMIT_MAX_SUBMISSIONS


def record_submission(ip: str):
    """Record a submission timestamp for the IP."""
    now = datetime.now(timezone.utc).timestamp()
    SUBMISSION_HISTORY.setdefault(ip, []).append(now)


def validate_contact_payload(data: dict):
    """
    Validate and sanitize input fields.
    Returns (cleaned_data, error_dict)
    """
    errors = {}
    if not isinstance(data, dict):
        return None, {"general": "Invalid request payload. Expected JSON object."}

    # Bot Honeypot Check: if 'company' or 'website' is filled, it is a bot
    honeypot = str(data.get("company", "") or data.get("website", "")).strip()
    if honeypot:
        logger.warning(f"Spam bot detected via honeypot field from IP: {get_client_ip()}")
        return None, {"bot": True}

    # 1. Name validation
    raw_name = str(data.get("name", "")).strip()
    if not raw_name:
        errors["name"] = "Please enter your name."
    elif len(raw_name) < 2 or len(raw_name) > 100:
        errors["name"] = "Name must be between 2 and 100 characters."
    elif "\r" in raw_name or "\n" in raw_name:
        errors["name"] = "Name cannot contain newline characters."

    # 2. Email validation
    raw_email = str(data.get("email", "")).strip()
    if not raw_email:
        errors["email"] = "Please enter your email address."
    elif "\r" in raw_email or "\n" in raw_email:
        errors["email"] = "Email address cannot contain newline characters."
    elif not EMAIL_REGEX.match(raw_email):
        errors["email"] = "Please enter a valid email address (e.g., name@example.com)."

    # 3. Subject validation
    raw_subject = str(data.get("subject", "")).strip()
    if not raw_subject:
        errors["subject"] = "Please enter a subject for your enquiry."
    elif len(raw_subject) < 3 or len(raw_subject) > 150:
        errors["subject"] = "Subject must be between 3 and 150 characters."
    elif "\r" in raw_subject or "\n" in raw_subject:
        errors["subject"] = "Subject cannot contain newline characters."

    # 4. Message validation
    raw_message = str(data.get("message", "")).strip()
    if not raw_message:
        errors["message"] = "Please enter your message."
    elif len(raw_message) < 10:
        errors["message"] = "Message must be at least 10 characters long."
    elif len(raw_message) > 5000:
        errors["message"] = "Message is too long (maximum 5000 characters)."

    if errors:
        return None, errors

    cleaned = {
        "name": raw_name,
        "email": raw_email.lower(),
        "subject": raw_subject,
        "message": raw_message
    }
    return cleaned, None


def get_smtp_config():
    """Retrieve and validate SMTP configuration from environment."""
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587").strip())
    smtp_email = os.getenv("SMTP_EMAIL", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    receiver_email = os.getenv("CONTACT_RECEIVER_EMAIL", "inoutx.testing@gmail.com").strip()

    is_placeholder = (
        not smtp_email or
        not smtp_password or
        "your_verified_sender" in smtp_email.lower() or
        "your_gmail_app_password" in smtp_password.lower() or
        smtp_password == "placeholder"
    )

    return {
        "host": smtp_host,
        "port": smtp_port,
        "email": smtp_email,
        "password": smtp_password,
        "receiver": receiver_email,
        "is_configured": not is_placeholder
    }


def send_contact_emails(name: str, visitor_email: str, subject: str, message: str, client_ip: str):
    """
    Sends:
    1. Notification email to the INOUTX team (inoutx.testing@gmail.com).
    2. Confirmation email to the visitor.
    """
    config = get_smtp_config()
    if not config["is_configured"]:
        logger.error("Email delivery attempted but SMTP credentials are not configured in .env.")
        raise ValueError("Email service is not yet configured. Please configure SMTP_EMAIL and SMTP_PASSWORD in .env.")

    submission_time_utc = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    escaped_name = html.escape(name)
    escaped_email = html.escape(visitor_email)
    escaped_subject = html.escape(subject)
    escaped_message = html.escape(message).replace("\n", "<br/>")

    # ----------------------------------------------------
    # 1. Build Notification Email for INOUTX Admin Team
    # ----------------------------------------------------
    admin_msg = MIMEMultipart("alternative")
    admin_msg["Subject"] = f"[INOUTX Contact] {subject}"
    admin_msg["From"] = formataddr(("INOUTX Web Notification", config["email"]))
    admin_msg["To"] = config["receiver"]
    admin_msg["Reply-To"] = formataddr((name, visitor_email))
    admin_msg["Date"] = formatdate(localtime=True)

    admin_text = (
        f"INOUTX Smart College Vehicle Monitoring System\n"
        f"New Project Enquiry / Contact Form Submission\n"
        f"====================================================\n\n"
        f"Visitor Name : {name}\n"
        f"Visitor Email: {visitor_email}\n"
        f"Subject      : {subject}\n"
        f"Date & Time  : {submission_time_utc}\n"
        f"Client IP    : {client_ip}\n\n"
        f"Message:\n"
        f"----------------------------------------------------\n"
        f"{message}\n"
        f"----------------------------------------------------\n\n"
        f"Reply directly to this email to respond to {name}."
    )

    admin_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>New INOUTX Contact Message</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #1e293b; }}
        .card {{ max-width: 620px; margin: 0 auto; background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
        .header {{ background: linear-gradient(135deg, #001938 0%, #003377 100%); color: #ffffff; padding: 28px 32px; text-align: left; }}
        .header h1 {{ margin: 0; font-size: 22px; font-weight: 800; letter-spacing: -0.02em; }}
        .header p {{ margin: 6px 0 0; font-size: 13px; color: #bae0fd; }}
        .content {{ padding: 32px; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; background: #e0f2fe; color: #0369a1; margin-bottom: 20px; }}
        table.meta {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
        table.meta td {{ padding: 10px 14px; font-size: 13px; border-bottom: 1px solid #f1f5f9; }}
        table.meta td.label {{ width: 120px; font-weight: 700; color: #64748b; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
        table.meta td.val {{ color: #0f172a; font-weight: 600; }}
        .msg-box {{ background: #f8fafc; border-left: 4px solid #003377; padding: 18px 20px; border-radius: 0 12px 12px 0; font-size: 14px; line-height: 1.6; color: #334155; margin-bottom: 24px; }}
        .footer {{ background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 18px 32px; font-size: 12px; color: #64748b; text-align: center; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h1>INOUTX Portal</h1>
          <p>Smart College Vehicle Monitoring System &bull; Campus Gate Automated Telemetry</p>
        </div>
        <div class="content">
          <span class="badge">New Contact Enquiry</span>
          <table class="meta">
            <tr>
              <td class="label">Visitor Name</td>
              <td class="val">{escaped_name}</td>
            </tr>
            <tr>
              <td class="label">Visitor Email</td>
              <td class="val"><a href="mailto:{escaped_email}" style="color: #0284c7; text-decoration: none;">{escaped_email}</a></td>
            </tr>
            <tr>
              <td class="label">Subject</td>
              <td class="val">{escaped_subject}</td>
            </tr>
            <tr>
              <td class="label">Timestamp</td>
              <td class="val">{submission_time_utc}</td>
            </tr>
            <tr>
              <td class="label">Source IP</td>
              <td class="val"><code>{client_ip}</code></td>
            </tr>
          </table>
          <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em; margin-bottom: 8px;">Complete Message</div>
          <div class="msg-box">{escaped_message}</div>
          <p style="font-size: 13px; color: #64748b; margin: 0;">You can reply directly to this notification to email <strong>{escaped_name}</strong> back.</p>
        </div>
        <div class="footer">
          INOUTX Transport Telemetry System &bull; K. Ramakrishnan College of Technology (Autonomous), Tiruchirappalli
        </div>
      </div>
    </body>
    </html>
    """

    admin_msg.attach(MIMEText(admin_text, "plain", "utf-8"))
    admin_msg.attach(MIMEText(admin_html, "html", "utf-8"))

    # ----------------------------------------------------
    # 2. Build Confirmation Email for Visitor
    # ----------------------------------------------------
    visitor_msg = MIMEMultipart("alternative")
    visitor_msg["Subject"] = "We Received Your Message — INOUTX"
    visitor_msg["From"] = formataddr(("INOUTX Team", config["email"]))
    visitor_msg["To"] = visitor_email
    visitor_msg["Date"] = formatdate(localtime=True)

    visitor_text = (
        f"Subject: We Received Your Message — INOUTX\n\n"
        f"Hello {name},\n\n"
        f"Thank you for contacting INOUTX Smart College Vehicle Monitoring System.\n\n"
        f"We have successfully received your message. Our team will review your enquiry and get back to you as soon as possible.\n\n"
        f"Your Inquiry Summary:\n"
        f"Subject: {subject}\n"
        f"Message: {message}\n\n"
        f"Regards,\n"
        f"INOUTX Team\n"
        f"KRCT, Tiruchirappalli\n"
    )

    visitor_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>We Received Your Message — INOUTX</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #1e293b; }}
        .card {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e2e8f0; box-shadow: 0 4px 14px rgba(0,0,0,0.06); }}
        .header {{ background: linear-gradient(135deg, #001938 0%, #003377 100%); color: #ffffff; padding: 30px 32px; text-align: left; }}
        .header h1 {{ margin: 0; font-size: 20px; font-weight: 800; }}
        .header p {{ margin: 6px 0 0; font-size: 13px; color: #bae0fd; }}
        .content {{ padding: 32px; font-size: 14px; line-height: 1.6; color: #334155; }}
        .summary-box {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 18px 20px; border-radius: 12px; margin: 20px 0; font-size: 13px; }}
        .summary-box strong {{ color: #0f172a; }}
        .footer {{ background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 20px 32px; font-size: 12px; color: #64748b; line-height: 1.5; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h1>INOUTX Smart College Vehicle Monitoring System</h1>
          <p>Autonomous College Bus Gate Movement Monitoring &amp; Telemetry</p>
        </div>
        <div class="content">
          <p style="margin-top: 0;"><strong>Hello {escaped_name},</strong></p>
          <p>Thank you for contacting <strong>INOUTX Smart College Vehicle Monitoring System</strong>.</p>
          <p>We have successfully received your message. Our team will review your enquiry and get back to you as soon as possible.</p>
          
          <div class="summary-box">
            <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em; margin-bottom: 8px;">Your Message Summary</div>
            <p style="margin: 4px 0;"><strong>Subject:</strong> {escaped_subject}</p>
            <p style="margin: 4px 0;"><strong>Message:</strong></p>
            <div style="color: #475569; margin-top: 4px;">{escaped_message}</div>
          </div>

          <p style="margin-bottom: 4px;">Regards,</p>
          <p style="margin: 0; font-weight: 700; color: #003377;">INOUTX Team</p>
          <p style="margin: 0; font-size: 13px; color: #64748b;">KRCT, Tiruchirappalli</p>
        </div>
        <div class="footer">
          K. Ramakrishnan College of Technology (Autonomous), Kariyamanickam Road, Samayapuram, Tiruchirappalli, Tamil Nadu 621112.<br/>
          This is an automated confirmation of receipt for your enquiry.
        </div>
      </div>
    </body>
    </html>
    """

    visitor_msg.attach(MIMEText(visitor_text, "plain", "utf-8"))
    visitor_msg.attach(MIMEText(visitor_html, "html", "utf-8"))

    # ----------------------------------------------------
    # 3. Connect to SMTP and Dispatch Both Emails
    # ----------------------------------------------------
    logger.info(f"Connecting to SMTP server {config['host']}:{config['port']}...")
    try:
        with smtplib.SMTP(config["host"], config["port"], timeout=12) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(config["email"], config["password"])

            # Send Notification to Admin
            server.send_message(admin_msg)
            logger.info(f"Notification email dispatched to {config['receiver']}.")

            # Send Confirmation to Visitor
            try:
                server.send_message(visitor_msg)
                logger.info(f"Confirmation email dispatched to visitor ({visitor_email}).")
            except Exception as conf_err:
                logger.warning(f"Notification was sent, but visitor confirmation email failed: {conf_err}")

    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error(f"SMTP Authentication Error: {auth_err}")
        raise PermissionError("SMTP authentication failed. Please verify your Gmail App Password in .env.")
    except (socket.timeout, smtplib.SMTPConnectError, socket.gaierror) as conn_err:
        logger.error(f"SMTP Connection Error: {conn_err}")
        raise ConnectionError(f"Unable to reach email server ({config['host']}:{config['port']}). Please check network/host configuration.")
    except Exception as general_err:
        logger.error(f"Failed during SMTP transmission: {general_err}")
        raise RuntimeError(f"Email delivery failed: {str(general_err)}")


# ----------------------------------------------------------------------
# API ROUTES
# ----------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint displaying system and SMTP readiness."""
    config = get_smtp_config()
    return jsonify({
        "status": "healthy",
        "service": "INOUTX Backend Portal",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "smtp_configured": config["is_configured"],
        "smtp_host": config["host"],
        "receiver_email": config["receiver"]
    }), 200


@app.route("/api/contact", methods=["POST"])
def submit_contact_form():
    """
    Contact Form Submission Endpoint
    Validates input, rate limits, sends notification & visitor confirmation emails.
    """
    client_ip = get_client_ip()

    # Rate limiting
    if is_rate_limited(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return jsonify({
            "success": False,
            "error": "You have submitted multiple requests recently. Please wait a few minutes before sending another message."
        }), 429

    # Payload retrieval
    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({
            "success": False,
            "error": "Empty or invalid submission data."
        }), 400

    # Validation
    cleaned_data, errors = validate_contact_payload(data)
    if errors:
        # If bot detected, pretend success so bot doesn't retry
        if errors.get("bot"):
            return jsonify({
                "success": True,
                "message": "Thank you! Your message has been received."
            }), 200
        return jsonify({
            "success": False,
            "error": "Please correct the highlighted errors.",
            "fields": errors
        }), 400

    # Send Emails
    try:
        send_contact_emails(
            name=cleaned_data["name"],
            visitor_email=cleaned_data["email"],
            subject=cleaned_data["subject"],
            message=cleaned_data["message"],
            client_ip=client_ip
        )
        record_submission(client_ip)
        return jsonify({
            "success": True,
            "message": "Thank you for reaching out! Your message has been successfully sent to the INOUTX team. A confirmation email has been dispatched to your inbox."
        }), 200

    except PermissionError as p_err:
        return jsonify({
            "success": False,
            "error": str(p_err)
        }), 500
    except (ConnectionError, ValueError) as c_err:
        return jsonify({
            "success": False,
            "error": str(c_err)
        }), 503
    except Exception as e:
        logger.exception("Unexpected error during contact form processing:")
        return jsonify({
            "success": False,
            "error": f"Failed to send message: {str(e)}"
        }), 500


# ----------------------------------------------------------------------
# STATIC FRONTEND ROUTES
# ----------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main INOUTX website index.html."""
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:path>")
def static_proxy(path):
    """Serve static assets directly."""
    if os.path.exists(os.path.join(BASE_DIR, path)):
        return send_from_directory(BASE_DIR, path)
    return send_from_directory(BASE_DIR, "index.html")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    logger.info(f"Starting INOUTX Flask Server on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
