import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv

load_dotenv()

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL")

def send_alert_email(to_email: str, subject: str, body: str):
    """Send an alert email via SendGrid"""
    if not SENDGRID_API_KEY:
        print(f"[ALERT] No SendGrid key — would have sent: {subject}")
        return False
    try:
        message = Mail(
            from_email=FROM_EMAIL,
            to_emails=to_email,
            subject=subject,
            html_content=f"""
            <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0a0e1a;color:#e2e8f0;padding:32px;border-radius:12px;">
                <h2 style="color:#ef4444;">🛡️ ThreatView Alert</h2>
                <div style="background:#111827;padding:20px;border-radius:8px;border-left:4px solid #ef4444;">
                    {body}
                </div>
                <p style="color:#6b7280;font-size:12px;margin-top:20px;">
                    This alert was generated automatically by ThreatView.
                </p>
            </div>
            """
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
        print(f"[ALERT] Email sent to {to_email}: {subject}")
        return True
    except Exception as e:
        print(f"[ALERT] Email error: {e}")
        return False

def check_industry_alerts(db, new_indicators: list):
    """IF new threat industry matches user industry THEN send email"""
    from models.user_alert import UserAlert
    
    users = db.query(UserAlert).filter(UserAlert.alert_on_industry == True).all()
    
    for user in users:
        if not user.industry:
            continue
        matching = [
            i for i in new_indicators
            if user.industry.lower() in (i.get("tags") or "").lower()
            or user.industry.lower() in (i.get("description") or "").lower()
        ]
        if matching:
            body = f"""
                <p><strong>Industry Match Detected!</strong></p>
                <p>Your industry <strong>{user.industry}</strong> was mentioned in {len(matching)} new threat indicator(s).</p>
                <table style="width:100%;border-collapse:collapse;margin-top:16px;">
                    <tr style="border-bottom:1px solid #374151;">
                        <th style="text-align:left;padding:8px;color:#9ca3af;">Indicator</th>
                        <th style="text-align:left;padding:8px;color:#9ca3af;">Type</th>
                        <th style="text-align:left;padding:8px;color:#9ca3af;">Source</th>
                    </tr>
                    {"".join(f'<tr><td style="padding:8px;font-family:monospace;color:#a5b4fc">{i["value"]}</td><td style="padding:8px">{i["threat_type"]}</td><td style="padding:8px">{i["source"]}</td></tr>' for i in matching[:5])}
                </table>
                <p style="margin-top:16px;color:#ef4444;">⚠️ Immediate review recommended.</p>
            """
            send_alert_email(
                user.email,
                f"⚠️ ThreatView: {len(matching)} threats targeting {user.industry} detected",
                body
            )

def check_domain_alerts(db, new_indicators: list):
    """Alert user if their domain appears in any threat feed"""
    from models.user_alert import UserAlert
    
    users = db.query(UserAlert).filter(UserAlert.alert_on_domain == True).all()
    
    for user in users:
        if not user.domain:
            continue
        matching = [
            i for i in new_indicators
            if user.domain.lower() in (i.get("value") or "").lower()
        ]
        if matching:
            body = f"""
                <p><strong>⚠️ Brand Alert — Your Domain Was Detected!</strong></p>
                <p>Your domain <strong>{user.domain}</strong> was found in {len(matching)} threat feed(s).</p>
                <table style="width:100%;border-collapse:collapse;margin-top:16px;">
                    <tr style="border-bottom:1px solid #374151;">
                        <th style="text-align:left;padding:8px;color:#9ca3af;">Indicator</th>
                        <th style="text-align:left;padding:8px;color:#9ca3af;">Threat Type</th>
                        <th style="text-align:left;padding:8px;color:#9ca3af;">Source</th>
                    </tr>
                    {"".join(f'<tr><td style="padding:8px;font-family:monospace;color:#ef4444">{i["value"]}</td><td style="padding:8px">{i["threat_type"]}</td><td style="padding:8px">{i["source"]}</td></tr>' for i in matching[:5])}
                </table>
                <p style="margin-top:16px;color:#ef4444;">🚨 Your domain may be used in a phishing campaign. Investigate immediately.</p>
            """
            send_alert_email(
                user.email,
                f"🚨 ThreatView: Your domain {user.domain} found in threat feeds!",
                body
            )
