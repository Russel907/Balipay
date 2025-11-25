import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

def send_workflow_email(to_email, user_name, workflow_name, current_stage, message):
    sender_email = "fairoosa02112000@gmail.com"
    sender_password = "ssvp clya gfiv lytv"  # use environment variable later

    subject = f"Workflow Stage Notification - {workflow_name}"

    # HTML Email Template (Blue Theme)
    html_content = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                background-color: #f4f7fa;
                color: #333;
                margin: 0;
                padding: 0;
            }}
            .container {{
                width: 90%;
                max-width: 600px;
                margin: 40px auto;
                background: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(90deg, #007acc, #00c6ff);
                color: #ffffff;
                text-align: center;
                padding: 20px;
            }}
            .header h2 {{
                margin: 0;
                font-size: 22px;
            }}
            .content {{
                padding: 25px;
                line-height: 1.6;
                color: #333;
            }}
            .content h3 {{
                color: #007acc;
            }}
            .footer {{
                background: #f1f1f1;
                padding: 15px;
                text-align: center;
                font-size: 12px;
                color: #666;
            }}
            .button {{
                display: inline-block;
                background: #007acc;
                color: #fff;
                text-decoration: none;
                padding: 10px 18px;
                border-radius: 6px;
                margin-top: 15px;
            }}
            .button:hover {{
                background: #005f99;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header" style="text-align: center; background-color: #e6f0ff; padding: 15px; border-bottom: 2px solid #007bff;">
            <img src="https://upload.wikimedia.org/wikipedia/commons/a/ab/Logo_TV_2015.png" 
                alt="Company Logo" 
                style="width: 60px; height: auto; margin-bottom: 8px;" />
            <h2 style="color: #004080; font-family: Arial, sans-serif; font-size: 22px; font-weight: 700; margin: 0;">
                Workflow Stage Update
            </h2>
            </div>

            <div class="content">
                <p>Dear <strong>{user_name}</strong>,</p>
                <p>We wanted to inform you that your workflow <strong>{workflow_name}</strong> has moved to a new stage.</p>
                <h3>Current Stage: {current_stage}</h3>
                <p>This is an automated acknowledgment from the Workflow Automation System.</p>
                <p>{message}</p>
            </div>
            <div class="footer">
                <p>© {datetime.now().year} Workflow Automation System</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Create message
    msg = MIMEMultipart('alternative')
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(html_content, 'html'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        log_msg = f"[{datetime.now()}] ✅ Email sent to {to_email} for workflow '{workflow_name}' - Stage: {current_stage}"
        print(log_msg)
    except Exception as e:
        log_msg = f"[{datetime.now()}] ❌ Failed to send email to {to_email}. Error: {e}"
        print(log_msg)


send_workflow_email(
    to_email="20001102fairoosa@gmail.com",
    user_name="Yazer",
    workflow_name="Purchase Order Approval",
    current_stage="Manager Review",
    message="Your request has been approved by the manager and is now under finance department review."
)