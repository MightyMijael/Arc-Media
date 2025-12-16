from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from models import db, User, TimeLog, BreakAlert
from datetime import datetime, timedelta
import os
import secrets # For generating secure one-time passwords

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
# Using SQLite, Railway provides DATABASE_URL, but for SQLite we define it here
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///timeclock.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# --- Helper Functions ---

def get_current_user():
    """Get the current user object based on session."""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def calculate_break_alerts():
    """
    Check recent TimeLog entries for break overruns.
    Logs alerts if a break exceeds 30 minutes.
    This runs on specific page loads (like admin index).
    """
    thirty_minutes = timedelta(minutes=30)
    # Get all 'break_end' logs from the last hour to check against
    recent_break_ends = TimeLog.query.filter(
        TimeLog.action == 'break_end',
        TimeLog.timestamp >= datetime.now() - timedelta(hours=1)
    ).all()

    for end_log in recent_break_ends:
        # Find the corresponding 'break_start' for this user on the same day
        start_log = TimeLog.query.filter(
            TimeLog.user_id == end_log.user_id,
            TimeLog.action == 'break_start',
            TimeLog.timestamp.date() == end_log.timestamp.date(),
            TimeLog.timestamp < end_log.timestamp # Ensure start is before end
        ).order_by(TimeLog.timestamp.desc()).first() # Get the most recent start before this end

        if start_log:
            break_duration = end_log.timestamp - start_log.timestamp
            if break_duration > thirty_minutes:
                excess_time = break_duration - thirty_minutes
                # Check if an alert already exists for this specific event to avoid duplicates
                existing_alert = BreakAlert.query.filter_by(
                    user_id=end_log.user_id,
                    date=start_log.timestamp.date()
                ).filter(
                    BreakAlert.logged_timestamp >= start_log.timestamp,
                    BreakAlert.logged_timestamp <= end_log.timestamp
                ).first()

                if not existing_alert:
                    alert = BreakAlert(
                        user_id=end_log.user_id,
                        date=start_log.timestamp.date(),
                        break_duration=break_duration.total_seconds() / 60, # Store in minutes
                        excess_time=excess_time.total_seconds() / 60,      # Store in minutes
                        logged_timestamp=datetime.now()
                    )
                    db.session.add(alert)
    db.session.commit()


# --- Routes ---

@app.route('/')
def index():
    """Redirect to login if not logged in, otherwise to the appropriate dashboard."""
    if 'user_id' in session:
        user = get_current_user()
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else: # Assume agent role
            return redirect(url_for('agent_clock'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash(f'Logged in successfully as {user.username}!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('agent_clock'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/agent')
def agent_clock():
    if 'user_id' not in session or session.get('role') != 'agent':
        return redirect(url_for('login'))

    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Get today's logs for the user
    today_start = datetime.combine(datetime.today().date(), datetime.min.time())
    today_logs = TimeLog.query.filter(
        TimeLog.user_id == user.id,
        TimeLog.timestamp >= today_start
    ).order_by(TimeLog.timestamp.asc()).all()

    status = "Not Clocked In"
    last_action = None
    if today_logs:
        last_log = today_logs[-1]
        last_action = last_log.action
        if last_action == 'clock_in' or last_action == 'break_end':
            status = "Clocked In"
        elif last_action == 'clock_out':
            status = "Clocked Out"
        elif last_action == 'break_start':
            status = "On Break"

    return render_template('agent.html', user=user, status=status, last_action=last_action)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Calculate alerts before fetching data for display
    calculate_break_alerts()

    # Fetch all users and their latest status for display
    all_users = User.query.all()
    user_statuses = {}
    for u in all_users:
        latest_log = TimeLog.query.filter_by(user_id=u.id).order_by(TimeLog.timestamp.desc()).first()
        if latest_log:
            action = latest_log.action
            if action == 'clock_in' or action == 'break_end':
                user_statuses[u.id] = "Clocked In"
            elif action == 'clock_out':
                user_statuses[u.id] = "Clocked Out"
            elif action == 'break_start':
                user_statuses[u.id] = "On Break"
        else:
             user_statuses[u.id] = "Never Clocked"

    # Fetch recent break alerts
    recent_alerts = BreakAlert.query.order_by(BreakAlert.logged_timestamp.desc()).limit(10).all()

    return render_template('admin.html', user=user, all_users=all_users, user_statuses=user_statuses, alerts=recent_alerts)

@app.route('/punch', methods=['POST'])
def punch():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user_id = session['user_id']
    action = request.form.get('action') # Expected values: clock_in, break_start, break_end, clock_out

    valid_actions = ['clock_in', 'break_start', 'break_end', 'clock_out']
    if action not in valid_actions:
        return jsonify({'error': 'Invalid action'}), 400

    # Optional: Add logic to ensure sequence (e.g., can't clock out if not clocked in)
    # For now, just record the action.
    log_entry = TimeLog(user_id=user_id, action=action, timestamp=datetime.now())
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({'status': 'success', 'message': f'{action.replace("_", " ").title()} recorded.'})

@app.route('/export_timesheet')
def export_timesheet():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Basic export logic - fetch logs and format as CSV string
    # This is a simplified version, consider using pandas or csv module for robustness
    import io
    from flask import Response

    logs = TimeLog.query.join(User).add_columns(
        User.username,
        TimeLog.action,
        TimeLog.timestamp
    ).order_by(TimeLog.timestamp).all()

    output = io.StringIO()
    output.write("Username,Action,Timestamp\n") # CSV header
    for log in logs:
        output.write(f"{log.User.username},{log.TimeLog.action},{log.TimeLog.timestamp}\n")
    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=timesheet_export.csv"}
    )

@app.before_first_request
def create_tables_and_admin():
    """Create tables and initialize admin user if they don't exist."""
    db.create_all()
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        # Generate a temporary one-time password for the first admin setup
        temp_password = secrets.token_urlsafe(12)[:12] # Example: Generate a random 12-char string
        print(f"\n--- IMPORTANT: Initial Admin Setup ---")
        print(f"First-time Admin Username: admin")
        print(f"First-time Admin Password: {temp_password}")
        print("Log in with these credentials and change the password immediately.")
        print("---------------------------------------\n")
        admin_user = User(username='admin', role='admin')
        admin_user.set_password(temp_password) # Use the method from models.py
        db.session.add(admin_user)
        db.session.commit()

if __name__ == '__main__':
    # Only run this way for local development. For Railway, it uses the Procfile command.
    app.run(debug=True) 