from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='agent') # 'admin' or 'agent'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(20), nullable=False) # 'clock_in', 'break_start', 'break_end', 'clock_out'
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('time_logs', lazy=True))

    def __repr__(self):
        return f'<TimeLog {self.user_id} {self.action} @ {self.timestamp}>'

class BreakAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False) # Date the break occurred
    break_duration = db.Column(db.Float, nullable=False) # Duration in minutes
    excess_time = db.Column(db.Float, nullable=False) # Excess time in minutes
    logged_timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp()) # When the alert was generated

    user = db.relationship('User', backref=db.backref('break_alerts', lazy=True))

    def __repr__(self):
        return f'<BreakAlert {self.user.username} on {self.date}, Excess: {self.excess_time} mins>'