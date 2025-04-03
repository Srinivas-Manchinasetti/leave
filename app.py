from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'user' or 'admin'

# Leave Model
class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    reason = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(10), default="Pending")  # Pending, Approved, Rejected

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/user_dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        reason = request.form['reason']
        leave_request = LeaveRequest(user_id=current_user.id, reason=reason)
        db.session.add(leave_request)
        db.session.commit()
        flash('Leave request submitted.', 'success')
    
    leave_requests = LeaveRequest.query.filter_by(user_id=current_user.id).all()
    return render_template('user_dashboard.html', leave_requests=leave_requests)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('user_dashboard'))

    leave_requests = LeaveRequest.query.all()
    return render_template('admin_dashboard.html', leave_requests=leave_requests)

@app.route('/approve/<int:leave_id>')
@login_required
def approve_leave(leave_id):
    if current_user.role != 'admin':
        return redirect(url_for('user_dashboard'))

    leave_request = LeaveRequest.query.get(leave_id)
    leave_request.status = "Approved"
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/reject/<int:leave_id>')
@login_required
def reject_leave(leave_id):
    if current_user.role != 'admin':
        return redirect(url_for('user_dashboard'))

    leave_request = LeaveRequest.query.get(leave_id)
    leave_request.status = "Rejected"
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():  # Ensures database tables are created within the app context
        db.create_all()
    app.run(debug=True)

