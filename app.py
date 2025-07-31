import os
from datetime import datetime
from flask import Flask, request, url_for, render_template, flash, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64

print("Log Message: All the dependencies are successfully installed in the python environment and successfully imported.")
 
PW_Dir = os.path.dirname(os.path.abspath(__file__)) 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ledger.sqlite3'
app.config['PASSWORD_HASH'] = '#$Colter@^'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'Arthur@Redemption'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

db = SQLAlchemy(app)
# db.init_app(app)
'''Database Tables'''

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_user=db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.user_id}>'
    
    def __init__(self, user_id, password, is_admin=False):
        self.user_id = user_id
        self.set_password(password)
        self.is_admin = is_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ParkingLot(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price_per_unit = db.Column(db.Float, nullable=False)  # price per unit time (hour)
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    max_spots = db.Column(db.Integer, nullable=False)
    spots = db.relationship('ParkingSpot', backref='lot', cascade="all, delete-orphan")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ParkingLot {self.name}>'
    def __init__(self, name, price_per_unit, address, pin_code, max_spots):
        self.name = name
        self.price_per_unit = price_per_unit
        self.address = address
        self.pin_code = pin_code
        self.max_spots = max_spots
        self.created_at = datetime.utcnow()
        # Here we don't create spots in constructor - do it after the lot is saved

    def add_spot(self, spot_number):
        existing_spots = ParkingSpot.query.filter_by(lot_id=self.id).count()
        if existing_spots < self.max_spots:
            new_spot = ParkingSpot(spot_number=spot_number, lot_id=self.id)
            db.session.add(new_spot)
            db.session.commit()
        else:
            raise Exception("Maximum parking spots reached.")
            
    def create_spots(self):
        """Create all parking spots for this lot"""
        for i in range(self.max_spots):
            spot = ParkingSpot(spot_number=str(i+1), lot_id=self.id)
            db.session.add(spot)
        db.session.commit()
    def remove_spot(self, spot_number):
        spot = ParkingSpot.query.filter_by(spot_number=spot_number, lot_id=self.id).first()
        if spot:
            db.session.delete(spot)
            db.session.commit()
        else:
            raise Exception("Parking spot not found.")
    
    def get_available_spots(self):
        return ParkingSpot.query.filter_by(lot_id=self.id, status='A').all()        
    def get_occupied_spots(self):
        return ParkingSpot.query.filter_by(lot_id=self.id, status='O').all()
    def get_spot_by_number(self, spot_number):
        return ParkingSpot.query.filter_by(spot_number=spot_number, lot_id=self.id).first()
    def get_spot_by_id(self, spot_id):
        return ParkingSpot.query.filter_by(id=spot_id, lot_id=self.id).first()  
    def get_spot_status(self, spot_number):
        spot = self.get_spot_by_number(spot_number)
        if spot:
            return spot.status
        else:
            raise Exception("Parking spot not found.")
    def set_spot_status(self, spot_number, status):
        spot = self.get_spot_by_number(spot_number)
        if spot:
            if status in ['A', 'O']:
                spot.status = status
                db.session.commit()
            else:
                raise Exception("Invalid status. Use 'A' for available or 'O' for occupied.")
        else:
            raise Exception("Parking spot not found.")
    def calculate_cost(self, spot_number, duration):
        spot = self.get_spot_by_number(spot_number)
        if spot and spot.status == 'O':
            return self.price_per_unit * duration
        else:
            raise Exception("Spot is not occupied or does not exist.")
    def get_spot_reservations(self, spot_number):
        spot = self.get_spot_by_number(spot_number)
        if spot:
            return Reservation.query.filter_by(spot_id=spot.id).all()
        else:
            raise Exception("Parking spot not found.")
    def get_all_reservations(self):
        return Reservation.query.filter_by(lot_id=self.id).all()
    
class ParkingSpot(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    spot_number = db.Column(db.String(20), nullable=False)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'), nullable=False)
    status = db.Column(db.String(1), nullable=False, default='A')  # 'A': available, 'O': occupied
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # reservations = db.relationship('Reservation', backref='spot', cascade="all, delete-orphan")
    def __repr__(self):
        return f'<ParkingSpot {self.spot_number} in Lot {self.lot_id}>'   
    def __init__(self, spot_number, lot_id):
        self.spot_number = spot_number
        self.lot_id = lot_id
        self.status = 'A'  # Fixed the syntax error
        self.created_at = datetime.utcnow()
    
    def reserve(self, user, parking_timestamp, leaving_timestamp=None):
        if self.status == 'A':
            reservation = Reservation(
                spot_id=self.id, 
                user_id=user.id, 
                parking_timestamp=parking_timestamp, 
                leaving_timestamp=leaving_timestamp
            )
            self.status = 'O'
            db.session.add(reservation)
            db.session.commit()
            return reservation
        else:
            raise Exception("Spot is already occupied.")
    def release(self):
        if self.status == 'O':
            self.status = 'A'
            db.session.commit()
        else:
            raise Exception("Spot is already available.")       

    def get_reservations(self):
        return Reservation.query.filter_by(spot_id=self.id).all()   

    def get_reservation_by_id(self, reservation_id):
        return Reservation.query.filter_by(id=reservation_id, spot_id=self.id).first()

    def get_reservation_by_user(self, user_id): 
        return Reservation.query.filter_by(user_id=user_id, spot_id=self.id).all()
    
    def get_reservation_by_timestamp(self, parking_timestamp):
        return Reservation.query.filter_by(parking_timestamp=parking_timestamp, spot_id=self.id).first()
    
    def get_reservation_by_leaving_timestamp(self, leaving_timestamp):
        return Reservation.query.filter_by(leaving_timestamp=leaving_timestamp, spot_id=self.id).first()
    def get_all_reservations(self):
        return Reservation.query.filter_by(spot_id=self.id).all()    
        
class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parking_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    leaving_timestamp = db.Column(db.DateTime, nullable=True)
    cost = db.Column(db.Float, default=0.0)    
    # Store parking lot details at time of booking to preserve history
    lot_name_at_booking = db.Column(db.String(100), nullable=True)  # Lot name when booked
    lot_address_at_booking = db.Column(db.String(200), nullable=True)  # Lot address when booked
    price_per_unit_at_booking = db.Column(db.Float, nullable=True)  # Price when booked

    spot = db.relationship('ParkingSpot')
    user = db.relationship('User')

    def __repr__(self):
        return f'<Reservation {self.id} for {self.user.user_id} at {self.spot.spot_number}>'    
    def __init__(self, spot_id, user_id, parking_timestamp=None, leaving_timestamp=None):
        self.spot_id = spot_id
        self.user_id = user_id
        self.parking_timestamp = parking_timestamp if parking_timestamp else datetime.utcnow()
        self.leaving_timestamp = leaving_timestamp
        self.cost = 0.0
        
        # Store lot details at time of booking for historical preservation
        spot = ParkingSpot.query.get(spot_id)
        if spot and spot.lot:
            self.lot_name_at_booking = spot.lot.name
            self.lot_address_at_booking = spot.lot.address
            self.price_per_unit_at_booking = spot.lot.price_per_unit
    def calculate_cost(self):
        if self.leaving_timestamp and self.parking_timestamp:
            duration = (self.leaving_timestamp - self.parking_timestamp).total_seconds() / 3600 # Convert to hours      
            price_per_unit = self.get_price_per_unit()  # Use historical price if available
            self.cost = price_per_unit * duration
            db.session.commit()
        else:
            raise Exception("Leaving timestamp is not set. Cannot calculate cost.")
    def get_cost(self):
        if self.cost > 0:
            return self.cost
        else:
            raise Exception("Cost has not been calculated yet. Please set the leaving timestamp first.")
    def set_leaving_timestamp(self, leaving_timestamp):
        self.leaving_timestamp = leaving_timestamp
        self.calculate_cost()
        db.session.commit()
    
    def get_lot_name(self):
        """Get parking lot name - use stored historical data if lot is deleted"""
        if self.lot_name_at_booking:
            return self.lot_name_at_booking
        elif self.spot and self.spot.lot:
            return self.spot.lot.name
        else:
            return "(Deleted Parking Lot)"
    
    def get_lot_address(self):
        """Get parking lot address - use stored historical data if lot is deleted"""
        if self.lot_address_at_booking:
            return self.lot_address_at_booking
        elif self.spot and self.spot.lot:
            return self.spot.lot.address
        else:
            return "Address no longer available"
    
    def get_price_per_unit(self):
        """Get price per unit - use stored historical data if lot is deleted"""
        if self.price_per_unit_at_booking:
            return self.price_per_unit_at_booking
        elif self.spot and self.spot.lot:
            return self.spot.lot.price_per_unit
        else:
            return 0.0
    
    def is_lot_deleted(self):
        """Check if the original parking lot has been deleted"""
        return self.lot_name_at_booking and (not self.spot or not self.spot.lot)
    def get_reservation_by_id(self, reservation_id):
        return Reservation.query.filter_by(id=reservation_id, spot_id=self.spot.id).first()
  


    def get_reservation_by_user(self, user_id):
        return Reservation.query.filter_by(user_id=user_id, spot_id=self.spot.id).all() 
    def get_reservation_by_timestamp(self, parking_timestamp):
        return Reservation.query.filter_by(parking_timestamp=parking_timestamp, spot_id=self.spot.id).first()
    def get_reservation_by_leaving_timestamp(self, leaving_timestamp):
        return Reservation.query.filter_by(leaving_timestamp=leaving_timestamp, spot_id=self.spot.id).first()
    def get_all_reservations(self):
        return Reservation.query.filter_by(spot_id=self.spot.id).all()


def initialise_admin():
    with app.app_context():
        admin_entry=User.query.filter_by(is_admin=True).first()
        if not admin_entry:
            admin_entry=User(user_id="admin", password='23f2003877', is_admin=True)
            db.session.add(admin_entry)
            db.session.commit()

with app.app_context():
    db.create_all()
    initialise_admin()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():    
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        user = User.query.filter_by(user_id=user_id).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('❌ Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        
        if User.query.filter_by(user_id=user_id).first():
            flash('❌ Username already exists!', 'danger')
        else:
            new_user = User(user_id=user_id, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('✅ Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        users = User.query.all()
        parking_lots = ParkingLot.query.all()
        
        # Calculate comprehensive admin statistics
        total_spots = sum(lot.max_spots for lot in parking_lots)
        occupied_spots = 0
        available_spots = 0
        
        # Get all reservations for analytics
        all_reservations = Reservation.query.all()
        active_reservations = [r for r in all_reservations if r.leaving_timestamp is None]
        completed_reservations = [r for r in all_reservations if r.leaving_timestamp is not None]
        
        # Calculate revenue
        total_revenue = sum(r.cost for r in completed_reservations)
        
        # Calculate occupancy by lot
        for lot in parking_lots:
            lot_occupied = len([s for s in lot.spots if s.status == 'O'])
            lot_available = len([s for s in lot.spots if s.status == 'A'])
            # Attach calculated values to lot object for template use
            lot.occupied_spots = lot_occupied
            lot.available_spots = lot_available
            occupied_spots += lot_occupied
            available_spots += lot_available
        
        # Calculate occupancy rate
        occupancy_rate = (occupied_spots / total_spots * 100) if total_spots > 0 else 0
        
        # Recent activity (last 10 reservations) - filter out reservations with missing spot data
        valid_reservations = [r for r in all_reservations if r.spot and r.spot.lot]
        recent_reservations = sorted(valid_reservations, key=lambda x: x.parking_timestamp or datetime.min, reverse=True)[:10]
        
        # Top performing lots (by revenue)
        lot_revenues = {}
        for res in completed_reservations:
            # Defensive: skip if spot or lot is missing
            if res.spot and res.spot.lot:
                lot_name = res.spot.lot.name
                if lot_name in lot_revenues:
                    lot_revenues[lot_name] += res.cost
                else:
                    lot_revenues[lot_name] = res.cost
        
        top_lots = sorted(lot_revenues.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Active users count (users with reservations)
        active_users = len(set(r.user_id for r in all_reservations))
        
        admin_stats = {
            'total_spots': total_spots,
            'occupied_spots': occupied_spots,
            'available_spots': available_spots,
            'occupancy_rate': occupancy_rate,
            'total_revenue': total_revenue,
            'active_reservations_count': len(active_reservations),
            'completed_reservations_count': len(completed_reservations),
            'total_reservations_count': len(all_reservations),
            'recent_reservations': recent_reservations,
            'top_lots': top_lots,
            'active_users': active_users,
            'avg_revenue_per_reservation': total_revenue / len(completed_reservations) if completed_reservations else 0
        }
        
        return render_template('admin_dashboard.html', 
                             users=users, 
                             parking_lots=parking_lots,
                             admin_stats=admin_stats)
    else:
        # Get user's reservations
        user_reservations = Reservation.query.filter_by(user_id=current_user.id).all()
        # Sort in Python instead of SQL to avoid SQLAlchemy issues
        user_reservations.sort(key=lambda x: x.parking_timestamp or datetime.min, reverse=True)
        
        # Separate active and completed reservations
        active_reservations = [r for r in user_reservations if r.leaving_timestamp is None]
        completed_reservations = [r for r in user_reservations if r.leaving_timestamp is not None]
        
        # Get all parking lots with availability info
        parking_lots = ParkingLot.query.all()
        
        # Calculate availability for each lot for template use
        for lot in parking_lots:
            lot_occupied = len([s for s in lot.spots if s.status == 'O'])
            lot_available = len([s for s in lot.spots if s.status == 'A'])
            # Attach calculated values to lot object for template use
            lot.occupied_spots = lot_occupied
            lot.available_spots = lot_available
        
        # Filter to only lots with available spots for the user dashboard
        available_lots = [lot for lot in parking_lots if lot.available_spots > 0]
        
        # Calculate real-time costs for active reservations
        current_time = datetime.utcnow()
        for reservation in active_reservations:
            if reservation.parking_timestamp:
                duration_hours = (current_time - reservation.parking_timestamp).total_seconds() / 3600
                reservation.current_cost = duration_hours * reservation.spot.lot.price_per_unit
                reservation.duration_hours = duration_hours
        
        # Calculate duration for completed reservations
        for reservation in completed_reservations:
            if reservation.parking_timestamp and reservation.leaving_timestamp:
                duration_hours = (reservation.leaving_timestamp - reservation.parking_timestamp).total_seconds() / 3600
                reservation.duration_hours = duration_hours
            else:
                reservation.duration_hours = 0
        
        # Calculate statistics
        total_spent = sum(r.cost for r in completed_reservations)
        active_cost = sum(getattr(r, 'current_cost', 0) for r in active_reservations)
        
        # Get current tab from query parameter
        current_tab = request.args.get('tab', 'overview')
        
        return render_template('user_dashboard.html', 
                             reservations=user_reservations,
                             active_reservations=active_reservations,
                             completed_reservations=completed_reservations,
                             parking_lots=parking_lots,
                             available_lots=available_lots,
                             current_time=current_time,
                             total_spent=total_spent,
                             active_cost=active_cost,
                             current_tab=current_tab)

@app.route('/user_statistics')
@login_required
def user_statistics():
    """User statistics and insights page"""
    if current_user.is_admin:
        flash('❌ This page is for regular users only!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get user's reservations
    user_reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    user_reservations.sort(key=lambda x: x.parking_timestamp or datetime.min, reverse=True)
    
    # Separate active and completed reservations
    active_reservations = [r for r in user_reservations if r.leaving_timestamp is None]
    completed_reservations = [r for r in user_reservations if r.leaving_timestamp is not None]
    
    # Calculate real-time costs for active reservations
    current_time = datetime.utcnow()
    for reservation in active_reservations:
        if reservation.parking_timestamp:
            duration_hours = (current_time - reservation.parking_timestamp).total_seconds() / 3600
            reservation.current_cost = duration_hours * reservation.spot.lot.price_per_unit
            reservation.duration_hours = duration_hours
    
    # Calculate duration for completed reservations
    for reservation in completed_reservations:
        if reservation.parking_timestamp and reservation.leaving_timestamp:
            duration_hours = (reservation.leaving_timestamp - reservation.parking_timestamp).total_seconds() / 3600
            reservation.duration_hours = duration_hours
        else:
            reservation.duration_hours = 0
    
    # Calculate statistics
    total_spent = sum(r.cost for r in completed_reservations)
    
    return render_template('user_statistics.html',
                         reservations=user_reservations,
                         active_reservations=active_reservations,
                         completed_reservations=completed_reservations,
                         total_spent=total_spent)

@app.route('/user_history')
@login_required
def user_history():
    """User booking history page"""
    if current_user.is_admin:
        flash('❌ This page is for regular users only!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get user's reservations
    user_reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    user_reservations.sort(key=lambda x: x.parking_timestamp or datetime.min, reverse=True)
    
    # Separate active and completed reservations
    active_reservations = [r for r in user_reservations if r.leaving_timestamp is None]
    completed_reservations = [r for r in user_reservations if r.leaving_timestamp is not None]
    
    # Calculate real-time costs for active reservations
    current_time = datetime.utcnow()
    for reservation in active_reservations:
        if reservation.parking_timestamp:
            duration_hours = (current_time - reservation.parking_timestamp).total_seconds() / 3600
            reservation.current_cost = duration_hours * reservation.spot.lot.price_per_unit
            reservation.duration_hours = duration_hours
    
    # Calculate duration for completed reservations
    for reservation in completed_reservations:
        if reservation.parking_timestamp and reservation.leaving_timestamp:
            duration_hours = (reservation.leaving_timestamp - reservation.parking_timestamp).total_seconds() / 3600
            reservation.duration_hours = duration_hours
        else:
            reservation.duration_hours = 0
    
    # Calculate statistics
    total_spent = sum(r.cost for r in completed_reservations)
    active_cost = sum(getattr(r, 'current_cost', 0) for r in active_reservations)
    
    return render_template('user_history.html',
                         reservations=user_reservations,
                         active_reservations=active_reservations,
                         completed_reservations=completed_reservations,
                         current_time=current_time,
                         total_spent=total_spent,
                         active_cost=active_cost)

@app.route('/admin_analytics')
@login_required
def admin_analytics():
    """Admin system overview and analytics page"""
    if not current_user.is_admin:
        flash('❌ This page is for administrators only!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all data needed for analytics
    all_lots = ParkingLot.query.all()
    all_reservations = Reservation.query.all()
    all_users = User.query.filter_by(is_admin=False).all()
    
    # Calculate total spots and occupancy
    total_spots = sum(lot.max_spots for lot in all_lots)
    occupied_spots = 0
    
    # Calculate occupied spots correctly and attach to lot objects
    for lot in all_lots:
        lot_occupied = len([s for s in lot.spots if s.status == 'O'])
        lot_available = len([s for s in lot.spots if s.status == 'A'])
        # Attach calculated values to lot object for template use
        lot.occupied_spots = lot_occupied
        lot.available_spots = lot_available
        occupied_spots += lot_occupied
    
    # Calculate total revenue
    total_revenue = sum(r.cost for r in all_reservations if r.cost)
    
    # Active reservations - filter out reservations with missing spot data
    active_reservations = [r for r in all_reservations if r.leaving_timestamp is None and r.spot and r.spot.lot]
    
    # Completed reservations - filter out reservations with missing spot data
    completed_reservations = [r for r in all_reservations if r.leaving_timestamp is not None and r.spot and r.spot.lot]
    
    # Recent reservations (last 24 hours) - filter out reservations with missing spot data
    from datetime import timedelta
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
    valid_recent_reservations = [r for r in all_reservations if r.spot and r.spot.lot and r.parking_timestamp and r.parking_timestamp >= twenty_four_hours_ago]
    
    return render_template('admin_analytics.html',
                         lots=all_lots,
                         total_spots=total_spots,
                         occupied_spots=occupied_spots,
                         available_spots=total_spots - occupied_spots,
                         total_users=len(all_users),
                         total_revenue=total_revenue,
                         active_reservations=active_reservations,
                         completed_reservations=completed_reservations,
                         recent_reservations=valid_recent_reservations)

@app.route('/admin_charts')
@login_required  
def admin_charts():
    """Admin charts and reports page"""
    if not current_user.is_admin:
        flash('❌ This page is for administrators only!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all data needed for charts
    all_lots = ParkingLot.query.all()
    all_reservations = Reservation.query.all()
    
    # Filter reservations to only include those with valid spot data
    valid_reservations = [r for r in all_reservations if r.spot and r.spot.lot]
    
    # Calculate availability for each lot for template use
    for lot in all_lots:
        lot_occupied = len([s for s in lot.spots if s.status == 'O'])
        lot_available = len([s for s in lot.spots if s.status == 'A'])
        # Attach calculated values to lot object for template use
        lot.occupied_spots = lot_occupied
        lot.available_spots = lot_available
    
    return render_template('admin_charts.html',
                         lots=all_lots,
                         reservations=valid_reservations)

@app.route('/create_parking_lot_page')
@login_required
def create_parking_lot_page():
    """Flask-centric create parking lot page"""
    if not current_user.is_admin:
        flash('🚫 Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('create_parking_lot.html')

@app.route('/create_parking_lot', methods=['GET', 'POST'])
@login_required
def create_parking_lot():
    if not current_user.is_admin:
        flash('❌ Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'GET':
        return render_template('create_parking_lot.html')
    
    # POST method - process form
    try:
        name = request.form.get('name', '').strip()
        price_per_unit = float(request.form.get('price_per_unit', '0'))
        address = request.form.get('address', '').strip()
        pin_code = request.form.get('pin_code', '').strip()
        max_spots = int(request.form.get('max_spots', '0'))
        
        # Validation
        if not name or not address or not pin_code:
            flash('❌ All fields are required!', 'danger')
            return render_template('create_parking_lot.html')
        
        if not pin_code.isdigit() or len(pin_code) != 6:
            flash('❌ PIN code must be exactly 6 digits!', 'danger')
            return render_template('create_parking_lot.html')
        
        if price_per_unit <= 0:
            flash('❌ Price per hour must be greater than 0!', 'danger')
            return render_template('create_parking_lot.html')
        
        if max_spots <= 0 or max_spots > 1000:
            flash('❌ Number of spots must be between 1 and 1000!', 'danger')
            return render_template('create_parking_lot.html')
        
        # Check if lot name already exists
        existing_lot = ParkingLot.query.filter_by(name=name).first()
        if existing_lot:
            flash(f'❌ A parking lot named "{name}" already exists!', 'danger')
            return render_template('create_parking_lot.html')
        
        new_lot = ParkingLot(name=name, price_per_unit=price_per_unit, 
                            address=address, pin_code=pin_code, max_spots=max_spots)
        db.session.add(new_lot)
        db.session.commit()
        
        # Create parking spots after the lot is saved
        new_lot.create_spots()
        
        flash(f'🏢 Parking lot "{name}" created successfully with {max_spots} spots!', 'success')
        return redirect(url_for('dashboard'))
        
    except ValueError as e:
        flash('❌ Invalid input values. Please check your entries!', 'danger')
        return render_template('create_parking_lot.html')
    except Exception as e:
        flash(f'❌ Error creating parking lot: {str(e)}', 'danger')
        return render_template('create_parking_lot.html')

@app.route('/reserve_spot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def reserve_spot(lot_id):
    if current_user.is_admin:
        flash('❌ Admins cannot reserve spots!', 'danger')
        return redirect(url_for('dashboard'))
    
    lot = ParkingLot.query.get_or_404(lot_id)
    
    if request.method == 'GET':
        # Show confirmation page with lot details
        available_spots = lot.get_available_spots()
        if not available_spots:
            flash('😞 No available spots in this parking lot!', 'warning')
            return redirect(url_for('dashboard'))
        
        return render_template('confirm_reservation.html', lot=lot, available_spots=len(available_spots))
    
    elif request.method == 'POST':
        # Process the reservation
        available_spots = lot.get_available_spots()
        
        if not available_spots:
            flash('😞 No available spots in this parking lot!', 'warning')
            return redirect(url_for('dashboard'))
        
        # Get first available spot and reserve it (allow multiple reservations per user per lot)
        spot = available_spots[0]
        reservation = spot.reserve(current_user, datetime.utcnow())
        
        # Count user's total active reservations for informative message
        user_active_count = Reservation.query.filter_by(user_id=current_user.id, leaving_timestamp=None).count()
        
        if user_active_count == 1:
            flash(f'Successfully reserved spot {spot.spot_number} at {lot.name}! Enjoy your parking! ', 'success')
        else:
            flash(f'Successfully reserved spot {spot.spot_number} at {lot.name}! You now have {user_active_count} active reservations. ', 'success')
        
        return redirect(url_for('dashboard', tab='active'))

@app.route('/release_spot/<int:reservation_id>', methods=['GET', 'POST'])
@login_required
def release_spot(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if reservation.user_id != current_user.id and not current_user.is_admin:
        flash('❌ Unauthorized access!', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'GET':
        # Show confirmation page
        if reservation.leaving_timestamp:
            flash('ℹ️ This reservation has already been completed!', 'info')
            return redirect(url_for('dashboard'))
        
        # Calculate current cost
        current_time = datetime.utcnow()
        duration_hours = (current_time - reservation.parking_timestamp).total_seconds() / 3600
        estimated_cost = duration_hours * reservation.spot.lot.price_per_unit
        
        return render_template('confirm_release.html', 
                             reservation=reservation, 
                             duration_hours=duration_hours,
                             estimated_cost=estimated_cost)
    
    elif request.method == 'POST':
        # Process the release
        if not reservation.leaving_timestamp:
            reservation.set_leaving_timestamp(datetime.utcnow())
            reservation.spot.release()
            flash(f'✅ Spot {reservation.spot.spot_number} released successfully! Final cost: ₹{reservation.cost:.2f} 🎉', 'success')
        else:
            flash('ℹ️ This reservation was already completed!', 'info')
    
        return redirect(url_for('dashboard', tab='completed'))

@app.route('/view_parking_lot/<int:lot_id>')
@login_required
def view_parking_lot(lot_id):
    if not current_user.is_admin:
        flash('❌ Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    lot = ParkingLot.query.get_or_404(lot_id)
    spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
    reservations = []
    for spot in spots:
        spot_reservations = Reservation.query.filter_by(spot_id=spot.id).all()
        reservations.extend(spot_reservations)
    
    return jsonify({
        'lot': {
            'id': lot.id,
            'name': lot.name,
            'address': lot.address,
            'pin_code': lot.pin_code,
            'price_per_unit': lot.price_per_unit,
            'max_spots': lot.max_spots,
            'created_at': lot.created_at.strftime('%Y-%m-%d %H:%M:%S')
        },
        'spots': [{
            'id': spot.id,
            'spot_number': spot.spot_number,
            'status': spot.status,
            'created_at': spot.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for spot in spots],
        'reservations': [{
            'id': res.id,
            'spot_number': res.spot.spot_number,
            'user_id': res.user.user_id,
            'parking_timestamp': res.parking_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'leaving_timestamp': res.leaving_timestamp.strftime('%Y-%m-%d %H:%M:%S') if res.leaving_timestamp else None,
            'cost': res.cost
        } for res in reservations]
    })

@app.route('/edit_parking_lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def edit_parking_lot(lot_id):
    if not current_user.is_admin:
        flash('❌ Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    lot = ParkingLot.query.get_or_404(lot_id)
    
    if request.method == 'POST':
        # Check if we can modify max_spots
        occupied_spots = len(lot.get_occupied_spots())
        new_max_spots = int(request.form['max_spots'])
        
        if new_max_spots < occupied_spots:
            flash(f'❌ Cannot reduce spots to {new_max_spots}. {occupied_spots} spots are currently occupied!', 'danger')
            return redirect(url_for('dashboard'))
        
        # Update lot details
        lot.name = request.form['name']
        lot.price_per_unit = float(request.form['price_per_unit'])
        lot.address = request.form['address']
        lot.pin_code = request.form['pin_code']
        
        # Handle spot count changes
        current_spots = len(lot.spots)
        if new_max_spots > current_spots:
            # Add new spots
            for i in range(current_spots + 1, new_max_spots + 1):
                new_spot = ParkingSpot(spot_number=str(i), lot_id=lot.id)
                db.session.add(new_spot)
        elif new_max_spots < current_spots:
            # Remove excess spots (only if they're available)
            spots_to_remove = ParkingSpot.query.filter_by(lot_id=lot.id, status='A').order_by(ParkingSpot.id.desc()).limit(current_spots - new_max_spots).all()
            for spot in spots_to_remove:
                db.session.delete(spot)
        
        lot.max_spots = new_max_spots
        db.session.commit()
        
        flash(f' Parking lot "{lot.name}" updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return jsonify({
        'id': lot.id,
        'name': lot.name,
        'address': lot.address,
        'pin_code': lot.pin_code,
        'price_per_unit': lot.price_per_unit,
        'max_spots': lot.max_spots
    })

@app.route('/delete_parking_lot/<int:lot_id>', methods=['DELETE'])
@login_required
def delete_parking_lot(lot_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    lot = ParkingLot.query.get_or_404(lot_id)
    
    # Check if any spots are occupied
    occupied_spots = lot.get_occupied_spots()
    if occupied_spots:
        return jsonify({'error': f'Cannot delete parking lot. {len(occupied_spots)} spots are currently occupied!'}), 400
    
    # Check for active reservations
    active_reservations = 0
    for spot in lot.spots:
        active_count = Reservation.query.filter_by(spot_id=spot.id, leaving_timestamp=None).count()
        active_reservations += active_count
    
    if active_reservations > 0:
        return jsonify({'error': f'Cannot delete parking lot. {active_reservations} active reservations exist!'}), 400
    
    # Delete all spots first (cascade should handle this, but being explicit)
    ParkingSpot.query.filter_by(lot_id=lot_id).delete()
    
    # Delete the parking lot
    db.session.delete(lot)
    db.session.commit()
    
    return jsonify({'success': f'Parking lot "{lot.name}" deleted successfully!'}), 200

# Flask-centric Page Routes for Admin Operations
@app.route('/view_parking_lot_page/<int:lot_id>')
@login_required
def view_parking_lot_page(lot_id):
    """Flask-centric view parking lot details page"""
    if not current_user.is_admin:
        flash('🚫 Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    lot = ParkingLot.query.get_or_404(lot_id)
    spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
    
    # Get recent reservations for this lot
    reservations = []
    for spot in spots:
        spot_reservations = Reservation.query.filter_by(spot_id=spot.id).order_by(Reservation.id.desc()).limit(10).all()
        for res in spot_reservations:
            user = User.query.get(res.user_id)
            reservations.append({
                'user_id': user.user_id if user else 'Unknown',
                'spot_number': spot.spot_number,
                'parking_timestamp': res.parking_timestamp,
                'leaving_timestamp': res.leaving_timestamp,
                'cost': res.cost,
                'status': 'Completed' if res.leaving_timestamp else 'Active'
            })
    
    # Sort by parking timestamp
    reservations.sort(key=lambda x: x['parking_timestamp'], reverse=True)
    
    # Calculate statistics
    available_spots = len([s for s in spots if s.status == 'A'])
    occupied_spots = len([s for s in spots if s.status == 'O'])
    occupancy_rate = (occupied_spots / lot.max_spots * 100) if lot.max_spots > 0 else 0
    
    return render_template('view_parking_lot.html', 
                         lot=lot, 
                         spots=spots, 
                         reservations=reservations[:10],  # Latest 10 reservations
                         available_spots=available_spots,
                         occupied_spots=occupied_spots,
                         occupancy_rate=occupancy_rate)

@app.route('/edit_parking_lot_page/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def edit_parking_lot_page(lot_id):
    """Flask-centric edit parking lot page"""
    if not current_user.is_admin:
        flash('🚫 Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    lot = ParkingLot.query.get_or_404(lot_id)
    
    if request.method == 'POST':
        try:
            # Get form data with defaults
            name = request.form.get('name', '').strip()
            address = request.form.get('address', '').strip()
            pin_code = request.form.get('pin_code', '').strip()
            price_per_unit = float(request.form.get('price_per_unit', '0'))
            new_max_spots = int(request.form.get('max_spots', '0'))
            
            # Basic validation
            if not name or not address or not pin_code:
                flash('❌ All fields are required!', 'danger')
                return render_template('edit_parking_lot.html', lot=lot)
            
            if not pin_code.isdigit() or len(pin_code) != 6:
                flash('❌ PIN code must be exactly 6 digits!', 'danger')
                return render_template('edit_parking_lot.html', lot=lot)
            
            if price_per_unit <= 0:
                flash('❌ Price per hour must be greater than 0!', 'danger')
                return render_template('edit_parking_lot.html', lot=lot)
            
            if new_max_spots <= 0 or new_max_spots > 1000:
                flash('❌ Number of spots must be between 1 and 1000!', 'danger')
                return render_template('edit_parking_lot.html', lot=lot)
            
        except ValueError:
            flash('❌ Invalid input values. Please check your entries!', 'danger')
            return render_template('edit_parking_lot.html', lot=lot)
        
        # Check if reducing spots is allowed
        if new_max_spots < lot.max_spots:
            occupied_spots = ParkingSpot.query.filter_by(lot_id=lot_id, status='O').count()
            if new_max_spots < occupied_spots:
                flash(f'❌ Cannot reduce spots to {new_max_spots}. Currently {occupied_spots} spots are occupied!', 'danger')
                return render_template('edit_parking_lot.html', lot=lot)
            
            # Remove excess spots (only available ones)
            spots_to_remove = ParkingSpot.query.filter_by(lot_id=lot_id, status='A').order_by(ParkingSpot.spot_number.desc()).limit(lot.max_spots - new_max_spots).all()
            for spot in spots_to_remove:
                db.session.delete(spot)
        
        elif new_max_spots > lot.max_spots:
            # Add new spots
            current_spots = ParkingSpot.query.filter_by(lot_id=lot_id).all()
            current_max_spot = max([int(s.spot_number) for s in current_spots], default=0)
            for i in range(current_max_spot + 1, current_max_spot + (new_max_spots - lot.max_spots) + 1):
                new_spot = ParkingSpot(
                    spot_number=str(i),
                    lot_id=lot_id
                )
                db.session.add(new_spot)
        
        # Update lot details
        lot.name = name
        lot.address = address
        lot.pin_code = pin_code
        lot.price_per_unit = price_per_unit
        lot.max_spots = new_max_spots
        
        db.session.commit()
        flash(f'✅ Parking lot "{name}" updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_parking_lot.html', lot=lot)

@app.route('/delete_parking_lot_page/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def delete_parking_lot_page(lot_id):
    """Flask-centric delete parking lot confirmation page"""
    if not current_user.is_admin:
        flash('🚫 Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    lot = ParkingLot.query.get_or_404(lot_id)
    
    # Check for active reservations
    active_reservations = 0
    for spot in lot.spots:
        active_count = Reservation.query.filter_by(spot_id=spot.id, leaving_timestamp=None).count()
        active_reservations += active_count
    
    if request.method == 'POST':
        if active_reservations > 0:
            flash(f'❌ Cannot delete parking lot. {active_reservations} active reservations exist!', 'danger')
            return render_template('delete_parking_lot.html', lot=lot, active_reservations=active_reservations)
        
        # Delete all spots first
        ParkingSpot.query.filter_by(lot_id=lot_id).delete()
        
        # Delete the parking lot
        lot_name = lot.name
        db.session.delete(lot)
        db.session.commit()
        
        flash(f' Parking lot "{lot_name}" deleted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('delete_parking_lot.html', lot=lot, active_reservations=active_reservations)

@app.route('/search_lots', methods=['GET', 'POST'])
@login_required
def search_lots():
    """User search for available parking lots functionality"""
    if current_user.is_admin:
        flash('🚫 This page is for regular users only!', 'danger')
        return redirect(url_for('dashboard'))
    
    search_results = []
    search_query = ''
    
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        
        if search_query:
            # Search by parking lot name (case insensitive)
            matching_lots = ParkingLot.query.filter(
                ParkingLot.name.ilike(f'%{search_query}%')
            ).all()
            
            # Calculate availability for each lot and filter to only available ones
            for lot in matching_lots:
                lot_occupied = len([s for s in lot.spots if s.status == 'O'])
                lot_available = len([s for s in lot.spots if s.status == 'A'])
                # Attach calculated values to lot object
                lot.occupied_spots = lot_occupied
                lot.available_spots = lot_available
                
                # Only include lots with available spots
                if lot_available > 0:
                    search_results.append(lot)
        else:
            flash('❌ Please enter a search query!', 'warning')
    
    return render_template('search_lots.html', 
                         search_results=search_results,
                         search_query=search_query)

@app.route('/search_spots', methods=['GET', 'POST'])
@login_required
def search_spots():
    """Admin search for parking spots functionality"""
    if not current_user.is_admin:
        flash('🚫 Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    search_results = []
    search_query = ''
    search_type = 'all'
    
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        search_type = request.form.get('search_type', 'all')
        
        if search_query:
            if search_type == 'spot_number':
                # Search by spot number
                spots = ParkingSpot.query.filter(ParkingSpot.spot_number.contains(search_query)).all()
            elif search_type == 'lot_name':
                # Search by parking lot name
                lots = ParkingLot.query.filter(ParkingLot.name.contains(search_query)).all()
                spots = []
                for lot in lots:
                    spots.extend(ParkingSpot.query.filter_by(lot_id=lot.id).all())
            elif search_type == 'status':
                # Search by status
                status_map = {'available': 'A', 'occupied': 'O', 'a': 'A', 'o': 'O'}
                status = status_map.get(search_query.lower(), search_query.upper())
                spots = ParkingSpot.query.filter_by(status=status).all()
            else:
                # Search all (spot number, lot name, or status)
                spots_by_number = ParkingSpot.query.filter(ParkingSpot.spot_number.contains(search_query)).all()
                lots = ParkingLot.query.filter(ParkingLot.name.contains(search_query)).all()
                spots_by_lot = []
                for lot in lots:
                    spots_by_lot.extend(ParkingSpot.query.filter_by(lot_id=lot.id).all())
                
                status_map = {'available': 'A', 'occupied': 'O', 'a': 'A', 'o': 'O'}
                status = status_map.get(search_query.lower())
                spots_by_status = ParkingSpot.query.filter_by(status=status).all() if status else []
                
                # Combine and remove duplicates
                all_spots = spots_by_number + spots_by_lot + spots_by_status
                spots = list({spot.id: spot for spot in all_spots}.values())
            
            # Build search results with additional info
            for spot in spots:
                # Get current reservation if occupied
                current_reservation = None
                if spot.status == 'O':
                    current_reservation = Reservation.query.filter_by(
                        spot_id=spot.id, 
                        leaving_timestamp=None
                    ).first()
                
                search_results.append({
                    'spot': spot,
                    'lot': spot.lot,
                    'current_reservation': current_reservation,
                    'status_text': 'Available' if spot.status == 'A' else 'Occupied',
                    'status_class': 'success' if spot.status == 'A' else 'danger'
                })
        else:
            flash('❌ Please enter a search query!', 'warning')
    
    return render_template('search_spots.html', 
                         search_results=search_results,
                         search_query=search_query,
                         search_type=search_type)



if __name__ == '__main__':
    app.run(debug=True)