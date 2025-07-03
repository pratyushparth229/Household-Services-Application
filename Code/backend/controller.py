from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, abort,  get_flashed_messages,send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import os
from datetime import datetime
from werkzeug.utils import secure_filename
import matplotlib.pyplot as plt
import matplotlib.pyplot as plt
from adjustText import adjust_text
import numpy as np


# Flask app initialization
app = Flask(__name__)
app.secret_key = "supersecretkey"
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["UPLOAD_CHART_FOLDER"]="static"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#initializing flask-login
login_manager=LoginManager()
login_manager.init_app(app)
# Database Initialization
DATABASE = "users.db"
ROLE = {"ADMIN": 0, "SERVICE_PROFESSIONAL": 1, "CUSTOMER": 2}
SERVICE_CATEGORY = [
    "Repairing Service",
    "Electricity Service",
    "Servicing",
    "Home Furnishing",
    "Driving Service",
    "Painting",
    "Gardening Services",
    "Cleaning Services",
    "Salon Services",
    "Plumbing",
]


def get_user_by_email(email):
    conn=sqlite3.connect('users.db')
    cursor=conn.cursor()
    cursor.execute("Select id, email, password, role, approval from users where email=?",(email,))
    user=cursor.fetchone()
    conn.close()
    return user

class User(UserMixin):
    def __init__(self, id, email, role, status):
        self.id=id
        self.email=email
        self.role=role 
        self.status=status
        
@login_manager.user_loader
def load_user(user_id):
    conn=sqlite3.connect('users.db')
    cursor=conn.cursor()
    cursor.execute("Select id, email, role, approval from users where id=?",(user_id,))
    user=cursor.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[3])
    return None


@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.path.startswith('/admin'):
        return redirect(url_for('admin_login'))
    return redirect(url_for('login'))

def isAuthorized(user, role):
    if user.role!=ROLE[role]:
        return False 
    return True

def isBlocked(user):
    if user.status=="BLOCKED":
        return True 
    return False
    

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Create tables
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role  INT NOT NULL,
                username TEXT NOT NULL,
                address TEXT NOT NULL,
                pin_code INT NOT NULL,
                service_name TEXT,
                experience INTEGER,
                cv_path TEXT,
                approval TEXT DEFAULT 'IN_PROGRESS' CHECK (approval IN ('IN_PROGRESS', 'SUCCESS', 'REJECTED',"BLOCKED", "UNBLOCKED")),
                FOREIGN KEY(service_name) REFERENCES services(service_name)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_category TEXT NOT NULL,
                service_name TEXT UNIQUE NOT NULL,
                service_description TEXT NOT NULL,
                base_price REAL NOT NULL,
                time_required TEXT NOT NULL
            )
        """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER NOT NULL,
                customer_id INTEGER NOT NULL,
                professional_id INTEGER,
                status TEXT DEFAULT 'pending' CHECK (status IN('pending', 'accepted', 'closed', 'rejected')),
                description TEXT,
                date_created TEXT DEFAULT CURRENT_TIMESTAMP,
                rating INTEGER CHECK (rating >= 1 AND rating <= 5), 
                reviews TEXT, 
                timestamp DATETIME, 
                FOREIGN KEY(service_id) REFERENCES services(id),
                FOREIGN KEY(customer_id) REFERENCES users(id),
                FOREIGN KEY(professional_id) REFERENCES users(id)
            )
        """
        )
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            professional_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES requests (id),
            FOREIGN KEY (professional_id) REFERENCES users (id)
            )'''
        )
        


        conn.commit()


# Home route
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        get_flashed_messages() 
        role=current_user.role
        if role==ROLE["CUSTOMER"]:
            flash("Already Logged In as Customer! Logout first.", "warning")
            return redirect(url_for('customer_dashboard'))
        if role==ROLE["SERVICE_PROFESSIONAL"]:
            flash("Already Logged In as Professional! Logout first.", "warning")
            return redirect(url_for("professional_dashboard"))
        if role==ROLE["ADMIN"]:
            flash("Already Logged In as Admin! Logout first.", "warning")
            return redirect(url_for("admin_dashboard"))
        
    
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        user=get_user_by_email(email)
        get_flashed_messages() 
        if user and user[2]==password:
            role=user[3]
            if role == ROLE["CUSTOMER"]:
                login_user(User(user[0], user[1], user[3], user[4]))
                flash("Logged in as Customer Successfully!", "success")
                
                return redirect(url_for("customer_dashboard"))  # Replace with customer dashboard
            elif role == ROLE["SERVICE_PROFESSIONAL"]:
                login_user(User(user[0], user[1], user[3], user[4]))
                flash("Logged in as Professional  Successfully!", "success")
                return redirect(url_for("professional_dashboard"))  # Replace with professional dashboard
            else:
                flash("Invalid credentials! Please register.", "danger")
                return redirect(url_for("register_choice")) #TODO: redirect/render to cust/prof login page with errMsg
        else:
            flash("Invalid credentials! Please register.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated:
        get_flashed_messages() 
        role=current_user.role
        if role==ROLE["CUSTOMER"]:
            flash("Already Logged In as Customer! Logout first.", "warning")
            return redirect(url_for('customer_dashboard'))
        if role==ROLE["SERVICE_PROFESSIONAL"]:
            flash("Already Logged In as Professional! Logout first.", "warning")
            return redirect(url_for("professional_dashboard"))
        if role==ROLE["ADMIN"]:
            flash("Already Logged In as Admin! Logout first.", "warning")
            return redirect(url_for("admin_dashboard"))    
    
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        role = None

        # Validate admin credentials
        user=get_user_by_email(email)
        print(user)
        get_flashed_messages() 
        if user and user[2]==password:
            role=user[3]
            if role == ROLE["ADMIN"]:
                login_user(User(user[0], user[1], user[3], user[4]))
                flash("Admin logged in successfully!", "success")
                return redirect(
                    url_for("admin_dashboard")
                )  # Replace with your admin dashboard route
            else:
                flash("Invalid credentials! Please try again.", "danger")
                return redirect(url_for("admin_login"))
        else:
            flash("Invalid credentials! Please try again.", "danger")
            return redirect(url_for("admin_login"))

    return render_template("admin_login.html")

@app.route("/logout")
@login_required
def logout():
    if not current_user.is_authenticated:
        get_flashed_messages() 
        flash("Please Login First!", "warning")
        return redirect(url_for("index")) 
        
    role=current_user.role
    logout_user()
    get_flashed_messages() 
    if role==1 or role==2:
        flash("Logged out successfully!", "success")
        return redirect(url_for("login"))
    elif role==0:
        flash("Logged out successfully!", "success")
        return redirect(url_for("admin_login"))
    else:
        flash("Logged out successfully!", "success")
        return redirect(url_for("index")) 

# Route for Registration Choice
@app.route("/register")
def register_choice():
    if current_user.is_authenticated:
        get_flashed_messages() 
        role=current_user.role
        if role==ROLE["CUSTOMER"]:
            flash("Already Logged In as Customer! Logout first.", "warning")
            return redirect(url_for('customer_dashboard'))
        if role==ROLE["SERVICE_PROFESSIONAL"]:
            flash("Already Logged In as Professional! Logout first.", "warning")
            return redirect(url_for("professional_dashboard"))
        if role==ROLE["ADMIN"]:
            flash("Already Logged In as Admin! Logout first.", "warning")
            return redirect(url_for("admin_dashboard")) 
    return render_template("login.html")


# Route to Register as Customer
@app.route("/register_customer", methods=["GET", "POST"])
def register_customer():
    get_flashed_messages() 
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        address = request.form["address"]
        pin_code = int(request.form["pin_code"])

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO users (email, username, password, approval, role, address, pin_code) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        email,
                        username,
                        password,
                        "SUCCESS",
                        ROLE["CUSTOMER"],
                        address,
                        pin_code,
                    ),
                )
                conn.commit()
                flash("Customer registered successfully. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already exists. Please try a different one.", "danger")
                return redirect(url_for("register_customer"))

    return render_template("register_customer.html")


# Route to Register as Professional
@app.route("/register_professional", methods=["GET", "POST"])
def register_professional():
    get_flashed_messages() 
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        service_name = request.form["service_name"]
        experience = request.form["experience"]
        address = request.form["address"]
        pin_code =int( request.form["pin_code"])
        cv = request.files["cv"]

        if cv and cv.filename.endswith(".pdf"):
            cv_filename = secure_filename(cv.filename)
            cv_path = os.path.join(app.config["UPLOAD_FOLDER"],f"${email}-${cv_filename}")
            cv.save(cv_path)

            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        """
                        INSERT INTO users (email, username, password, role, service_name, experience, cv_path, address, pin_code)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            email,
                            username,
                            password,
                            ROLE["SERVICE_PROFESSIONAL"],
                            service_name,
                            experience,
                            cv_path,
                            address,
                            pin_code,
                        ),
                    )
                    conn.commit()
                    flash(
                        "Professional registered successfully. Please log in.",
                        "success",
                    )
                    print("success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError as e:
                    flash(
                        "Username already exists. Please try a different one.", "danger"
                    )
                    return redirect(url_for("register_professional"))
        else:
            flash("Invalid CV file. Please upload a PDF.", "danger")
            return redirect(url_for("register_professional"))
    else:
        service_name=[]
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("select id, service_name from services")
            services = cursor.fetchall()
            service_name=[{"id":ele[0], "service_name":ele[1]} for ele in services]
            
        return render_template("register_professional.html",service_name=service_name)


# Admin dashboard
@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
        
    servicesList = []
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM services")
        services = cursor.fetchall()
       
        servicesList = [
            {
                "id": s[0],
                "service_category": s[1],
                "service_name": s[2],
                "service_description": s[3],
                "base_price": s[4],
                "time_required": s[5],
            }
            for s in services
        ]

        cursor.execute(
            "SELECT id, username FROM users WHERE role = ? AND approval = ?",
            (ROLE["SERVICE_PROFESSIONAL"], "IN_PROGRESS"),
        )
        unapproved_professionals_tuples_list = cursor.fetchall()
        unapproved_professionals = [
            {"id": tpl[0], "username": tpl[1]}
            for tpl in unapproved_professionals_tuples_list
        ]
        

        cursor.execute(
            """
            SELECT id, professional_id,date_created, status
            FROM requests
        """
        )
        
        requests = cursor.fetchall()
        
        request_list = [
            {"id": tpl[0], "professional_id": tpl[1], "date_created":tpl[2], "status":tpl[3]}
            for tpl in requests
        ]


    conn = get_db_connection()
    allProfessional=[]
    allCustomer=[]
    allCustomer = conn.execute("""
            select id, username, approval from users where role=2
                                    """).fetchall()
        
    allProfessional = conn.execute("""
            select id, username, service_name, approval from users where role=1 and approval!='IN_PROGRESS'
                                    """).fetchall()

    return render_template(
        "admin_dashboard.html",
        services=servicesList,
        unapproved_professionals=unapproved_professionals,
        requests=request_list,
        allProfessional=allProfessional,
        allCustomer=allCustomer
        
    )

@app.route("/admin_dashboard/block-unblock-user/<int:user_id>", methods=["POST"])
@login_required
def block_unblock_user(user_id):
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
    
    get_flashed_messages()
    conn = get_db_connection()
    user=conn.execute("""
                 select approval from users where id=?
                 """
                 ,(user_id,)
    ).fetchone()
    if user['approval']!="BLOCKED":
        conn.execute("""
                 update users 
                 set approval='BLOCKED'
                 where id=?
                 """
                 ,(user_id,)
        )
        flash("Blocked successfully!", "success")
    if user['approval']=="BLOCKED":
        conn.execute("""
                 update users 
                 set approval='UNBLOCKED'
                 where id=?
                 """
                 ,(user_id,)
        )
        flash("Unblocked successfully!", "success")
    conn.commit()
    conn.close()
    
    
    return redirect(url_for("admin_dashboard"))
    


# Customer dashboard
@app.route("/customer_dashboard")
@login_required
def customer_dashboard():
    
    if isAuthorized(current_user,"CUSTOMER")==False:
        abort(403)
    
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    
    user_id = current_user.id
    print(user_id)
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM services")
        services = cursor.fetchall()
        services_list = [
            {
                "id": s[0],
                "service_category": s[1],
                "service_name": s[2],
                "service_description": s[3],
                "base_price": s[4],
                "time_required": s[5],
            }
            for s in services
        ]
        #print(services_list)
        cursor.execute(
            """
           SELECT 
                r.id,
                s.service_name,
                r.status,
                COALESCE(p.username, 'None') AS professional_name,
                r.description
            FROM 
                requests r
            JOIN 
                services s ON r.service_id = s.id
            LEFT JOIN 
                users p ON r.professional_id = p.id
            WHERE 
                r.customer_id = ?;
        """,
            (user_id,),
        )
        service_history = cursor.fetchall()
        service_history_list = [
            {"id": s[0], "service_name": s[1], "description": s[4], "status": s[2], "professional_name":s[3]}
            for s in service_history
        ]
        print(service_history_list)

    return render_template(
        "customer_dashboard.html",
        services=services_list,
        service_history=service_history_list,
        user_id=user_id
    )


def segregate_requests_by_status(requests):
    """
    Segregates requests into two lists based on their status.

    Parameters:
        requests (list): A list of dictionaries, each representing a request.

    Returns:
        tuple: Two lists - one containing requests with status 'accepted',
               and the other containing requests with status 'closed'.
    """
    accepted_requests = [
        request for request in requests if request.get("status") == "accepted"
    ]
    closed_requests = [
        request for request in requests if request.get("status") == "closed"
    ]
    return accepted_requests, closed_requests

# Professional dashboard
@app.route("/professional_dashboard")
@login_required
def professional_dashboard():
 
    if isAuthorized(current_user,"SERVICE_PROFESSIONAL")==False:
        abort(403)
    
    if isBlocked(current_user):
        return render_template("blocked_page.html")
        
    user_id=current_user.id
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
           SELECT 
                r.id AS request_id,
                s.service_name,
                u.username AS customer_name,
                u.pin_code AS customer_pin_code,
                u.address AS customer_address
            FROM 
                requests r
            JOIN 
                services s ON r.service_id = s.id
            JOIN 
                users u ON r.customer_id = u.id
            LEFT JOIN 
                rejections rej ON r.id = rej.request_id AND rej.professional_id = ?
            WHERE 
                r.professional_id IS NULL
                AND rej.id IS NULL;

        """,(user_id,)
        )
        pending_requests = cursor.fetchall()
        print(pending_requests)
        pending_requests=[{
            "customer_username":ele[2], 
            "pin_code":ele[3],
            "address":ele[4],
            "service_name":ele[1],
            "id":ele[0]                                               
            } for ele in pending_requests]
        print("pending",pending_requests)
    
    
        cursor.execute(
            """
            SELECT 
                u.username AS customer_name,
                u.pin_code AS customer_pin_code,
                u.address AS customer_address,
                s.service_name,
                r.status,
                r.id AS request_id
            FROM 
                requests r
            JOIN 
                users u ON r.customer_id = u.id
            JOIN 
                services s ON r.service_id = s.id
            WHERE 
                r.professional_id = ? and status=?;

        """,
            (user_id,"accepted"),
        )
        accepted_requests = cursor.fetchall()
        accepted_requests=[{
            "customer_username":ele[0], 
            "pin_code":ele[1],
            "address":ele[2],
            "service_name":ele[3],
            "status":ele[4],
            "id":ele[5]                                               
            } for ele in accepted_requests]
        print(accepted_requests)
        
        
        cursor.execute("""
        SELECT 
            r.id AS request_id,
            s.service_name,
            u.username AS customer_name,
            u.pin_code AS customer_pin_code,
            u.address AS customer_address,
            r.rating
        FROM 
            requests r
        JOIN 
            services s ON r.service_id = s.id
        JOIN 
            users u ON r.customer_id = u.id
       
        WHERE 
            r.professional_id = ?  
            AND r.status = 'closed';
        """,(user_id,)
        )
        
        closed_request = cursor.fetchall()
        print(closed_request)
        closed_request=[{
            "customer_username":ele[2], 
            "pin_code":ele[3],
            "address":ele[4],
            "service_name":ele[1],
            "id":ele[0]   ,
            "rating":ele[5]                                            
            } for ele in closed_request]
        print(closed_request)

        
        

    return render_template(
        "professional_dashboard.html",
        pending_requests=pending_requests,
        accepted_requests=accepted_requests,
        closed_requests=closed_request
    )


# Route to create a new service
@app.route("/admin_dashboard/services/create", methods=["GET", "POST"])
@login_required
def create_service():
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
    
    get_flashed_messages() 
    if request.method == "POST":
        category = request.form["category"]
        name = request.form["name"]
        description = request.form["description"]
        time_required = request.form["time_required"]
        base_price = request.form["base_price"]

        # Insert the new service into the database
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO services (service_category, service_name, service_description, time_required, base_price)
                VALUES (?, ?, ?, ?, ?)
            """,
                (category, name, description, time_required, base_price),
            )
            conn.commit()

        flash("Service created successfully!")
        return redirect(url_for("admin_dashboard"))

    return render_template("create_service.html", service_category=SERVICE_CATEGORY)


# Route to edit an existing service
@app.route("/admin_dashboard/services/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_service(id):
    get_flashed_messages() 
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
        
    servicesList = []
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        s = cursor.execute("SELECT * FROM services WHERE id = ?", (id,)).fetchone()
        service = {
            "id": s[0],
            "service_category": s[1],
            "service_name": s[2],
            "service_description": s[3],
            "base_price": s[4],
            "time_required": s[5],
        }

    if service is None:
        flash("Service not found!")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        category = request.form["category"]
        name = request.form["name"]
        description = request.form["description"]
        time_required = request.form["time_required"]
        base_price = request.form["base_price"]

        # Update the service in the database
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE services
                SET service_category = ?, service_name = ?, service_description = ?, time_required = ?, base_price = ?
                WHERE id = ?
            """,
                (category, name, description, time_required, base_price, id),
            )
            conn.commit()

        flash("Service updated successfully!")
        return redirect(url_for("admin_dashboard"))

    return render_template(
        "edit_service.html", service=service, service_category=SERVICE_CATEGORY
    )


# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Delete service route
@app.route("/admin_dashboard/services/delete/<int:service_id>", methods=["GET"])
@login_required
def delete_service(service_id):
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
    get_flashed_messages() 
        
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Delete the service from the database
        cursor.execute("DELETE FROM services WHERE id = ?", (service_id,))
        conn.commit()
        flash("Service deleted successfully!", "success")
    except Exception as e:
        flash(f"Something went wrong!", "danger")
        return redirect(url_for("admin_dashboard")) 
    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))  # Redirect to the Admin Dashboard


# Approve service professional route
@app.route(
    "/admin_dashboard/approve_professional/<int:professional_id>", methods=["GET"]
)
@login_required
def approve_professional(professional_id):
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
    get_flashed_messages() 
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            'UPDATE users SET approval = "SUCCESS" WHERE id = ?', (professional_id,)
        )
        conn.commit()
        flash("Professional approved successfully!", "success")
    except Exception as e:
        flash(f"something wen wrong!", "danger")
        return redirect(url_for("admin_dashboard"))  
    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))  # Redirect to the Admin Dashboard


# Reject service professional route
@app.route(
    "/admin_dashboard/reject_professional/<int:professional_id>", methods=["GET"]
)
@login_required
def reject_professional(professional_id):
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
    get_flashed_messages() 
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Update professional's approval status to 'REJECTED'
        cursor.execute("DELETE FROM users WHERE id = ?", (professional_id,))
        conn.commit()
        flash("Professional rejected successfully!", "success")
    except Exception as e:
        flash(f"something went wrong", "danger")
    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))  # Redirect to the Admin Dashboard

# Route to serve the PDF
@app.route('/uploads/<filename>')
@login_required
def serve_pdf(filename):
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    try:
        # Serve the file from the uploads directory
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route("/view_professional/<int:professional_id>", methods=["GET"])
@login_required
def view_professional(professional_id):
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    
    user=None
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        s = cursor.execute("SELECT id, username, experience, service_name, approval, cv_path FROM users WHERE id = ?", (professional_id,)).fetchone()
        if s:
            user = {
                "id": s[0],
                "username": s[1],
                "experience": s[2],
                "service_name": s[3],
                "approval": s[4],
                "cv_path":s[5]
            }
    print(user, s)
    if user:
        return  render_template("view_professional.html", user=user)
    else:
        get_flashed_messages() 
        flash("Invalid user!", "danger")
        role=current_user.role 
        if role==0:
            return redirect(url_for("admin_dashboard"))
        if role==2:
            return redirect(url_for("customer_dashboard"))
    
# Route to get summary
@app.route('/admin_dashboard/summary', methods=['GET'])
@login_required
def admin_summary():
    if isAuthorized(current_user,"ADMIN")==False:
        abort(403)
    
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Query to get user role counts
    cursor.execute("""
        SELECT role, COUNT(*) AS count
        FROM users
        GROUP BY role
    """)
    user_roles = cursor.fetchall()
    user_role_counts = {row['role']: row['count'] for row in user_roles}
    print(user_role_counts)
    temp={}
    for key in user_role_counts:
        if key==1:
            temp["professional"]=user_role_counts[key]
        if key==2:
            temp["customer"]=user_role_counts[key]
    user_role_counts=temp
    
    
    # Query to get approval counts
    cursor.execute("""
        SELECT approval, COUNT(*) AS count
        FROM users
        GROUP BY approval
    """)
    approval_counts = {row['approval']: row['count'] for row in cursor.fetchall()}
    
    if "IN_PROGRESS" not in approval_counts:
        approval_counts["IN_PROGRESS"]=0
    if "SUCCESS" not in approval_counts:
        approval_counts["SUCCESS"]=0
    if "REJECTED" not in approval_counts:
        approval_counts["REJECTED"]=0
    print(approval_counts)
    
    # Query to get total customers and professionals
    cursor.execute("""
        SELECT COUNT(*) AS total_customers
        FROM users
        WHERE role = 2
    """)
    total_customers = cursor.fetchone()['total_customers']
    
    cursor.execute("""
        SELECT COUNT(*) AS total_professionals
        FROM users
        WHERE role = 1
    """)
    total_professionals = cursor.fetchone()['total_professionals']
    
    # Query to get request statuses
    cursor.execute("""
        SELECT status, COUNT(*) AS count
        FROM requests
        GROUP BY status
    """)
    request_statuses = {row['status']: row['count'] for row in cursor.fetchall()}
    
    cursor.execute("""
            SELECT 
                COUNT(*) AS rejected_requests_count
            FROM 
                requests r
            WHERE 
                NOT EXISTS (
                    SELECT 1
                    FROM users u
                    WHERE u.role = 1 -- Professional users
                    AND NOT EXISTS (
                        SELECT 1
                        FROM rejections rej
                        WHERE rej.request_id = r.id
                        AND rej.professional_id = u.id
                    )
        );
    """)
    rejected_requests_count = cursor.fetchone()['rejected_requests_count']
    
    conn.close()
    request_statuses["rejected"]=rejected_requests_count
   
    if "pending" not in request_statuses:
        request_statuses["pending"]=0
    if "accepted" not in request_statuses:
        request_statuses["accepted"]=0
    if "closed" not in request_statuses:
        request_statuses["closed"]=0
    if "rejected" not in request_statuses:
        request_statuses["rejected"]=0
    
    labels_role=["customer", "professional"]
    values_role=[user_role_counts['customer'], user_role_counts['professional']]
    
    labels_request=["accepted", "closed", "rejected", "pending"]
    values_request=[request_statuses["accepted"], request_statuses["closed"], request_statuses["rejected"], request_statuses["pending"]]
    
    generate_charts(labels_role, values_role, labels_request, values_request)
    
    # Prepare response
    response = {
        'user_role_counts': user_role_counts,
        'approval_counts': approval_counts,
        'total_customers': total_customers,
        'total_professionals': total_professionals,
        'request_statuses': request_statuses
    }
    # return jsonify(response)
    return  render_template("admin_summary.html", 
                            user_role_counts=user_role_counts, 
                            approval_counts=approval_counts,
                            total_professionals=total_professionals,
                            total_customers=total_customers,
                            request_statuses=request_statuses
                            
                            )


# Route to create a new service request
@app.route("/customer_dashboard/create_request/<int:service_id>", methods=["GET", "POST"])
@login_required
def create_request(service_id):
    if isAuthorized(current_user,"CUSTOMER")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    
    customer_id=current_user.id
    if request.method == "POST":
        description = request.form["description"]
        # Insert the new request into the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO requests (service_id, description, customer_id)
            VALUES (?, ?, ?)
        """,
            (service_id, description, customer_id),
        )
        conn.commit()
        conn.close()

        return redirect(
            url_for("customer_dashboard")
        )  # Redirect to the customer dashboard
    else:
        service = None
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            s = cursor.execute(
                "SELECT id, service_category, service_name  FROM services WHERE id = ?",
                (service_id,),
            ).fetchone()
            service = {"id": s[0], "service_category": s[1], "service_name": s[2]}
        return render_template('create_request.html', service=service)


# Route to edit an existing service request
@app.route("/customer_dashboard/edit_request/<int:request_id>", methods=["GET", "POST"])
@login_required
def edit_request(request_id):
    if isAuthorized(current_user,"CUSTOMER")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    
    customer_id=current_user.id
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the request details
    cursor.execute("""SELECT r.id, s.service_name, s.service_category, r.description
            FROM requests r
            JOIN services s ON r.service_id = s.id
            WHERE r.customer_id = ?""", (customer_id,))
    request_details = cursor.fetchone()
    req={"id":request_details[0], "service_name":request_details[1] ,"service_category":request_details[2],"description":request_details[3]}
    print(req)
    if request_details is None:
        return "Request not found", 404

    if request.method == "POST":
        service_description = request.form["description"]

        # Update the request in the database
        cursor.execute(
            """
            UPDATE requests
            SET description = ?
            WHERE id = ?
        """,
            (service_description, request_id),
        )
        conn.commit()
        conn.close()

        return redirect(
            url_for("customer_dashboard")
        )  # Redirect to the customer dashboard
    else:
        # Pre-populate the form with existing data
        return render_template("edit_request.html", request=req)


# Route to delete a service request
@app.route("/customer_dashboard/delete_request/<int:request_id>", methods=["GET"])
@login_required
def delete_request(request_id):
    if isAuthorized(current_user,"CUSTOMER")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Delete the request from the database
    cursor.execute("DELETE FROM requests WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("customer_dashboard"))  # Redirect to the customer dashboard

# Route to add a review and rating for a request and close the request
@app.route('/customer_dashboard/close-submit-review/<int:request_id>', methods=['POST', "GET"])
@login_required
def submit_review(request_id):
    if isAuthorized(current_user,"CUSTOMER")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    
    if request.method=="POST":
        # Get the data from the request
        rating = int(request.form['rating'])
        
        reviews = request.form['review']
        
        if not request_id or not rating or not reviews:
            return redirect(url_for("customer_dashboard"))  #

        # Validate rating (between 1 and 5)
        if not (1 <= rating <= 5):
            return redirect(url_for("customer_dashboard"))  #

        # Insert the review and rating into the reviewAndRating table
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Insert into reviewAndRating table
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("""
                update requests 
                set rating=? ,
                reviews=?,
                timestamp=?,
                status='closed'
                where id=?
            """, (rating, reviews, timestamp, request_id))
            
            # Close the request after review and rating submission
            # cursor.execute("""
            #     UPDATE requests
            #     SET status = 'closed'
            #     WHERE id = ?
            # """, (request_id,))
            
            conn.commit()
            conn.close()

            flash("successfully submitted the reviews and closed the request!")
            return redirect(url_for("customer_dashboard"))  #
        except Exception as e:
            print(e)
            flash("something went wrong!", "danger")
            return redirect(url_for("customer_dashboard"))  #
    else:
        return render_template("rating.html", request_id=request_id)  #

# Accept Request
@app.route('/professional_dashboard/accept_request/<int:request_id>', methods=['GET'])
@login_required
def accept_request(request_id):
    if isAuthorized(current_user,"SERVICE_PROFESSIONAL")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if request exists and professional_id is null
    cursor.execute('SELECT * FROM requests WHERE id = ? AND professional_id IS NULL', (request_id,))
    request_record = cursor.fetchone()

    if not request_record:
        return redirect(
            url_for("professional_dashboard")
        ) 

    user_id=current_user.id
    # Update the request to assign the professional
    cursor.execute('UPDATE requests SET professional_id = ?, status = "accepted" WHERE id = ?', (user_id, request_id))
    conn.commit()
    
    return redirect(
        url_for("professional_dashboard")
    )

# Reject Request
@app.route('/professional_dashboard/reject_request/<int:request_id>', methods=['GET'])
@login_required
def reject_request(request_id):
    if isAuthorized(current_user,"SERVICE_PROFESSIONAL")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert rejection record in the 'rejections' table
    user_id=current_user.id
    cursor.execute('INSERT INTO rejections (request_id, professional_id) VALUES (?, ?)',
                   (request_id, user_id))

    conn.commit()

    return redirect(
        url_for("professional_dashboard")
    )

@app.route('/professional_dashboard/profile', methods=['GET', 'POST'])
@login_required
def edit_professional():
    if isAuthorized(current_user,"SERVICE_PROFESSIONAL")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    professional_id=current_user.id
    
    if request.method=="POST": 
        conn = get_db_connection()
        professional = conn.execute(
            'SELECT * FROM users WHERE id = ? AND role = 1', (professional_id,)
        ).fetchone()

        if not professional:
            flash('Professional not found!', 'error')
            return redirect(url_for('admin_dashboard'))

        
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        service_name = request.form['service_name']
        experience = request.form['experience']
        address = request.form['address']
        pin_code = int(request.form['pin_code'])
        cv_file = request.files['cv']

        # Handle file upload for CV
        cv_path = professional['cv_path']
        if cv_file and cv_file.filename != '':
            cv_filename = f"{professional_id}_{cv_file.filename}"
            cv_path = os.path.join(app.config['UPLOAD_FOLDER'], cv_filename)
            cv_file.save(cv_path)
        # Update the professional's details in the database
        conn.execute(
            '''
            UPDATE users
            SET email = ?, username = ?, password = ?, service_name = ?, experience = ?,
                address = ?, pin_code = ?, cv_path = ?
            WHERE id = ? AND role = 1
            ''',
            (email, username, password, service_name, experience, address, pin_code, cv_path, professional_id)
        )
        conn.commit()
        conn.close()

        flash('Professional details updated successfully!', 'success')
        return redirect(url_for('edit_professional'))

    else:
        conn = get_db_connection()
        professional = conn.execute(
            'SELECT * FROM users WHERE id = ? AND role = 1', (professional_id,)
        ).fetchone()
        conn.close()
        
        
        if not professional:
            flash('Professional not found!', 'error')
            return redirect(url_for('professional_dashboard'))
        
        service_name=[]
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("select id, service_name from services")
            services = cursor.fetchall()
            service_name=[{"id":ele[0], "service_name":ele[1]} for ele in services]
        
        return render_template('professional_profile.html', professional=professional, service_name=service_name)


@app.route('/customer_dashboard/profile', methods=['GET', 'POST'])
@login_required
def edit_customer():
    if isAuthorized(current_user,"CUSTOMER")==False:
        abort(403)
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    customer_id=current_user.id
    
    if request.method=="POST": 
        conn = get_db_connection()
        customer = conn.execute(
            'SELECT * FROM users WHERE id = ? AND role = 2', (customer_id,)
        ).fetchone()

        if not customer:
            flash('Customer not found!', 'error')
            return redirect(url_for('customer_dashboard'))

        
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']
        pin_code = request.form['pin_code']

        # Update the professional's details in the database
        conn.execute(
            '''
            UPDATE users
            SET email = ?, username = ?, password = ?, 
                address = ?, pin_code = ?
            WHERE id = ? AND role = 2
            ''',
            (email, username, password, address, pin_code, customer_id)
        )
        conn.commit()
        conn.close()

        flash('Customer details updated successfully!', 'success')
        return redirect(url_for('edit_customer'))

    else:
        conn = get_db_connection()
        customer = conn.execute(
            'SELECT * FROM users WHERE id = ? AND role = 2', (customer_id,)
        ).fetchone()
        conn.close()
        
        
        if not customer:
            flash('Customer not found!', 'error')
            return redirect(url_for('customer_dashboard'))
        
        return render_template('customer_profile.html', customer=customer)
    

@app.route("/customer_dashboard/search", methods=["GET", "POST"])
@login_required
def search():
    if isBlocked(current_user):
        return render_template("blocked_page.html")
    if request.method=="POST":
        search_name=request.form['search_name']
        search_query=request.form['search_query']
        
        conn = get_db_connection()
        professional=[]
        if search_name=="pin_code":
            professional = conn.execute(
            """
            SELECT 
                u.id AS professional_id,
                u.username,
                u.email,
                u.address,
                u.pin_code,
                u.service_name,
                s.service_category,
                s.service_description,
                s.base_price,
                s.time_required,
                COALESCE(AVG(r.rating), 0) AS average_rating
            FROM users u
            JOIN services s ON u.service_name = s.service_name
            LEFT JOIN requests r ON u.id = r.professional_id
            WHERE u.role = 1  
            AND u.pin_code=?
            GROUP BY u.id, s.id;
            """,
                (int(search_query),)
            ).fetchall()
        
        elif search_name=="service_name":
            professional = conn.execute(
            """
            SELECT 
                u.id AS professional_id,
                u.username,
                u.email,
                u.address,
                u.pin_code,
                u.service_name,
                s.service_category,
                s.service_description,
                s.base_price,
                s.time_required,
                COALESCE(AVG(r.rating), 0) AS average_rating
            FROM users u
            JOIN services s ON u.service_name = s.service_name
            LEFT JOIN requests r ON u.id = r.professional_id
            WHERE u.role = 1  
            AND u.service_name like ?
            GROUP BY u.id, s.id;
            """,
                (f"{search_query}",)
            ).fetchall() 
        
        elif search_name=="address":
            professional = conn.execute(
            """
            SELECT 
                u.id AS professional_id,
                u.username,
                u.email,
                u.address,
                u.pin_code,
                u.service_name,
                s.service_category,
                s.service_description,
                s.base_price,
                s.time_required,
                COALESCE(AVG(r.rating), 0) AS average_rating
            FROM users u
            JOIN services s ON u.service_name = s.service_name
            LEFT JOIN requests r ON u.id = r.professional_id
            WHERE u.role = 1 
            AND u.address like ? 
            GROUP BY u.id, s.id;
            """,
                (f"{search_query}",)
            ).fetchall()
        
        conn.close()
        print(professional)
        for row in professional:
            print(row['service_name'])
        
        
        return render_template("customer_search.html", allData=professional)
        
    else:
        return render_template("customer_search.html")

# Function to fetch data from the database
def get_chart_data():
    conn = sqlite3.connect('database.db')  # Replace with your database file
    cursor = conn.cursor()

    # Query to fetch data for charts
    cursor.execute("""
        SELECT service_name, COUNT(*) AS request_count
        FROM requests
        JOIN services ON requests.service_id = services.id
        GROUP BY service_name
    """)
    data = cursor.fetchall()
    conn.close()

    # Extract labels and values
    labels = [row[0] for row in data]
    values = [row[1] for row in data]
    return labels, values

# Function to generate charts
def generate_charts(labels_role, values_role, labels_request, values_request):

    # Pie Chart
    pie_path = os.path.join(app.config['UPLOAD_CHART_FOLDER'], 'pie_chart.png')
    plt.figure(figsize=(6, 6))
    explode = [0.05 if values_request.count(v) > 1 else 0 for v in values_request]
    plt.pie(values_request, labels=labels_request, autopct=lambda p: f'{p:.1f}%' if p > 0 else '', startangle=140, colors=plt.cm.Paired.colors,labeldistance=1.2, pctdistance=0.8,explode=explode )
    plt.title("Requests Distribution by Service")
    plt.savefig(pie_path)
    plt.close()

    # Bar Chart
    bar_path = os.path.join(app.config['UPLOAD_CHART_FOLDER'], 'bar_chart.png')
    plt.figure(figsize=(8, 6))
    plt.bar(labels_role, values_role, color='skyblue')
    plt.xlabel('Service Names')
    plt.ylabel('Request Counts')
    plt.title('Request Counts by Service')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(bar_path)
    plt.close()

    return pie_path, bar_path


# Run the app

