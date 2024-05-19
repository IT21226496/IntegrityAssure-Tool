import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import requests
from PIL import Image, ImageTk
import sqlite3
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
import re
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime

class SoftwareIntegrityChecker:
    def __init__(self, master):
        self.master = master
        master.title("IntegrityAssure 1.0")
        master.geometry("800x600")
        
        # Set background color
        self.bg_color = "#F0F0F0"  # Light gray
        
        # Configure main frame
        self.main_frame = tk.Frame(master, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Set background image
        image = Image.open("D:\\SLIIT\\Modules\\YEAR 3\\SEMESTER 2\\ISP\\sss\\logo7.png")  # Background image
        image = image.resize((800, 600), Image.LANCZOS)
        self.background_image = ImageTk.PhotoImage(image)
        self.background_label = tk.Label(self.main_frame, image=self.background_image)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Introduction Label
        self.intro_label = ttk.Label(self.main_frame, text="IntegrityAssure 1.0", font=('Arial', 28, 'bold'),foreground="#008631",background="#83f28f")
        self.intro_label.pack(pady=(50, 20))
        
        messagebox.showinfo("Welcome to IntegrityAssure","IntegrityAssure is a robust software integrity checking tool designed to safeguard your devices from potential threats. With IntegrityAssure, you can verify the integrity and legitimacy of the software, ensuring that it is free of harmful trojans and malwares.\n\n Key Features:\n\n 1. User Authentication: Securely register and login to the platform to access its functionalities.\n\n2. File Integrity Checks: Verify the integrity of your software applications by comprehensive scanning.\n\n 3.Password Security: Ensure password strength and security with built-in checks for common passwords.\n")
        
        messagebox.showinfo("Steps","Follow these simple steps to find the legitimacy of software:\n1. Register/Login\n2. Select File\n3. Stay Secure\n\nEnsure the integrity of your software with IntegrityAssure 1.0!")

        # Username and Password Entry
        self.username_label = ttk.Label(self.main_frame, text="Username:", font=('Arial',16),foreground="#008631",background=self.bg_color)
        self.username_label.pack()
        self.username_entry = ttk.Entry(self.main_frame, font=('Arial', 12))
        self.username_entry.pack(pady=5)

        self.password_label = ttk.Label(self.main_frame, text="Password:", font=('Arial',16),foreground="#008631",background=self.bg_color)
        self.password_label.pack()
        self.password_entry = ttk.Entry(self.main_frame, show='*', font=('Arial', 12))
        self.password_entry.pack(pady=5)

        # Register and Login Buttons
        self.register_button = ttk.Button(self.main_frame, text="Register", command=self.register_user, style="Custom.TButton")
        self.register_button.pack(pady=10)

        self.login_button = ttk.Button(self.main_frame, text="Login", command=self.authenticate_user, style="Custom.TButton")
        self.login_button.pack(pady=10)

        # Select File Button (hidden until login)
        self.select_file_button = ttk.Button(self.main_frame, text="Select File", command=self.browse_file, style="Custom.TButton")
        self.select_file_button.pack(pady=20)
        self.select_file_button.pack_forget()  # Hide initially

        # Custom Styles
        self.style = ttk.Style()
        self.style.configure("Custom.TButton", font=('Arial', 14, 'bold'), background="#008631", foreground="#008631", width=20)

        # Initialize database
        self.initialize_database()

        # Load the common passwords dataset and train the machine learning model
        self.train_model()

    def initialize_database(self):
        # Connect to the SQLite database
        self.conn = sqlite3.connect('software_integrity.db')
        self.cur = self.conn.cursor()

        # Create tables if not exists
        self.cur.execute('''CREATE TABLE IF NOT EXISTS user
                     (id INTEGER PRIMARY KEY,
                      username TEXT NOT NULL,
                      password TEXT NOT NULL)''')
        
        self.cur.execute('''CREATE TABLE IF NOT EXISTS file
                     (id INTEGER PRIMARY KEY,
                      file_name TEXT NOT NULL,
                      hash_value TEXT NOT NULL)''')
        
        # Initial software hash values (replace these with your actual hash values)
        software_hashes = [
            (r"CiscoPacketTracer822_64bit_setup_signed (1).exe", "1aa1094bfa611c955c2e2885aea3bc8685211c95b55de017242fd0d38eb7cab1"),
            (r"ZoomInstallerFull.exe", "7afe9e45f6abdd65857da90a3233018582ad513519517b52e09b2fd206405471"),
            (r"VSCodeUserSetup-x64-1.82.0.exe", "75bf6e941390d95a64bb34b60a4623557fd197d7a438c703a5ac1b07efe44955"),
            (r"OpenOffice.exe", "B7A979F574A053763BAFB42D4CBBF8542EB9F37CF8DC5125909E303B90CE5137"),
            (r"VirtualBox-7.0.14-161095-Win.exe", "4719b38e7a276b43099ce4d6349e6bfc80edf644ee59d9dafd264bc7ed7691f4"),
            (r"genymotion-3.6.0.exe", "fb8f02459cb5ef092b23ec44ba1fce797a5672e00d57ecf6eda13cf92317a02f"),
            (r"RStudio-2023.12.1-402.exe", "d3c03c42a42c9b5cd4f3d72a0cfc0859f0099b8199af842da762b0584ab4bea0"),
            (r"jdk-20_windows-x64_bin.exe", "ef40941f1b54b52747d98330ca845374bccb8e3635fc7f647f60405cf51eb17f"),
            (r"ChromeSetup.exe", "ACFA79180B59B5314ACEFC151F1982F6DD648599591069B6B4E070CB72AF484C"),
            (r"WhatsApp.exe", "AF7D0EA2DF7A7FDAF0715B61FEBA81C49ED157FE70ADC7140D7FAAB600FBCA39"),
            (r"Kaspersky.exe", "0d4c7158ce7eb2eb0c8966c1c799da1ed1da62878bf2e6b5e2b7f282ea8d8018"),
            (r"Wireshark.exe", "e641193fa2fceca701553b91a36524b39cf965137b957f9f7c8d8149e28ebdb0"),
            (r"Word.exe", "7e3174f5a16b2cdc48bb5991209d5429dd20cc7804358cf6bbb938e32f9e3488"),
            (r"Notepad++.exe", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            
        ]

        # Insert initial software hash values into the database
        self.cur.executemany("INSERT INTO file (file_name, hash_value) VALUES (?, ?)", software_hashes)

        # Commit changes
        self.conn.commit()
        
         #Initialize user and login time attributes
        self.logged_in_user = None  
        self.login_time = None      

    def train_model(self):
        # Load the common passwords dataset from a CSV file
        common_passwords_df = pd.read_csv("D:\SLIIT\Modules\YEAR 3\SEMESTER 2\ISP\SSS\common_passwords.csv")  # Adjust the path as needed
        
        # In this case, we'll consider all passwords common, as there is no 'common' column
        # Therefore, we need to create a 'common' column and assign it a value of 1 for all rows
        common_passwords_df['common'] = 1
        
        # Split the dataset into features (passwords) and target variable (common or not)
        X = common_passwords_df.drop(columns=['password'])  

        y = common_passwords_df['password']
        
        # Split the dataset into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Initialize and train the RandomForestClassifier model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Check if username already exists
        self.cur.execute("SELECT * FROM user WHERE username = ?", (username,))
        if self.cur.fetchone():
            messagebox.showerror("Error", "Username already exists. Please choose a different username.")
            return

        # Check if password is common
        if self.is_password_common(password):
            messagebox.showwarning("Warning", "Common password detected. Please choose a stronger password.")
            return

        # Password policy regex
        # Minimum 6 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character
        password_policy_regex = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$"

        # Validate password against the policy
        if not re.match(password_policy_regex, password):
            messagebox.showerror("Error", "Password must contain at least 6 characters, including one uppercase letter, one lowercase letter, one digit, and one special character.")
            return

        # Insert new user into the database
        self.cur.execute("INSERT INTO user (username, password) VALUES (?, ?)", (username, password))
        self.conn.commit()
        messagebox.showinfo("Success", "User registered successfully.")
   
    def is_password_common(self, password):
        # Load the common passwords dataset from a CSV file
        common_passwords_df = pd.read_csv("D:\SLIIT\Modules\YEAR 3\SEMESTER 2\ISP\SSS\common_passwords.csv")  # Adjust the path as needed
    
        # Check if the entered password is in the common passwords dataset
        if password in common_passwords_df['password'].values:
            return True
        else:
            return False


    def authenticate_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        self.cur.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = self.cur.fetchone()
        
        if user:
            messagebox.showinfo("Success", "Login successful!")
            self.logged_in_user = username
            self.login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.select_file_button.pack(pady=20)  # Show the Select File button upon successful login
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.verify_file(file_path)

    def verify_file(self, file_path):
        # Calculate the file's hash
        hash_value = self.calculate_file_hash(file_path)

        # Check if the hash value exists in the database
        self.cur.execute("SELECT * FROM file WHERE hash_value = ?", (hash_value,))
        result = self.cur.fetchone()

        if result:
            messagebox.showinfo("Integrity Check", "The Software is legitimate and matches the hash value in the database.")
            # Prompt to save the report
            save_report = messagebox.askyesno("Save Report", "Do you want to save the test results in a PDF report?")
            if save_report:
                self.save_pdf_report(file_path, hash_value, "Legitimate")
        else:
            # If not in the local database, check with VirusTotal
            verdict = self.check_with_virustotal(hash_value)
            if verdict == "clean":
                messagebox.showinfo("Integrity Check", "The Software not found in the database and proceed to scan with VirusTotal!")
                messagebox.showinfo("VirusTotal Scan", "The Software is clean according to VirusTotal.")
                # Insert hash value into the database
                self.cur.execute('''INSERT INTO file (file_name, hash_value) VALUES (?, ?)''', (os.path.basename(file_path), hash_value))
                self.conn.commit()

            elif verdict == "malicious":
                messagebox.showwarning("VirusTotal Scan", "The file is detected as malicious by VirusTotal.")
            else:
                messagebox.showerror("VirusTotal Scan", "The file could not be verified with VirusTotal.")
            
            # Prompt to save the report
            save_report = messagebox.askyesno("Save Report", "Do you want to save the test results in a PDF report?")
            if save_report:
                self.save_pdf_report(file_path, hash_value, verdict)

    def calculate_file_hash(self, file_path, algorithm='sha256'):
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def check_with_virustotal(self, hash_value):
       api_key = "#################################################"  
       url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
       headers = {
            "x-apikey": api_key
        }

       response = requests.get(url, headers=headers)
       if response.status_code == 200:
            json_response = response.json()
            # Parse the JSON response to determine if the file is clean or malicious
            if 'data' in json_response and 'attributes' in json_response['data']:
                last_analysis_stats = json_response['data']['attributes']['last_analysis_stats']
                if last_analysis_stats['malicious'] > 0:
                    return "malicious"
                else:
                    return "clean"
            else:
                return "unknown"
       else:
            return "unknown"

    def save_pdf_report(self, file_path, hash_value, verdict):
        file_name = os.path.basename(file_path)
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Prepare data for the table
        data = [
            ["Username", self.logged_in_user],
            ["Login Time", self.login_time],
            ["File Name", file_name],
            ["File Path", file_path],
            ["Hash Value", hash_value],
            ["Scan Date", scan_date],
            ["Verdict", verdict]
       
        ]

        # Create PDF document
        pdf_file = f"{self.logged_in_user}_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        document = SimpleDocTemplate(pdf_file, pagesize=letter)

        # Define table style
        style = getSampleStyleSheet()
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ])

        # Create and style the table
        table = Table(data)
        table.setStyle(table_style)

        # Build the PDF
        elements = [Paragraph("File Integrity Check Report", style['Title']), table]
        document.build(elements)

        messagebox.showinfo("Report Saved", f"The PDF report has been saved as {pdf_file}")


# Main application
root = tk.Tk()
app = SoftwareIntegrityChecker(root)
root.mainloop()
