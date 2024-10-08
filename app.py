from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import mysql.connector
import bcrypt
import os
from io import BytesIO
import paramiko  # For secure SFTP connections
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
load_dotenv()


# For debugging purposes only
print("Environment Variables:")
print(f"SECRET_KEY: {os.environ.get('SECRET_KEY', 'Not Set')}")
print(f"DB_HOST: {os.environ.get('DB_HOST', 'Not Set')}")
print(f"DB_USER: {os.environ.get('DB_USER', 'Not Set')}")
print(f"DB_PASSWORD: {'****' if os.environ.get('DB_PASSWORD') else 'Not Set'}")  # Hide actual password
print(f"DB_NAME: {os.environ.get('DB_NAME', 'Not Set')}")
print(f"FTP_HOST: {os.environ.get('FTP_HOST', 'Not Set')}")
print(f"FTP_USER: {os.environ.get('FTP_USER', 'Not Set')}")
print(f"FTP_PASSWORD: {'****' if os.environ.get('FTP_PASSWORD') else 'Not Set'}")  # Hide actual password



app = Flask(__name__)

# Use the secret key from environment variable
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# Configure session security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',  # Ensure your app is served over HTTPS in production
    SESSION_COOKIE_SAMESITE='Lax'
)

def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host=os.environ.get('DB_HOST'),
            user=os.environ.get('DB_USER'),
            password=os.environ.get('DB_PASSWORD'),
            database=os.environ.get('DB_NAME')
            # Optionally add SSL parameters here if available
        )
        return connection
    except mysql.connector.Error as err:
        app.logger.error(f"Error connecting to the database: {err}")
        return None

def authenticate_user(username, password):
    connection = connect_to_database()
    if connection is None:
        app.logger.error("Database connection failed.")
        return None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT rowid, pass_crypted FROM llx_user WHERE login = %s", (username,))
        user = cursor.fetchone()
    except mysql.connector.Error as err:
        app.logger.error(f"Error querying the database: {err}")
        return None
    finally:
        if connection.is_connected():
            connection.close()

    if user:
        rowid, pass_crypted = user['rowid'], user['pass_crypted']
        app.logger.debug(f"User found: {username}, rowid: {rowid}")
        # Check the password using bcrypt
        if bcrypt.checkpw(password.encode('utf-8'), pass_crypted.encode('utf-8')):
            app.logger.debug("Password match.")
            return rowid
        else:
            app.logger.debug("Password does not match.")
    else:
        app.logger.debug(f"No user found with username: {username}")
    return None

def fetch_documents_by_lastname(lastname):
    connection = connect_to_database()
    if connection is None:
        return None

    try:
        cursor = connection.cursor(dictionary=True)
        sql = """
            SELECT ecm.filename, ecm.filepath, ecm.fullpath_orig, ecm.description, ecm.date_c, ecm.fk_user_c
            FROM llx_ecm_files AS ecm
            JOIN llx_socpeople AS sp ON sp.rowid = ecm.src_object_id
            WHERE ecm.src_object_type = 'socpeople' AND sp.lastname = %s
        """
        cursor.execute(sql, (lastname,))
        documents = cursor.fetchall()
    finally:
        connection.close()

    # Add download URL to each document
    for document in documents:
        document['download_url'] = url_for('download_document', filepath=document['filepath'], filename=document['filename'])

    return documents

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = authenticate_user(username, password)
        if user_id:
            session['user_id'] = user_id
            session['username'] = username
            return redirect(url_for('documents'))
        else:
            flash('Nom d\'utilisateur ou mot de passe invalide.')
            return render_template('login.html', error='Nom d\'utilisateur ou mot de passe invalide.')
    return render_template('login.html')

@app.route('/documents')
def documents():
    if 'user_id' not in session:
        print("User not logged in, redirecting to login.")
        return redirect(url_for('login'))
    
    username = session.get('username')
    print(f"User {username} is logged in, fetching documents.")
    documents = fetch_documents_by_lastname(username)
    print(f"Documents: {documents}")
    return render_template('documents.html', documents=documents)


@app.route('/download/<path:filepath>/<filename>')
def download_document(filepath, filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Secure the filename and filepath to prevent directory traversal attacks
    filename = secure_filename(filename)
    filepath = secure_filename(filepath)

    ftp_host = os.environ.get('FTP_HOST')
    ftp_user = os.environ.get('FTP_USER')
    ftp_pass = os.environ.get('FTP_PASSWORD')

    # Use SFTP (secure FTP) instead of FTP
    try:
        transport = paramiko.Transport((ftp_host, 22))
        transport.connect(username=ftp_user, password=ftp_pass)
        sftp = paramiko.SFTPClient.from_transport(transport)

        # Construct the full path using the /documents directory
        full_path = os.path.join('/documents', filepath, filename)
        app.logger.debug(f"Attempting to retrieve file from SFTP: {full_path}")  # Debugging statement

        bio = BytesIO()
        sftp.getfo(full_path, bio)
    except Exception as e:
        app.logger.error(f"Error retrieving file: {e}")  # Logging error
    finally:
        if 'sftp' in locals() and sftp:
            sftp.close()
        if 'transport' in locals() and transport:
            transport.close()
            transport.close()

    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=filename)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
