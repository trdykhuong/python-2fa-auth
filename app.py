from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyotp
import qrcode
import io
import base64
from flask_bcrypt import Bcrypt
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash



app = Flask(__name__)
app.secret_key = 'your_secret_key'  
bcrypt = Bcrypt(app)

# Hàm mã hóa AES
def encrypt_data(data, key):
    if not isinstance(data, str):
        data = str(data)  # Dam bao la chuoi
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB) # Tao doi tuong AES 
    padded_data = pad(data.encode('utf-8'), AES.block_size)  # Pad() them cac byte bo sung  
    encrypted = cipher.encrypt(padded_data) # ma hoa
    return base64.b64encode(encrypted).decode('utf-8') # dang ma hoa base64

# Hàm giải mã AES
def decrypt_data(encrypted_data, key):
    if not isinstance(encrypted_data, str):
        raise ValueError("Dữ liệu mã hóa phải là chuỗi.") # kiem tra chuoi
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB) 
    decoded_data = base64.b64decode(encrypted_data) #giai ma base64
    decrypted = cipher.decrypt(decoded_data) #giai ma
    return unpad(decrypted, AES.block_size).decode('utf-8') # loai pad()

# Tạo database
def init_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    # Cập nhật bảng users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            otp_secret TEXT NOT NULL,
            otp_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Lưu thời gian thay đổi OTP       
            safe_mode INTEGER DEFAULT 0  
        )
    ''')

    # Cập nhật bảng passwords
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            description TEXT NOT NULL,          
            password TEXT NOT NULL,             
            encrypted_password INTEGER DEFAULT 1, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Tạo trigger để tự động cập nhật thời gian khi có thay đổi
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS update_password_timestamp
        AFTER UPDATE ON passwords
        FOR EACH ROW
        BEGIN
            UPDATE passwords
            SET updated_at = CURRENT_TIMESTAMP
            WHERE id = OLD.id;
        END;
    ''')

    # Tạo bảng backup_data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backup_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            backup_key TEXT NOT NULL UNIQUE, 
            backup_content TEXT NOT NULL, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

# Khởi tạo cơ sở dữ liệu
init_db()



def clean_database():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    
    cursor.execute('SELECT id, description, password FROM passwords')
    rows = cursor.fetchall()

    for row in rows:
        password_id, description, password = row
        if not isinstance(description, str) or not isinstance(password, str):
            print(f"Invalid data for ID {password_id}: {description}, {password}")
            cursor.execute(
                'UPDATE passwords SET description = ?, password = ? WHERE id = ?',
                ('Invalid', 'Invalid', password_id)
            )

    conn.commit()
    conn.close()

clean_database()
# Chào mừng người dùng
@app.route('/')
def index():
    return render_template('index.html')

#Đăng kí
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp_secret = pyotp.random_base32()  

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)',
                           (username, hashed_password, otp_secret))
            conn.commit()
            session['username'] = username
            session['otp_secret'] = otp_secret
            return redirect(url_for('show_qr'))
        except sqlite3.IntegrityError:
            flash('Tên đăng nhập đã tồn tại!', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

#Hiện mã QR
@app.route('/show_qr')
def show_qr():
    otp_secret = session.get('otp_secret') # lay khoa otp tu nguoi dung
    username = session.get('username')
    if not otp_secret or not username:
        return redirect(url_for('index'))

    # Tạo mã QR cho ứng dụng Google Authenticator
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(username, issuer_name="Password Manager") # tao doi tuong TOTP tu pyotp (tao OTP/thgian) - tạo chuoi chua tt can thiet de thiet lap 2FA
    img = qrcode.make(otp_uri) # tao ma QR tu chuoi URI
    buf = io.BytesIO() # tao bo nho dem luu tam anh QR
    img.save(buf, format='PNG') # luu anh vao bo nho dem
    qr_code = base64.b64encode(buf.getvalue()).decode('utf-8') # ma hoa noi dung anh QR sang base64, nhung vao html

    return render_template('show_qr.html', qr_code=qr_code, username=username)

#Đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp = request.form['otp']

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            hashed_password = user[2]  
            otp_secret = user[3]      

            # Kiểm tra mật khẩu có khớp không
            if bcrypt.check_password_hash(hashed_password, password):
                totp = pyotp.TOTP(otp_secret)

                # Xác thực OTP
                if totp.verify(otp):
                    session['user_id'] = user[0] 
                    session['username'] = user[1]
                    flash('Đăng nhập thành công!', 'success')
                    return redirect(url_for('password_manager'))
                else:
                    flash('Mã OTP không hợp lệ!', 'danger')
            else:
                flash('Mật khẩu không chính xác!', 'danger')
        else:
            flash('Người dùng không tồn tại!', 'danger')

    return render_template('login.html')


#Thêm mật khẩu
@app.route('/password_manager', methods=['GET', 'POST'])
def password_manager():
    user_id = session.get('user_id')
    username = session.get('username')
    key = "your_16_byte_key"  # Đảm bảo khóa AES là 16 ký tự

    if not user_id:
        flash("Vui lòng đăng nhập để truy cập trang này.", "danger")
        return redirect(url_for('login'))

    try:
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()

        if request.method == 'POST':
            description = request.form['description']
            password = request.form['password']

            if not description.strip() or not password.strip():
                flash("Mô tả và mật khẩu không được để trống.", "danger")
            else:
                # Mã hóa description và password
                encrypted_description = encrypt_data(description.strip(), key)
                encrypted_password = encrypt_data(password.strip(), key)
                cursor.execute(
                    'INSERT INTO passwords (user_id, description, password) VALUES (?, ?, ?)',
                    (user_id, encrypted_description, encrypted_password)
                )
                conn.commit()
                flash('Đã thêm mật khẩu mới!', 'success')

        # Lấy danh sách mật khẩu của người dùng
        cursor.execute('SELECT id, description, password FROM passwords WHERE user_id = ?', (user_id,))
        passwords = cursor.fetchall()

        # Kiểm tra chế độ an toàn (Safe Mode)
        cursor.execute('SELECT safe_mode FROM users WHERE id = ?', (user_id,))
        safe_mode = cursor.fetchone()[0]
        session['safe_mode'] = safe_mode  # Đồng bộ với session

        if safe_mode:
            
            passwords = [
        (pwd[0], decrypt_data(pwd[1], key), '********') for pwd in passwords
            ]
        else:

            passwords = [
        (pwd[0], decrypt_data(pwd[1], key), decrypt_data(pwd[2], key)) for pwd in passwords
            ]

    except ValueError as e:
        flash(f"Lỗi giải mã dữ liệu: {e}", "danger")
        passwords = []
    except sqlite3.Error as e:
        flash(f"Lỗi cơ sở dữ liệu: {e}", "danger")
        passwords = []
    finally:
        conn.close()

    return render_template('password_manager.html', passwords=passwords, safe_mode=safe_mode, username=username)

#Xóa mật khẩu
@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (id, user_id))
    conn.commit()
    conn.close()
    flash('Đã xóa mật khẩu!', 'success')

    return redirect(url_for('password_manager'))

#Sửa mật khẩu
@app.route('/update_password/<int:id>', methods=['GET', 'POST'])
def update_password(id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        new_password = request.form['password']
        cursor.execute('UPDATE passwords SET password = ? WHERE id = ? AND user_id = ?', (new_password, id, user_id))
        conn.commit()
        flash('Đã cập nhật mật khẩu!', 'success')
        return redirect(url_for('password_manager'))

    cursor.execute('SELECT * FROM passwords WHERE id = ? AND user_id = ?', (id, user_id))
    password = cursor.fetchone()
    conn.close()

    if not password:
        flash('Mật khẩu không tồn tại!', 'danger')
        return redirect(url_for('password_manager'))

    return render_template('update_password.html', password=password)

#Quên mật khẩu
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        otp = request.form['otp']
        new_password = request.form['new_password']

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            otp_secret = user[3]
            totp = pyotp.TOTP(otp_secret)
            if totp.verify(otp):  # Xác thực OTP
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

                conn = sqlite3.connect('passwords.db')
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
                conn.commit()
                conn.close()

                flash('Mật khẩu đã được cập nhật!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Mã OTP không hợp lệ!', 'danger')
        else:
            flash('Tên người dùng không tồn tại!', 'danger')

    return render_template('forgot_password.html')

# Đổi mật khẩu
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    user_id = session.get('user_id')
    if not user_id:
        flash("Vui lòng đăng nhập để tiếp tục.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Mật khẩu mới không khớp!", "danger")
            return redirect(url_for('change_password'))

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[0], current_password):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
            conn.commit()
            conn.close()
            flash("Mật khẩu đã được thay đổi thành công!", "success")
            return redirect(url_for('password_manager'))
        else:
            flash("Mật khẩu hiện tại không chính xác!", "danger")

    return render_template('change_password.html')

  
# Safe-mode
@app.route('/toggle_safe_mode', methods=['GET', 'POST'])
def toggle_safe_mode():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form.get('otp')

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT otp_secret, safe_mode FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if user:
            otp_secret = user[0]
            current_safe_mode = user[1]  
            totp = pyotp.TOTP(otp_secret)

            # Xác thực OTP
            if totp.verify(otp):
                new_safe_mode = not current_safe_mode
                cursor.execute('UPDATE users SET safe_mode = ? WHERE id = ?', (new_safe_mode, user_id))
                conn.commit()
                session['safe_mode'] = new_safe_mode  # Cập nhật vào session
                flash('Chế độ an toàn đã được cập nhật!', 'success')
            else:
                flash('Mã OTP không hợp lệ!', 'danger')
        else:
            flash('Không tìm thấy người dùng!', 'danger')

        conn.close()
        return redirect(url_for('password_manager'))

    return render_template('toggle_safe_mode.html')

# Thay đổi thiết bị
@app.route('/change_device', methods=['GET', 'POST'])
def change_device():
    user_id = session.get('user_id')
    if not user_id:
        flash("Vui lòng đăng nhập để thực hiện thao tác này.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        otp = request.form['otp']

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password, otp_secret FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            flash("Không tìm thấy người dùng.", "danger")
            return redirect(url_for('change_device'))

        hashed_password, current_otp_secret = user
        totp = pyotp.TOTP(current_otp_secret)

        # Xác thực mật khẩu và OTP hiện tại
        if bcrypt.check_password_hash(hashed_password, password) and totp.verify(otp):
            # Tạo mã OTP mới
            new_otp_secret = pyotp.random_base32()

            # Cập nhật vào cơ sở dữ liệu
            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET otp_secret = ?, otp_updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                (new_otp_secret, user_id)
            )
            conn.commit()
            conn.close()

            # Tạo mã QR mới
            otp_uri = pyotp.TOTP(new_otp_secret).provisioning_uri(
                session.get('username'), issuer_name="Password Manager"
            )
            img = qrcode.make(otp_uri)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            qr_code = base64.b64encode(buf.getvalue()).decode('utf-8')

            flash("Thay đổi thiết bị thành công!", "success")
            return render_template('show_newQR.html', qr_code=qr_code)

        else:
            flash("Mật khẩu hoặc mã OTP không chính xác.", "danger")

    return render_template('change_device.html')

# Mất thiết bị
@app.route('/recover_device', methods=['GET', 'POST'])
def recover_device():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            hashed_password = user[2]
            otp_secret = user[3]

            # Kiểm tra mật khẩu có khớp không
            if bcrypt.check_password_hash(hashed_password, password):
                # Tạo mã QR mới
                otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(username, issuer_name="Password Manager")
                img = qrcode.make(otp_uri)
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                qr_code = base64.b64encode(buf.getvalue()).decode('utf-8')

                flash('Vui lòng quét mã QR để tiếp tục.', 'success')
                return render_template('recovery_qr.html', qr_code=qr_code)
            else:
                flash('Mật khẩu không chính xác!', 'danger')
        else:
            flash('Tên đăng nhập không tồn tại!', 'danger')
        return redirect(url_for('recover_device'))

    return render_template('forgot_device.html')


# Sao lưu dữ liệu
def generate_backup_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

@app.route('/backup_data', methods=['GET', 'POST'])
def backup_data():
    user_id = session.get('user_id')
    if not user_id:
        flash("Vui lòng đăng nhập để sử dụng tính năng này.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash("Vui lòng nhập mã OTP.", "danger")
            return redirect(url_for('backup_data'))

        # Kiểm tra mã OTP
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT otp_secret FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            flash("Người dùng không tồn tại.", "danger")
            return redirect(url_for('login'))

        otp_secret = user[0]
        totp = pyotp.TOTP(otp_secret)

        if not totp.verify(otp):
            flash("Mã OTP không hợp lệ.", "danger")
            return redirect(url_for('backup_data'))

        # Thực hiện sao lưu nếu mã OTP hợp lệ
        try:
            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()

            # Lấy dữ liệu mật khẩu của người dùng
            cursor.execute('SELECT description, password FROM passwords WHERE user_id = ?', (user_id,))
            passwords = cursor.fetchall()
            if not passwords:
                flash("Không có dữ liệu để sao lưu.", "info")
                return redirect(url_for('password_manager'))

            # Sinh khóa backup
            backup_key = generate_backup_key()
            hashed_backup_key = generate_password_hash(backup_key)
            # Mã hóa nội dung sao lưu
            backup_content = encrypt_data(str(passwords), backup_key)

            # Lưu dữ liệu sao lưu vào DB
            cursor.execute(
            'INSERT INTO backup_data (user_id, backup_key, backup_content) VALUES (?, ?, ?)',
            (user_id, hashed_backup_key, backup_content)
            )

            conn.commit()

            # Lưu khóa backup vào session để hiển thị
            session['backup_key'] = backup_key
            return redirect(url_for('show_backup_key'))
        except Exception as e:
            flash(f"Lỗi sao lưu dữ liệu: {e}", "danger")
        finally:
            conn.close()

    return render_template('backup_data.html')


# Hiện key sao lưu 
@app.route('/show_backup_key')
def show_backup_key():
    user_id = session.get('user_id')
    if not user_id:
        flash("Vui lòng đăng nhập để sử dụng tính năng này.", "danger")
        return redirect(url_for('login'))

    backup_key = session.get('backup_key')

    try:
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()

        # Lấy danh sách các bản sao lưu đã tạo
        cursor.execute('SELECT id, backup_content FROM backup_data WHERE user_id = ?', (user_id,))
        backups = cursor.fetchall()
    except Exception as e:
        flash(f"Lỗi khi tải danh sách backup: {e}", "danger")
        backups = []
    finally:
        conn.close()

    return render_template('show_backup_key.html', backup_key=backup_key, backups=backups)


@app.route('/delete_backup/<int:backup_id>', methods=['POST'])
def delete_backup(backup_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Vui lòng đăng nhập để sử dụng tính năng này.", "danger")
        return redirect(url_for('login'))

    try:
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()

        # Xóa backup từ cơ sở dữ liệu
        cursor.execute('DELETE FROM backup_data WHERE id = ? AND user_id = ?', (backup_id, user_id))
        conn.commit()
        flash("Đã xóa bản sao lưu thành công.", "success")
    except Exception as e:
        flash(f"Lỗi khi xóa bản sao lưu: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for('show_backup_key'))


# Hàm xử lý logic khôi phục dữ liệu
@app.route('/recover_data', methods=['GET', 'POST'])
def recover_data():
    new_user_id = session.get('user_id')
    if not new_user_id:
        flash("Vui lòng đăng nhập để sử dụng tính năng này.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_username = request.form['old_username']
        backup_key = request.form['backup_key']

        try:
            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()

            # Lấy user_id của tài khoản cũ
            cursor.execute('SELECT id FROM users WHERE username = ?', (old_username,))
            old_user = cursor.fetchone()

            if not old_user:
                flash("Không tìm thấy tài khoản cũ.", "danger")
                return redirect(url_for('password_manager'))

            old_user_id = old_user[0]

            # Lấy dữ liệu backup
            cursor.execute(
                'SELECT backup_content FROM backup_data WHERE user_id = ?',
                (old_user_id,)
            )
            backup = cursor.fetchone()

            if not backup:
                flash("Khóa backup hoặc tài khoản không hợp lệ.", "danger")
                return redirect(url_for('password_manager'))

            encrypted_content = backup[0]

            # Giải mã dữ liệu
            decrypted_data = decrypt_data(encrypted_content, backup_key)
            passwords = eval(decrypted_data)  # Chuyển chuỗi thành danh sách

            # Thêm dữ liệu vào tài khoản mới
            for description, password in passwords:
                cursor.execute(
                    'INSERT INTO passwords (user_id, description, password) VALUES (?, ?, ?)',
                    (new_user_id, description, password)
                )
            conn.commit()

            flash("Khôi phục dữ liệu thành công!", "success")
        except Exception as e:
            flash(f"Lỗi khi khôi phục dữ liệu: {e}", "danger")
        finally:
            conn.close()

        return redirect(url_for('password_manager'))

    
    return render_template('recover_data.html')


# Đăng xuất
@app.route('/logout')
def logout():
    session.clear()  # Xóa toàn bộ session
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)


