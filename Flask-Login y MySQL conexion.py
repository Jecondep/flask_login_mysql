from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import User
from conexion.conexion import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'  # Cambia por una clave segura

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route('/')
def home():
    return "Página pública"

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Hola {current_user.nombre}, esta es una página protegida."

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']

        if User.get_by_email(email):
            flash('El email ya está registrado')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO usuarios (nombre, email, password) VALUES (%s, %s, %s)",
                       (nombre, email, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Usuario registrado correctamente. Por favor inicia sesión.')
        return redirect(url_for('login'))

    return '''
    <form method="post">
        Nombre: <input type="text" name="nombre" required><br>
        Email: <input type="email" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Registrar">
    </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.get_by_email(email)
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Has iniciado sesión correctamente')
            return redirect(url_for('dashboard'))
        else:
            flash('Email o contraseña incorrectos')
            return redirect(url_for('login'))

    return '''
    <form method="post">
        Email: <input type="email" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Iniciar sesión">
    </form>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
