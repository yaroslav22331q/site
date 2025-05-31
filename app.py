from flask import Flask, render_template, request, redirect, session
import sqlite3
import html
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret'
DATABASE = 'database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                score INTEGER DEFAULT 0
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        db.commit()

@app.route('/')
def home():
    db = get_db()
    comments = db.execute('''
        SELECT comments.content, users.username
        FROM comments JOIN users ON comments.user_id = users.id
    ''').fetchall()
    user = session.get('user')
    return render_template('home.html', comments=comments, user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (
                request.form['username'],
                generate_password_hash(request.form['password'])
            ))
            db.commit()
            return redirect('/login')
        except:
            return 'Користувач уже існує!'
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (request.form['username'],)).fetchone()
        if user and check_password_hash(user['password'], request.form['password']):
            session['user'] = user['username']
            return redirect('/')
        return "Невірний логін або пароль"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/comment', methods=['POST'])
def comment():
    if 'user' not in session:
        return redirect('/login')
    db = get_db()
    user = db.execute('SELECT id FROM users WHERE username = ?', (session['user'],)).fetchone()
    safe_content = html.escape(request.form['content'])
    db.execute('INSERT INTO comments (user_id, content) VALUES (?, ?)', (user['id'], safe_content))
    db.execute('UPDATE users SET score = score + 1 WHERE id = ?', (user['id'],))
    db.commit()
    return redirect('/')

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    all_users = db.execute('SELECT username FROM users WHERE username != ?', (session['user'],)).fetchall()
    return render_template('profile.html', user=user, all_users=all_users)

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user' not in session:
        return redirect('/login')
    sender = session['user']
    receiver = request.form['receiver']
    amount = int(request.form['amount'])

    db = get_db()
    sender_data = db.execute('SELECT * FROM users WHERE username = ?', (sender,)).fetchone()
    receiver_data = db.execute('SELECT * FROM users WHERE username = ?', (receiver,)).fetchone()

    if sender_data['score'] < amount:
        return "Недостатньо балів"
    if sender == receiver:
        return "Не можна надсилати бали самому собі"

    db.execute('UPDATE users SET score = score - ? WHERE username = ?', (amount, sender))
    db.execute('UPDATE users SET score = score + ? WHERE username = ?', (amount, receiver))
    db.commit()
    return redirect('/profile')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
