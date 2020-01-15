import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from importlib import reload

from helpers import apology, login_required, lookup, usd
from flask_moment import Moment
from momentjs import momentjs


os.chdir("C:\\Users\\HP PC\\Desktop\\Py\\src8\\finance")
# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded, config acts like some sort of dictionary value with Key-value pairs that represent what you want to do. In this case, the key is assigned a value of True to ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Set jinja template global
# app.jinja_env.globals["momentjs"] = momentjs

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///C:\\Users\\HP PC\\Desktop\\Py\\src8\\finance\\finance.db")
# db = sqlite3.connect('finance.db', check_same_thread=False)
# cur = db.cursor()

moment = Moment(app)


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks."""

    cash_row = db.execute("SELECT * FROM users WHERE id = :user_id", user_id = session["user_id"])

    price_row = db.execute("SELECT * FROM transactions WHERE user_id = :user_id", user_id = session['user_id'])

    rows = db.execute("SELECT * FROM portfolio WHERE user_id = :user_id ORDER BY symbol ASC", user_id = session["user_id"])

    portfolio = []

    for data in rows:
        portfolio_dict = {
				"symbol": data["symbol"],
				"shares": data["shares"],
				"total": data['TOTAL'] 
				}
        portfolio.append(portfolio_dict)

    for i in price_row:
        price_dict = {
				"price": i['price']
				}
        portfolio.append(price_dict)

    cash = float(cash_row[0]['cash'])
    cash_col = db.execute("SELECT cash, id FROM users WHERE id = 2")
    init_cash = int(cash_col[0]['cash'])

    return render_template("index.html", portfolio=portfolio, cash=cash, init_cash = init_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock."""	
# Confirm that the user was routed via POST
    if request.method == 'POST':
		#Assign the value of the lookup function's symbol argument (API call)
        stock = lookup(request.form.get('symbol'))

        if stock is None:
            flash('Invalid ticker symbol')

# Shares is assigned the value of the "shares" input in buy.html
        try:
            shares = int(request.form.get('shares'))
        except TypeError:
            flash('Shares must be a number')

        if shares < 0:
            flash('Must be positive number')

# Extract the cash column from the users table where the session id matches the id on the database 
        rows = db.execute('SELECT cash, username FROM users WHERE id = :user_id', user_id = session['user_id'])
		# Cash available to user is the user's cash value
        available_cash = rows[0]['cash']

		# price is assigned the value of stock's price key 
        price = stock['price']
        total_price = shares * price

        if available_cash < total_price:
            return apology("Insufficient funds")

        updated_rows = db.execute("UPDATE users SET cash = cash - :total_price WHERE id = :user_id", total_price = total_price, user_id = session['user_id'])

        #rows = db.execute("SELECT * FROM transactions WHERE user_id = :user_id", user_id = session["user_id"]) 

        db.execute("INSERT INTO 'transactions'(user_id, symbol, shares, price, status) VALUES (:user_id, :symbol, :shares, :price, :status)", user_id=session['user_id'], symbol = request.form.get('symbol'), shares = shares, price = price, status="BOUGHT")

		# Check if user has already bought stock from company by checking for the stock symbol in the user portfolio database
        exists = db.execute("SELECT symbol, name FROM portfolio WHERE user_id = :user_id AND (symbol = :symbol)", user_id = session['user_id'], symbol = request.form.get('symbol'))

        if len(exists) == 0:
            db.execute("INSERT INTO 'portfolio' (user_id, symbol, shares, name) VALUES(:user_id, :symbol, :shares, :name)", user_id = session["user_id"], symbol = request.form.get('symbol'), shares = shares, name = session['username'])

        else:
            db.execute("UPDATE portfolio SET shares = shares + :shares WHERE user_id = :user_id AND (symbol = :symbol)", shares = shares, user_id = session['user_id'], symbol = request.form.get('symbol'))

        db.execute("UPDATE portfolio SET 'TOTAL' = (SELECT sum(price * shares) from transactions WHERE user_id = :user_id AND symbol = :symbol) WHERE user_id = :user_id AND symbol = :symbol", user_id = session['user_id'], symbol = request.form.get('symbol'))

        flash("BOUGHT")

        #updated_cash = updated_rows[0]["cash"]

        return redirect("/")

    else:
        return render_template('buy.html')


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
	# Query database for username
    #rows = db.execute("SELECT * FROM users WHERE username = :username",                   username=request.form.get("username"))
    rows = db.execute("SELECT username from users")

    for row in rows:
        if request.form.get("username") == row[0]['username']:
            response = jsonify(False)
        else:
            flash("Available")
            response = jsonify(True)
            return redirect("/")

    return jsonify(response)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM transactions WHERE user_id = :user_id ORDER BY timestamp DESC", user_id = session["user_id"])
# Create list to store everything
    transactions = []

    for history in rows:
        hist_dict = {
		   "transaction": "BOUGHT" if history['status'] == 'BOUGHT' else "SOLD",
		   "price": history["price"],
	       "symbol": history["symbol"],
	       "shares": history["shares"],
	       "total": history["price"] * history["shares"],
           "time": history["timestamp"]
		}
        transactions.append(hist_dict)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return flash("Must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return flash("Must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash(u"Invalid password or username provided", "error")           
# return apology("Incorrect password or username", "403")

            return render_template("login.html")
        else:
            flash("You were successfully logged in")

# Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session['username'] = rows[0]['username'].lower()

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out."""
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

	# Get stock information
        stock = lookup(request.form.get("symbol"))

        # Validate ticker symbol
        if stock == None:
            return apology("Invalid ticker symbol")

        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")

# return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""
	# Forgets any user_id
    session.clear()

# User reached route via POST (as by submitting a form by POST)
    if request.method == "POST":
        password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

# Ensure submission of username
        if not request.form.get('username'):
            flash('Username cannot be empty', 403)

# Ensure password is submitted
        elif not request.form.get('password'):
            flash("Password cannot be empty", 403)		

# Create column in database for username and password
        exists = db.execute("SELECT * FROM users WHERE username = :username", username = request.form.get("username"))

        if exists:
            if request.form.get('username') == exists[0]['username']:
                flash("Username already exists")
        else:
            rows = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=request.form.get('username'), hash = password)
            flash("Registration complete", 200)

	# Remember which user has logged in
        session['user_id'] = rows[0]['id']
        session['username'] = rows[0]['username'].lower()

	# Redirect to check route
        #return redirect("/check")
		# Redirect to homepage
        return redirect("/")
	 # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

    #return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock."""
    if request.method == "POST":

        stock = lookup(request.form.get("symbol"))

        if stock is None:
            flash("Invalid ticker symbol")

        try:
            shares = int(request.form.get("shares"))
        except TypeError:
            flash("Shares must be a number")

        if shares < 0:
            flash("Must be a positive number")

        #rows = db.execute('SELECT username FROM users WHERE id = :user_id', user_id = session['user_id'])

		# price is assigned the value of stock's price key 
        price = stock['price']       
        total_price = shares * price 		

        updated_rows = db.execute("UPDATE users SET cash = cash + :total_price WHERE id = :user_id", total_price = total_price, user_id = session['user_id'])

        db.execute("INSERT INTO 'transactions'(user_id, symbol, shares, price, status) VALUES (:user_id, :symbol, :shares, :price, :status)", user_id=session['user_id'], symbol = request.form.get('symbol'), shares = shares, price=price, status="SOLD")

        exists = db.execute("SELECT symbol, name FROM portfolio WHERE user_id = :user_id AND (symbol = :symbol)", user_id = session['user_id'], symbol = request.form.get('symbol'))

        if len(exists) == 0:
            db.execute("INSERT INTO 'portfolio' (user_id, symbol, shares, name) VALUES(:user_id, :symbol, :shares, :name)", user_id = session["user_id"], symbol = request.form.get('symbol'), shares = shares, name = session['username'])

        else:
            db.execute("UPDATE portfolio SET shares = shares - :shares WHERE user_id = :user_id AND (symbol = :symbol)", shares = shares, user_id = session['user_id'], symbol = request.form.get('symbol'))

        db.execute("UPDATE portfolio SET 'TOTAL' = (SELECT sum(price * shares) from transactions WHERE user_id = :user_id AND symbol = :symbol) WHERE user_id = :user_id AND symbol = :symbol", user_id = session['user_id'], symbol = request.form.get('symbol'))

        flash("SOLD!")

        return redirect("/")

    else:
        rows = db.execute("SELECT * FROM portfolio WHERE user_id = :user_id ORDER BY symbol ASC", user_id = session["user_id"])

        portfolio = []

        for data in rows:
            portfolio_dict = {
				"symbol": data["symbol"],
				"shares": data["shares"],
				"total": data['TOTAL'], 
				}
            portfolio.append(portfolio_dict)

        return render_template("sell.html", portfolio=portfolio)


def errorhandler(e):
    """Handle error."""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

app.debug = False
app.run()
