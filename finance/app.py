import os
from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]
    total = 0

    # group by symbol, sum(shares) ->transaction
    try:
        transactions_db = db.execute(
            "SELECT symbol, SUM(shares) as shares FROM transactions WHERE user_id = ? GROUP BY symbol",
            user_id,
        )
        total = 0
        if transactions_db:
            for transaction in transactions_db:
                symbol = transaction["symbol"]
                stock = lookup(symbol)
                if stock:
                    transaction["price"] = usd(stock["price"])
                    transaction["total"] = usd(
                        stock["price"] * transaction["shares"])
                    total += stock["price"] * transaction["shares"]
        return render_template(
            "index.html",
            transactions=transactions_db,
            cash=usd(cash),
            total=usd(total + cash),
        )
    except:
        return render_template("index.html", cash=usd(cash), total=usd(total + cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if not symbol:
            return apology("Symbol cannot be empty")

        data = lookup(symbol)
        if not data:
            return apology("Invalid symbol")
        print(data)

        try:
            shares = int(shares)
            cash_db = db.execute(
                "SELECT cash FROM users WHERE id = ?", user_id)

            cash = cash_db[0]["cash"]
            transaction_value = shares * data["price"]

            if shares < 1:
                return apology("Shares cannot be negative")
            elif transaction_value > cash:
                return apology("Insufficient Balance")

            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                user_id,
                symbol,
                shares,
                data["price"]
            )

            # Update balance
            new_balance = cash - transaction_value
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       new_balance, user_id)

            # Redirect user to home page
            return redirect("/")
        except:
            return apology("Shares must be numeric")

    else:
        return render_template("buy.html")

# @app.route("/buy", methods=["GET", "POST"])
# @login_required
# def buy():
#     """Buy shares of stock"""
#     user_id = session["user_id"]

#     if request.method == "POST":
#         symbol = request.form.get("symbol").upper()
#         shares = request.form.get("shares")

#         # Debugging print statements
#         print("Received symbol:", symbol)
#         print("Received shares:", shares)

#         if not symbol:
#             return apology("Symbol cannot be empty")

#         data = lookup(symbol)
#         if not data:
#             return apology("Invalid symbol")

#         try:
#             shares = int(shares)
#             if shares < 1:
#                 return apology("Shares must be a positive number")
#         except ValueError:
#             print("Error: Shares is not numeric")
#             return apology("Shares must be numeric")

#         # Retrieve user's cash balance
#         cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
#         cash = cash_db[0]["cash"]

#         # Calculate transaction value
#         transaction_value = shares * data["price"]
#         print("Transaction value:", transaction_value)

#         if transaction_value > cash:
#             return apology("Insufficient Balance")

#         # Record the transaction
#         db.execute(
#             "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
#             user_id, symbol, shares, data["price"]
#         )

#         print(datetime.now())

#         # Update user's cash balance
#         new_balance = cash - transaction_value
#         db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, user_id)

#         # Redirect user to home page
#         return redirect("/")

#     else:
#         return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    try:
        transactions_db = db.execute(
            "SELECT * FROM transactions WHERE user_id = ?",
            user_id,
        )
        return render_template(
            "history.html",
            transactions=transactions_db,
        )
    except:
        return apology("Something is wrong")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get(
                "username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must provide symbol")

        data = lookup(symbol)
        if not data:
            return apology("Invalid Symbol")
        return render_template(
            "quoted.html", symbol=data["symbol"], price=data["price"]
        )
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if (request.method == "POST"):
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirmation password was submitted
        elif not confirmation:
            return apology("must provide confirmation password", 400)

        # Ensure password and confirmation match
        elif password != confirmation:
            return apology("passwords do not match", 400)

        hash = generate_password_hash(password)

        try:
            db.execute(
                "INSERT INTO users(username, hash) VALUES (?, ?)", username, hash)
            return redirect('/')
        except:
            return apology("Username already exists", 400)
        # Insert user into database
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Symbol cannot be empty")

        data = lookup(symbol)

        try:
            shares = int(shares)
            shares_db = db.execute(
                "SELECT SUM(shares) as shares FROM transactions WHERE user_id = ? and symbol = ? GROUP BY symbol",
                user_id,
                symbol,
            )
            current_shares = shares_db[0]["shares"]

            if shares < 1:
                return apology("Shares cannot be negative")
            elif not shares.is_integer():
                return apology("Shares cannot be fractional")
            elif current_shares - shares < 0:
                return apology("Insufficient Balance")

            # Create new transaction
            cash_db = db.execute(
                "SELECT cash FROM users WHERE id = ?", user_id)
            cash = cash_db[0]["cash"]
            transaction_value = shares * data["price"]
            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
                user_id,
                symbol,
                (-1) * shares,
                data["price"],
                datetime.now(),
            )

            # # Update balance
            new_balance = cash + transaction_value
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       new_balance, user_id)

            # # Redirect user to home page
            return redirect("/")
        except:
            return apology("Invalid shares ammount")

    else:
        symbols_db = db.execute(
            "SELECT DISTINCT symbol FROM transactions WHERE user_id = ?", user_id
        )
        symbols = []
        if symbols_db:
            for symbol in symbols_db:
                symbols.append(symbol["symbol"])

        return render_template("sell.html", symbols=symbols)
