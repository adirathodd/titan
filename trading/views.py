from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from .models import User, Transaction
from django.contrib.sites.shortcuts import get_current_site
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
import yfinance as yf
import plotly.graph_objects as go
from requests.exceptions import HTTPError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
import threading
from django.contrib import messages


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()

def dashboard(request):
    if request.user.is_authenticated and request.user.emailVerified:
        allShares = Transaction.objects.filter(user = request.user)
        total = User.objects.get(pk = request.user.id).balance
        for share in allShares:
            price = yf.Ticker(share.stock).info['currentPrice']
            total += share.shares * price
            update = Transaction.objects.get(user = request.user.id, stock = share.stock)
            update.currentValue = share.shares * price
            update.save()

        return render(request, "trading/dashboard.html", {
            "shares": allShares,
            "total": total,
        })
    else:
        return render(request, "trading/login.html")

def login_view(request):
    if request.method == "POST":

        # Attempt to sign user in
        username = request.POST["username"]
        password = request.POST["password"]
        # First, check if the user exists with the given username
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(request, 'trading/login.html', {
                "message": "Username does not exist."
            })

        # Check if the user is authenticated
        user = authenticate(request, username=username, password=password)
        if user is None:
            return render(request, 'trading/login.html', {
                'message': "Invalid password."
            })

        # Check if the email is verified
        if not user.emailVerified:
            return render(request, 'trading/login.html', {
                "message": "Email not verified. Please check your email for the verification link."
            })

        # Log the user in if all checks pass
        login(request, user)
        return HttpResponseRedirect(reverse("dashboard"))
    else:
        return render(request, "trading/login.html")


def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse("dashboard"))

def verifyEmail(request, user):
    currSite = request.get_host()
    emailSubject = "Titan - Verification email"
    emailBody = render_to_string('trading/activate.html', {
        'user': user,
        'domain': currSite,
        'uid': urlsafe_base64_encode(force_bytes(user.id)),
        'token': generate_token.make_token(user)
    })

    email = EmailMessage(subject=emailSubject, body=emailBody,
                         from_email=settings.EMAIL_FROM_USER,
                         to=[user.email]
                         )

    EmailThread(email).start()



def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
        if password != confirmation:
            return render(request, "trading/register.html", {
                "message": "Passwords must match."
            })
        if len(password) < 8:
            return render(request, "trading/register.html", {
                "message": "Password must be at least 8 characters long."
            })
        if User.objects.filter(username=username).exists():
            return render(request, "trading/register.html", {
                "message": "Username already taken."
            })
        if User.objects.filter(email=email).exists():
            return render(request, "trading/register.html", {
                "message": "There is already an account with this email address."
            })

        # Attempt to create new user
        try:
            validate_email(email)
            user = User.objects.create_user(username, email, password)
            user.save()
            verifyEmail(request, user)
            messages.success(request, "Check your email for the verification link.")
            return HttpResponseRedirect('.')
        except ValidationError as e:
            return render(request, "trading/register.html", {
                "message": "Email invalid."
            })
        except IntegrityError:
            return render(request, "trading/register.html", {
                "message": "Username already taken."
            })



    else:
        return render(request, "trading/register.html")

def is_valid_ticker(ticker):
    stock = yf.Ticker(ticker)
    info = stock.info
    essential_keys = ['currentPrice', 'shortName']
    if not info or any(key not in info for key in essential_keys):
        return False
    return True

def get_stock_history(stock, period):
    history = stock.history(period=period)
    if history.empty:
        raise ValueError(f"No {period} historical data found for the ticker")
    return history

def search(request):
    ticker = request.POST['ticker'].upper()
    currentShares = 0

    if request.user.is_authenticated:
        if Transaction.objects.filter(user=request.user, stock=ticker).exists():
            oldBuy = Transaction.objects.get(user=request.user, stock=ticker)
            currentShares = oldBuy.shares

    try:
        if not is_valid_ticker(ticker):
            raise ValueError("Invalid ticker symbol")

        stock = yf.Ticker(ticker)
        info = stock.info

        # 1 year history
        oneYr = get_stock_history(stock, "1y")
        fig1 = go.Figure(data=go.Scatter(x=oneYr.index, y=oneYr['Close']))
        graph1 = fig1.to_html(full_html=False, default_width='620px')

        # 6 months history
        sixMo = get_stock_history(stock, "6mo")
        fig2 = go.Figure(data=go.Scatter(x=sixMo.index, y=sixMo['Close']))
        graph2 = fig2.to_html(full_html=False, default_width='620px')

        # 1 month history
        oneMo = get_stock_history(stock, "1mo")
        fig3 = go.Figure(data=go.Scatter(x=oneMo.index, y=oneMo['Close']))
        graph3 = fig3.to_html(full_html=False, default_width='620px')

        return render(request, "trading/search.html", {
            "info": info,
            "oneYr": graph1,
            "sixMo": graph2,
            "oneMo": graph3,
            "currentShares": currentShares
        })
    except ValueError as ve:
        return render(request, "trading/dashboard.html", {
            "message": str(ve)
        })
    except Exception as e:
        return render(request, "trading/dashboard.html", {
            "message": "An error occurred while fetching data. Please try again later."
        })


def buy(request):
    if request.method == "POST":
        #Get information
        shares = int(request.POST['shares'])
        ticker = request.POST['ticker']
        price = float(request.POST['price'])
        user = request.user
        currentUser = User.objects.get(pk = user.id)
        balance = currentUser.balance

        #Check if user has enough money
        if balance < (shares * price):
            try:
                stock = yf.Ticker(ticker)
                info = stock.info
                #One yr
                oneYr = stock.history(period = "1y")
                fig1 = go.Figure(data = go.Scatter(x = oneYr.index,  y = oneYr['Close']))
                graph1 = fig1.to_html(full_html=False)

                #6 months
                six = stock.history(period = "6mo")
                fig2 = go.Figure(data = go.Scatter(x = six.index,  y = six['Close']))
                graph2 = fig2.to_html(full_html=False)

                #1 month
                one = stock.history(period = "1mo")
                fig3 = go.Figure(data = go.Scatter(x = one.index,  y = one['Close']))
                graph3 = fig3.to_html(full_html=False)

                return render(request, "trading/search.html", {
                    "info": info,
                    "oneYr": graph1,
                    "sixMo": graph2,
                    "oneMo": graph3,
                    "message": "Insuficient funds."
                })
            except HTTPError:
                return render(request, "trading/dashboard.html", {
                    "message": "Invalid ticker"
                })

        #Check if user has the stock
        if Transaction.objects.filter(user = user, stock = ticker).exists():
            oldBuy = Transaction.objects.get(user = user, stock = ticker)
            oldBuy.shares += shares
            oldBuy.save()
            oldBuy.currentValue = oldBuy.shares * price
            oldBuy.save()

        else:
            newTransaction = Transaction(user = user, stock = ticker, shares = shares)
            newTransaction.save()
            newTransaction.currentValue = newTransaction.shares * price
            newTransaction.save()

        #Update balance and return dashboard
        currentUser.balance = balance - (shares * price)
        currentUser.save()
        return HttpResponseRedirect('.')

def sell(request):
    if request.method == "POST":
        shares = int(request.POST['shares'])
        ticker = request.POST['ticker']
        price = float(request.POST['price'])
        user = request.user
        currentUser = User.objects.get(pk = user.id)
        balance = currentUser.balance

        oldBuy = Transaction.objects.get(user = user, stock = ticker)
        if shares == oldBuy.shares:
            oldBuy.delete()
        else:
            oldBuy.shares -= shares
            oldBuy.save()
            oldBuy.currentValue = oldBuy.shares * price
            oldBuy.save()
        currentUser.balance = balance + (shares * price)
        currentUser.save()
        return HttpResponseRedirect('.')

def activateUser(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk = uid)

    except Exception as e:
        user = None

    if user and generate_token.check_token(user, token):
        user.emailVerified = True
        user.save()
        login(request, user)
        return render(request, "trading/dashboard.html", {
                    "message2": "Email Verified Successfully!"
                })

    return render(request, "trading/login.html", {
        "message": "Email verification failed."
    })