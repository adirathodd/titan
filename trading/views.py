from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from .models import User, Transaction
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
import yfinance as yf
import plotly.graph_objects as go
from requests.exceptions import HTTPError

def dashboard(request):
    if request.user.is_authenticated:
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
        user = authenticate(request, username=username, password=password)

        # Check if authentication successful
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(reverse("dashboard"))
        else:
            return render(request, "trading/login.html", {
                "message": "Invalid username and/or password."
            })
    else:
        return render(request, "trading/login.html")


def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse("dashboard"))


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
        except ValidationError as e:
            return render(request, "trading/register.html", {
                "message": "Email invalid."
            })
        except IntegrityError:
            return render(request, "trading/register.html", {
                "message": "Username already taken."
            })
        login(request, user)
        return HttpResponseRedirect(reverse("dashboard"))
    else:
        return render(request, "trading/register.html")
    
def search(request):
    ticker = request.POST['ticker']
    currentShares = 0
    if request.user.is_authenticated:
        if Transaction.objects.filter(user = request.user, stock = ticker.upper()).exists():
            oldBuy = Transaction.objects.get(user = request.user, stock = ticker.upper())
            currentShares = currentShares + oldBuy.shares
        try:
            stock = yf.Ticker(ticker)
            info = stock.info
            oneYr = stock.history(period = "1y")
            fig1 = go.Figure(data = go.Scatter(x = oneYr.index,  y = oneYr['Close']))
            graph1 = fig1.to_html(full_html=False, default_width = '620px')

            #6 months
            six = stock.history(period = "6mo")
            fig2 = go.Figure(data = go.Scatter(x = six.index,  y = six['Close']))
            graph2 = fig2.to_html(full_html=False, default_width = '620px')

            #1 month
            one = stock.history(period = "1mo")
            fig3 = go.Figure(data = go.Scatter(x = one.index,  y = one['Close']))
            graph3 = fig3.to_html(full_html=False, default_width = '620px')

            #test

            return render(request, "trading/search.html", {
                "info": info,
                "oneYr": graph1,
                "sixMo": graph2,
                "oneMo": graph3,
                "currentShares": currentShares
            })
        except HTTPError:
            return render(request, "trading/dashboard.html", {
                "message": "Invalid ticker"
            })
    else:
        try:
            stock = yf.Ticker(ticker)
            info = stock.info
            oneYr = stock.history(period = "1y")
            fig1 = go.Figure(data = go.Scatter(x = oneYr.index,  y = oneYr['Close']))
            graph1 = fig1.to_html(full_html=False, default_width = '620px')

            #6 months
            six = stock.history(period = "6mo")
            fig2 = go.Figure(data = go.Scatter(x = six.index,  y = six['Close']))
            graph2 = fig2.to_html(full_html=False, default_width = '620px')

            #1 month
            one = stock.history(period = "1mo")
            fig3 = go.Figure(data = go.Scatter(x = one.index,  y = one['Close']))
            graph3 = fig3.to_html(full_html=False, default_width = '620px')

            #test

            return render(request, "trading/search.html", {
                "info": info,
                "oneYr": graph1,
                "sixMo": graph2,
                "oneMo": graph3,
                "currentShares": currentShares
            })
        except HTTPError:
            return render(request, "trading/dashboard.html", {
                "message": "Invalid ticker"
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