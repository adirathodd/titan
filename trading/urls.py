from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("register", views.register, name="register"),
    path("search", views.search, name = "search"),
    path("buy", views.buy, name = "buy"),
    path("sell", views.sell, name = "sell"),
]