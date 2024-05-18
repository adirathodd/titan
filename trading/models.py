from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    balance = models.FloatField(default = 10000)

class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete = models.CASCADE, related_name = "user")
    stock = models.CharField(max_length=10)
    shares = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    currentValue = models.FloatField(null = True, blank = True)