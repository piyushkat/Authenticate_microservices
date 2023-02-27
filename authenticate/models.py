from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from rest_framework.authtoken.models import Token



class Profile(models.Model):
    user = models.OneToOneField(User,blank=False, primary_key=True,on_delete=models.CASCADE)
    auth_token = models.CharField(max_length=100)
    is_verified = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)



class TokenUser(models.Model):
    user = models.OneToOneField(User,blank=False, primary_key=True,on_delete=models.CASCADE)
    refresh_token = models.CharField(max_length=2000, blank=True,default=None)
    access_token = models.CharField(max_length=2000, blank=True,default=None)