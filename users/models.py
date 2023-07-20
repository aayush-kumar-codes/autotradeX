from django.db import models
from django.contrib.auth.models import AbstractUser

from .managers import UserManager

# Create your models here.


class User(AbstractUser):

    email = models.EmailField(('email_address'), unique=True, max_length=200)
    username = models.CharField(max_length=200, null=True, blank=True)
    
    # Required fields for Django's AbstractUser
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        db_table = 'User'

    def __str__(self) -> str:
        return self.email
