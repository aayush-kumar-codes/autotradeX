from django.db import models
from django.contrib.auth.models import AbstractUser

from phonenumber_field.modelfields import PhoneNumberField

from .managers import UserManager


class User(AbstractUser):

    email = models.EmailField(('email_address'), unique=True, max_length=200)
    username = models.CharField(max_length=200, null=True, blank=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    kyc_full_name = models.CharField(max_length=100, blank=True)
    nick_name = models.CharField(max_length=200, blank=True)
    mobile_no = PhoneNumberField(unique=True, null=True, blank=True)
    country = models.CharField(max_length=200, blank=True)
    zip_code = models.CharField(max_length=10, blank=True)
    is_active = models.BooleanField(default=True)
    telegram_id = models.CharField(max_length=200, unique=True)
    binance_key = models.CharField(max_length=200)
    secret_key = models.CharField(max_length=200)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        db_table = 'User'

    def __str__(self) -> str:
        return self.email
