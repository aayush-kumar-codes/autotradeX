from django.db import models
from django.contrib.auth.models import AbstractUser

from phonenumber_field.modelfields import PhoneNumberField

from .managers import UserManager

# Create your models here.


class User(AbstractUser):

    email = models.EmailField(('email_address'), unique=True, max_length=200)
    username = models.CharField(max_length=200, null=True, blank=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    # role = models.PositiveSmallIntegerField(choices=RoleChoices.choices)
    mobile_no = PhoneNumberField(unique=True, null=True, blank=True)
    address = models.CharField(max_length=512, blank=True)
    city = models.CharField(max_length=100, blank=True) 
    state = models.CharField(max_length=100, blank=True)
    zip_code = models.CharField(max_length=10, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Required fields for Django's AbstractUser
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        db_table = 'User'

    def __str__(self) -> str:
        return self.email


# class Benefit(models.Model):
#     name = models.CharField(max_length=255)
#     description = models.TextField()

#     def __str__(self):
#         return self.name


# class Plan(models.Model):
#     BASIC = "BASIC"
#     STANDARD = "STANDARD"
#     PREMIUM = "PREMIUM"

#     name = models.CharField(max_length=124)
#     price = models.IntegerField()
#     benefits = models.ManyToManyField(Benefit)

#     def __str__(self):
#         return self.name
    

# class Subscription(models.Model):
#     Paid = 1
#     Unpaid = 2
#     STATUS_CHOICE = (
#         (Paid, 'Paid'),
#         (Unpaid, 'Unpaid')
#     )

#     user = models.ForeignKey(
#         User, on_delete=models.CASCADE,
#         related_name="user_subscription"
#     )
#     plan = models.ForeignKey(
#         Plan, on_delete=models.CASCADE, related_name="subscription_plan"
#     )
#     start_date = models.DateField(auto_now_add=True)
#     end_date = models.DateField(null=True, blank=True)
#     is_paid = models.PositiveSmallIntegerField(
#         choices=STATUS_CHOICE, default=2
#     )
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(
#         auto_now_add=False, null=True, blank=True
#     )

#     def __str__(self):
#         return f"{self.user.get_full_name()}'s {self.plan.name} Subscription"