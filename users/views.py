import base64, os

from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages


from .models import User

# Create your views here.

@login_required
def home(request):
    return render(request, 'home.html')


def signup_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm password')
        users = User.objects.filter(email=email)

        if users.exists():
            messages.error(request, 'This email already exists')
            return render(request, 'register.html')
        
        if password == confirm_password:
            user = User(email=email)
            user.password = make_password(password)
            user.save()
            messages.success(request, 'User Created successfully')
            return redirect('/login')
        else:
            messages.error(request, 'Password do not match')
    return render(request, 'register.html')


def signin_view(request):
    if request.method == 'GET':
        return render(request, 'login.html')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(username=email, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'User login successfully')
            return redirect('/home')
        else:
            messages.error(request, 'Invalid Email or Password')
            return redirect('/login')
        
    
def logout_view(request):
    logout(request)
    return redirect("/login")



def forget_password_view(request):
    if request.method == 'GET':
        return render(request, 'forgetpassword.html')

    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
            ip = os.getenv('IP')
            if user is not None:
                encoded_email = base64.urlsafe_b64encode(email.encode('utf-8')).decode('utf-8')
                reset_link = f"http://{ip}/reset-password/?token=" + encoded_email
                subject = "Forget Password"
                message = f"Click on the link to reset your password: <a href='{reset_link}'>click here</a>"
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [email]
                send_mail(subject, message, email_from, recipient_list, html_message=message)
                messages.success(request, 'Mail sent successfully')
                return redirect('/login')
            else:
                messages.error(request, 'Invalid email address')
                return redirect('/forget-password')
        except User.DoesNotExist:
            return redirect('/forget-password')
    

def reset_password_view(request):

    if request.method == 'GET':
        return render(request, 'resetpassword.html')
    
    elif request.method == 'POST':
        encoded_email = request.GET.get('token') 
        email = base64.urlsafe_b64decode(encoded_email).decode('utf-8')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error('Invalid email address')
            return render(request, 'resetpassword.html')

        new_password = request.POST.get('new password')
        confirm_password = request.POST.get('confirm new password')

        if new_password != confirm_password:

            messages.error(request, 'Passwords do not match')
            return render(request, 'resetpassword.html')

        user.set_password(confirm_password)
        user.save()
        messages.success(request, 'Password reset successfully')
        return redirect('/login')


@login_required
def change_password_view(request):
    if request.method == 'GET':
        return render(request, 'changepassword.html')

    elif request.method == 'POST':
        user = request.user
        if user.is_authenticated:
            old_pass = request.POST.get('old_password')
            new_pass = request.POST.get('new_password')
            confirm_pass = request.POST.get('confirm_password')

            if not user.check_password(old_pass):
                messages.error(request, 'Incorrect old password')
                return render(request, 'changepassword.html')

            if new_pass != confirm_pass:
                messages.error(request, 'Passwords do not match')
                return render(request, 'changepassword.html')

            user.set_password(new_pass)
            user.save()
            messages.success(request, 'Password changed successfully')
            return redirect('/home')
        else:
            return redirect('/changepassword')
        

@login_required
def profile_view(request):
    if request.method == 'GET':
        user = request.user
    return render(request, 'profile.html', {'user': user})
        

@login_required
def updateprofile_view(request):
    if request.method == 'GET':
        user_data = {
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'mobile_number': request.user.mobile_no,
            'address': request.user.address,
            'city': request.user.city,
            'state': request.user.state,
            'zip_code': request.user.zip_code,
        }
        return render(request, 'editprofile.html', {'user_data': user_data})
    
    elif request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.mobile_no = request.POST.get('mobile_number')
        user.address = request.POST.get('address')
        user.city = request.POST.get('city')
        user.state = request.POST.get('state')
        user.zip_code = request.POST.get('zip_code')
        user.save()
        messages.success(request, 'Profile Created successfully')
        return redirect('/profile')
    
def is_staff_user(user):
    return user.is_staff

@login_required
@user_passes_test(is_staff_user)
def active_user(request):
    if request.method == 'GET':
        active_users = User.objects.filter(is_active=True)
        return render(request, 'active_users.html', {'active_users': active_users})


@login_required
@user_passes_test(is_staff_user)
def all_users(request):
    if request.method == 'GET':
        active_users = User.objects.all()
        return render(request, 'all_users.html', {'active_users': active_users})