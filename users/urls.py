from django.urls import path
from . import views
from .decorator import redirect_authenticated_user  

urlpatterns = [
    path('home/', views.home, name='home'),
    path('', redirect_authenticated_user(views.signup_view), name="register"),
    path('login/', redirect_authenticated_user(views.signin_view), name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('forget-password/', views.forget_password_view, name='forget_password'),
    path('reset-password/', views.reset_password_view, name='reset_password'),
    path('change-password/', views.change_password_view, name='change_password'),
    path('profile/', views.profile_view, name='get_profile'),
    path('profile-edit/', views.updateprofile_view, name='update_profile'),
    path('active/', views.active_user, name='active_user'),
    path('all-users/', views.all_users, name='all_users'),
    path('binance/', views.binance_view, name='binance'),
    path('api-management/', views.api_management, name='api_management'),
    path('editapi-management/', views.update_api_management, name='update_api_management'),
]
