from django.urls import path
from . import views

urlpatterns = [
    path('users_login', views.users_login, name='users_login'),
    path('', views.index, name='index'),
    path('register', views.register, name='register'),
    path('portalchangepassword', views.portal_change_password, name='portalchangepassword'),
    path('user_logout', views.user_logout, name='user_logout'),
]