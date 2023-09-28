from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User

from django import forms


class CreateUserForm(UserCreationForm):

    class Meta:

        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'password1', 'password2']

# - Authenticate a user (Model Form)

class LoginForm(AuthenticationForm):

    username = forms.CharField(required=True)
    password = forms.CharField(required=True)


class ADUserChangePasswordForm(forms.Form):

    old_password = forms.CharField(required=True)
    new_password = forms.CharField(required=True)
    confirm_password = forms.CharField(required=True)


class SetStatusForm(forms.Form):

    set_activate_status = forms.BooleanField(required=False)
    set_deactivate_status = forms.BooleanField(required=False)


class LockSetStatusForm(forms.Form):

    set_unlock_status = forms.BooleanField(required=False)
