from django.db import models
# importing validationerror
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password



# creating a validator function
def validate_3insys_email(value):
    if "@3insys.com" in value:
        return value
    else:
        raise ValidationError("This field accepts mail id of 3insys only")
    

def validate_3insys_username(value):
    if value.split('.'):
        return value
    else:
        raise ValidationError("This field accepts username in e.g. john.doe format only")

# Create your models here.
    


