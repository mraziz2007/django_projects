from django.shortcuts import render
from .models import Student
import random

# Create your views here.

def index(request): 
    return render(request, 'student_mgmt_system/index.html', {
        'students': Student.objects.all(),
        'color': random.choice(["active", "primary", "secondary", "success", "danger", "warning", "info", "light", "dark"])
    })