from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from .models import Student
import random

# Create your views here.

def index(request): 
    return render(request, 'student_mgmt_system/index.html', {
        'students': Student.objects.all(),
        'colors': ["active", "primary", "secondary", "success", "danger", "warning", "info", "light", "dark"]
    })
    
def view_student(request, id):
    return HttpResponseRedirect(reverse('index'))