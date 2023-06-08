from django.shortcuts import render
from .models import Student

# Create your views here.

def index(request):
    return render(request, 'student_mgmt_system/index.html', {
        'students': Student.objects.all()
    })