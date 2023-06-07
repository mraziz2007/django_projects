from django.shortcuts import render

# Create your views here.

def index(request):
    return render(request, 'student_mgmt_system/index.html')