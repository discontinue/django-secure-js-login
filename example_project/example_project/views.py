from django.http import HttpResponse


from django.shortcuts import render

def index(request):
    return render(request, "example_project/index.html")


def create_test_user(request):
    create_superuser()