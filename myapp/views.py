from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required,user_passes_test
import socket
import ssl
from log4jscanner import Log4jScanner
import re
from django.http import JsonResponse
import boto3
import psutil


def is_admin(user):
    return user.is_authenticated and user.is_superuser

session = boto3.Session(
    aws_access_key_id='AKIAWOSMGA3CLMRQPM7S',
    aws_secret_access_key='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',
    region_name='eu-west-2'
)

# Create a Boto3 EC2 client
ec2_client = session.client('ec2')

def get_cpu_utilization(instance_id):
    cpu_percent = psutil.cpu_percent(interval=1)
    return cpu_percent


def get_ec2_instances():
    # Fetch the list of all EC2 instances
    response = ec2_client.describe_instances()

    # Extract the list of instances and their statuses from the response
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_type = instance['InstanceType']
            # instance_state = instance['State']['Name']
            # public_ip = instance.get('PublicIpAddress', 'N/A')
            # private_ip = instance.get('PrivateIpAddress', 'N/A')
            # launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
            # cpu_utilization = get_cpu_utilization(instance_id)

            instances.append({
                'id': instance_id,
                'type': instance_type
                # 'state': instance_state,
                # 'public_ip': public_ip,
                # 'private_ip': private_ip,
                # 'launch_time': launch_time,
                # 'cpu_utilization': cpu_utilization,  # Replace with actual value
                # 'memory_utilization': 'N/A',  # Replace with actual value
                # 'disk_usage': 'N/A',  # Replace with actual value
                # 'network_io': 'N/A'  # Replace with actual value
            })

        # Refresh the list of instances after stopping the selected instance
        instances = get_ec2_instances()

    return instances

@user_passes_test(is_admin)
def ec2_instance_list(request):
    # Fetch the list of all EC2 instances
    instances = get_ec2_instances()

    # if request.method == 'POST':
    #     # Stop the selected EC2 instance
    #     instance_id = request.POST.get('instance_id')
    #     ec2_client = boto3.client('ec2')
    #     ec2_client.stop_instances(InstanceIds=[instance_id])
    #
    #     # Refresh the list of instances after stopping the selected instance
    #     instances = get_ec2_instances()
    # Render the instances list in an HTML table
    return render(request, 'ec2_instance_list.html', {'instances': instances})

def scan_log4j(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        if ip_address:
            try:
                # Open a socket to the target IP address on port 443
                context = ssl.create_default_context()
                with socket.create_connection((ip_address, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                        # Send a test request to the server
                        ssock.sendall(b"GET / HTTP/1.1\r\nHost: " + ip_address.encode('utf-8') + b"\r\n\r\n")
                        response = ssock.recv(1024)
                        # Check if the response contains the string "Apache Log4j"
                        if b"Apache Log4j" in response:
                            return HttpResponse("IP address is vulnerable")
                            # return render(request, 'vulnerable.html', {'ip_address': ip_address})
                        else:
                            return HttpResponse("IP address is not vulnerable")
                            # return render(request, 'not_vulnerable.html', {'ip_address': ip_address})
            except Exception as e:
                # An exception occurred, so the IP address is likely not vulnerable
                return HttpResponse("IP address is not vulnerable excep")
                #return render(request, 'not_vulnerable.html', {'ip_address': ip_address})
    return render(request, 'scan_log4j.html')


def log4_check(request):
    if request.method=='POST':
        text_input = request.POST.get('text_input')
        result = Log4jScanner.url_list(text_input)
        if result['vulnerable']:
            return HttpResponse("This is malicious text")
        else:
            return HttpResponse("This is proper text")

    return render(request, 'log4_check.html')

@login_required(login_url='login')
def HomePage(request):
    return render(request, 'home.html')

def SignupPage(request):
    if request.method=='POST':
        uname = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password')
        pass2 = request.POST.get('confirm-password')
        if pass1!=pass2:
            return HttpResponse("Passwords dont match")
        else:
            my_user = User.objects.create_user(uname,email,pass1)
            my_user.save()
            return redirect('login')

        print(uname,email,pass1,pass2)

    return render(request, 'signup.html')

def LoginPage(request):
    if request.method=='POST':
        uname = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request,username=uname,password=password)
        if user is not None:
            login(request,user)
            return redirect('home')
        else:
            return HttpResponse("Username or Password is incorrect!!")

    return render(request, 'login.html')


def LogoutPage(request):
    logout(request)
    return redirect('login')
