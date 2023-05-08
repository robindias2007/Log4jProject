from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required,user_passes_test
import socket
import ssl
import re
from django.http import JsonResponse
import boto3
import psutil
import pdb
from django.core.mail import EmailMessage
import smtplib
import docker
import paramiko


def is_admin(user):
    return user.is_authenticated and user.is_superuser

session = boto3.Session(
    aws_access_key_id='AKIA3YWLQ2ROZY5WJH53',
    aws_secret_access_key='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',
    region_name='eu-west-2'
)

# Create a Boto3 EC2 client
ec2_client = session.client('ec2')

def get_cpu_utilization(instance_id):
    cpu_percent = psutil.cpu_percent(interval=1)
    return cpu_percent

# def get_ec2_instances():
#     # Fetch the list of all EC2 instances
#     pdb.set_trace()
#     response = ec2_client.describe_instances()
#
#     # Extract the list of instances and their statuses from the response
#     instances = []
#     for reservation in response['Reservations']:
#         for instance in reservation['Instances']:
#             instance_id = instance['InstanceId']
#             instance_type = instance['InstanceType']
#             # instance_state = instance['State']['Name']
#             # public_ip = instance.get('PublicIpAddress', 'N/A')
#             # private_ip = instance.get('PrivateIpAddress', 'N/A')
#             # launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
#             # cpu_utilization = get_cpu_utilization(instance_id)
#
#             instances.append({
#                 'id': instance_id,
#                 'type': instance_type
#                 # 'state': instance_state,
#                 # 'public_ip': public_ip,
#                 # 'private_ip': private_ip,
#                 # 'launch_time': launch_time,
#                 # 'cpu_utilization': cpu_utilization,  # Replace with actual value
#                 # 'memory_utilization': 'N/A',  # Replace with actual value
#                 # 'disk_usage': 'N/A',  # Replace with actual value
#                 # 'network_io': 'N/A'  # Replace with actual value
#             })
#
#         # Refresh the list of instances after stopping the selected instance
#         instances = get_ec2_instances()
#
#     return instances

@user_passes_test(is_admin)
def ec2_instance_lists(request):
    # Fetch the list of all EC2 instances
    #instances = get_ec2_instances()
    ecs_client = session.client('ecs')
    response = ecs_client.list_tasks()
    tasks = response['taskArns']
    container_info = []
    for task in tasks:
        task_info = ecs_client.describe_tasks(tasks=[task])
        containers = task_info['tasks'][0]['containers']
        for container in containers:
            container_info.append({
                'task_id': task_info['tasks'][0]['taskArn'],
                'container_name': container['name'],
                'container_id': container['dockerId']
            })
    return render(request, 'ec2_instance_list.html', {'instances': container_info})

def scan_log4j(request):
    # Get the uploaded file from the request
    if request.method == 'POST':
        #uploaded_file = request.FILES.get('my_file')
        with open('log4j_test_file.txt', 'r') as f:
            content = f.read()
            # Define regular expression pattern to match log4j strings
            # Pattern 1: Base64 encoded strings separated by optional pipe symbols
            log4j_pattern1 = r'\b[A-Za-z0-9+/]{1,}={0,2}\s*(?:\|\s*)?[A-Za-z0-9+/]{1,}={0,2}\s*(?:\|\s*)?[A-Za-z0-9+/]{1,}={0,2}\b'

            # Pattern 2: Unicode escape sequences or base64 encoded strings separated by optional pipe symbols
            log4j_pattern2 = r'((?:(?<!\\)\\(?:\\\\)*+(?:\\u[a-fA-F0-9]{4}|\\x[a-fA-F0-9]{2}))|[a-zA-Z0-9+/]{4}[AQgw]==)(\s+)?(\|\s+)?[^\s]*'

            # Pattern 3: Strings containing a specific HTTP method followed by a path that matches certain keywords
            log4j_pattern3 = r'\[(.*?)\].*?"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) (.*?)/(?:jmx-console|web-console|invoker|admin-console|web-inf).*?"'

            # Pattern 4: Strings containing references to log4j or log4shell configuration files with URLs that start with "http" or "https"
            log4j_pattern4 = r'(?i)(?:log4j|log4shell)\.(?:appender|logger|rootLogger|fileAppender|layout)\s*?[=(:].*?https?:\/\/.*?'

            # Pattern 5: Strings containing references to JMX, RMI, or JNDI that could be used for remote code execution
            log4j_pattern5 = r'(?i)(?:jmxremote|jmxrmi|jndi|rmi)\s*?(?::|\/).*?(?:jmxrmi|jmxremote|ClassLoader|ObjectInput|ObjectOutput|Protocol)'

            patterns = [log4j_pattern1, log4j_pattern2, log4j_pattern3, log4j_pattern4, log4j_pattern5]

            log4j_strings = re.findall(log4j_pattern5,content)
            #pdb.set_trace()
            if log4j_strings:
                print("Pattern Found")
                #print(log4j_strings)
                #return render(request, 'result.html', {'log4j_strings': log4j_strings})
            else:
                print("Pattern not found")

            # Read contents of the uploaded file
    return render(request, 'scan_log4j.html')



# def scan_log4j(request):
#     if request.method == 'POST':
#         ip_address = request.POST.get('ip_address')
#         if ip_address:
#             try:
#                 # Open a socket to the target IP address on port 443
#                 context = ssl.create_default_context()
#                 with socket.create_connection((ip_address, 443)) as sock:
#                     with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
#                         # Send a test request to the server
#                         ssock.sendall(b"GET / HTTP/1.1\r\nHost: " + ip_address.encode('utf-8') + b"\r\n\r\n")
#                         response = ssock.recv(1024)
#                         # Check if the response contains the string "Apache Log4j"
#                         if b"Apache Log4j" in response:
#                             return HttpResponse("IP address is vulnerable")
#                             # return render(request, 'vulnerable.html', {'ip_address': ip_address})
#                         else:
#                             return HttpResponse("IP address is not vulnerable")
#                             # return render(request, 'not_vulnerable.html', {'ip_address': ip_address})
#             except Exception as e:
#                 # An exception occurred, so the IP address is likely not vulnerable
#                 return HttpResponse("IP address is not vulnerable excep")
#                 #return render(request, 'not_vulnerable.html', {'ip_address': ip_address})
#     return render(request, 'scan_log4j.html')


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
            return HttpResponse("Invalid username or password.")

    return render(request, 'login.html')


def LogoutPage(request):
    logout(request)
    return redirect('login')

def send_email(request):
    # set up the SMTP connection
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'robindias2007@gmail.com'
    smtp_password = "icikeraihfdmwyms"
    smtp_connection = smtplib.SMTP(smtp_server, smtp_port)
    smtp_connection.starttls()
    smtp_connection.login(smtp_username, smtp_password)

    # set up the email message
    sender = 'robindias2007@gmail.com'
    recipient = 'robindias2007@gmail.com'
    subject = 'Test email'
    body = 'This is a test email sent from Python!'
    message = f"From: {sender}\nTo: {recipient}\nSubject: {subject}\n\n{body}"

    # send the email
    smtp_connection.sendmail(sender, recipient, message)

    # clean up
    smtp_connection.quit()
    return HttpResponse("EMAIL SENT")


def ec2_instance_list(request):

    ec2_client = session.client('ec2')
    ec2_instance_id = 'i-0a5a0f239993d1666'
    response = ec2_client.describe_instances(InstanceIds=[ec2_instance_id])
    ec2_public_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
    ec2_private_key_path = '/Users/robindias/Desktop/Project/CyberSecurity/server_key.cer'

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=ec2_public_ip, username='ec2-user', key_filename=ec2_private_key_path)
    stdin, stdout, stderr = ssh_client.exec_command('docker ps -a')

    container_info = []

    for line in stdout:
        fields = line.strip().split()
        if fields[0] != 'CONTAINER':
            container_id = fields[0]
            container_name = fields[-1]
            container_os = fields[1]
            container_status = fields[7]
            container_dict = {
                'id': container_id,
                'name': container_name,
                'os' : container_os,
                'status': container_status,
            }

            container_info.append(container_dict)

    ssh_client.close()
    return render(request, 'ec2_instance_list.html', {'container_info': container_info})

