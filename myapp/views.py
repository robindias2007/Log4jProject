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
import os


def is_admin(user):
    return user.is_authenticated and user.is_superuser

# session = boto3.Session(
#     aws_access_key_id='AKIA3YWLQ2ROZY5WJH53',
#     aws_secret_access_key='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',
#     region_name='eu-west-2'
# )
#
# # Create a Boto3 EC2 client
# ec2_client = session.client('ec2')

def scan_log4j(request):
    keywords = [ '${jndi:', 'java.naming.factory.initial', 'java.naming.provider.url', 'jndiLookup', 'log4j.appender', 'log4j.configuration', 'log4j.logger', 'log4j.rootLogger', 'rmi://', 'ldap://', 'javax.script', 'org.apache.log4j.','jndi','ldap','${jndi', 'log4j2.loggerContext', 'log4j2.formatMsgNoLookups', 'jmsConnectionFactory', 'JMSProducer', 'JMSConsumer', 'InitialContext', 'UnicastRemoteObject', 'MarshalledObject', 'javax.jms.ObjectMessage', 'javax.jms.BytesMessage', 'javax.jms.StreamMessage', 'javax.jms.MapMessage', 'org.apache.logging.log4j.core.appender.db.jdbc.DriverManagerConnectionSource', 'org.apache.logging.log4j.core.appender.db.jdbc.DataSourceConnectionSource', 'org.apache.logging.log4j.core.config.plugins.convert.TypeConverters', 'org.apache.logging.log4j.core.impl.ContextAnchor', 'org.apache.logging.log4j.core.impl.JdkMapAdapterStringMap', 'org.apache.logging.log4j.core.impl.Log4jContextFactory', 'org.apache.logging.log4j.core.util.Closer', 'org.apache.logging.log4j.core.util.Loader' ]
    if request.method == 'POST':
        #pdb.set_trace()
        #uploaded_file = request.FILES.get('my_file')
        file = request.FILES['my_file']

        # Open the text file to search

        with open('example.txt', 'r') as f:
            content = f.read()

        # Search for the keywords in the text file
        matches = []
        for keyword in keywords:
            pattern = re.compile(keyword, re.IGNORECASE)
            match = pattern.search(content)
            if match:
                matches.append(match.group(0))

        # Print the matched keywords
        if matches:
            print('Matched keywords:')
            for match in matches:
                print(match)
            return render(request, 'result.html', {'log4j_strings': matches})
        else:
            print('No matches found')

    return render(request, 'scan_log4j.html')

def scan_log4jj(request):
    # Get the uploaded file from the request
    if request.method == 'POST':
        #uploaded_file = request.FILES.get('my_file')
        with open('log4_one_five.txt', 'r') as f:

            content = f.read()

            pattern = r'\$\{jndi:(ldap[s]?|rmi)://[^\n]+'

            pattern2 = r'(?i)log4j\.(?:appender|logger|rootLogger|fileAppender|layout)\s*?[=(:].*?https?:\/\/.*?'
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

            log4j_strings = re.findall(pattern2,content)
            #pdb.set_trace()
            if log4j_strings:
                print("Pattern Found")
                #print(log4j_strings)
                return render(request, 'result.html', {'log4j_strings': log4j_strings})
            else:
                print("Pattern not found")

            # Read contents of the uploaded file
    return render(request, 'scan_log4j.html')

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

def send_email(message):
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
    body = message
    message = f"From: {sender}\nTo: {recipient}\nSubject: {subject}\n\n{body}"

    # send the email
    smtp_connection.sendmail(sender, recipient, message)

    # clean up
    smtp_connection.quit()
    return HttpResponse("EMAIL SENT")

@user_passes_test(is_admin)
# define a function to check for log4j vulnerability
def check_log4j_vulnerability(container):
    # get container ID
    container_id = container.short_id
    # run a command in the container to check for the vulnerability
    #cmd1 = f"docker exec {container_id} bash -c 'sudo grep -r org.apache.log4j /'"
    cmd = f"docker exec {container_id} bash -c \"grep -r 'log4j\.[1-2][a-zA-Z]*\s*=' /var/log/\""
    #docker logs < container - name - or -id > | grep < search - term >

    result = os.system(cmd)
    print("Vulnerability checking....")
    # return True if vulnerability is found, else False
    return result == 0


def check_containers_for_log4_vulnerability(request):
    # create a client to communicate with the Docker daemon
    client = docker.from_env()

    if request.method == 'POST':
        container_id = request.POST.get('container_id')
        container = client.containers.get(container_id)
        container.remove(force=True)
        return redirect('check_containers_for_log4_vulnerability')

    # get a list of all containers and their statuses
    containers = client.containers.list(all=True)

    # create a list to store container information
    container_info = []

    for container in containers:
        # get container details
        container_id = container.short_id
        container_name = container.name
        container_status = container.status
        container_created = container.attrs['Created']
        container_image = container.attrs['Config']['Image']
        container_ports = container.attrs['HostConfig']['PortBindings']
        #container_networks = container.attrs['NetworkSettings']['Networks']
        container_stats = container.stats(stream=False)
        cpu_total_usage = container_stats['cpu_stats']['cpu_usage']['total_usage'] # calculate CPU usage
        num_cpu_cores = psutil.cpu_count() # Get the number of CPU cores on the host system
        cpu_percent = (cpu_total_usage / num_cpu_cores) * 100

        # create dictionary of container information
        container_dict = {
            'id': container_id,
            'name': container_name,
            'status': container_status,
            'created': container_created,
            'image': container_image,
            'ports': container_ports,
            # 'networks': container_networks,
            # 'cpu_usage': round(cpu_percent, 2),
            # 'mem_usage': f'{mem_usage / (1024 * 1024):.2f} MB',
            # 'mem_limit': f'{mem_limit / (1024 * 1024):.2f} MB',
            # 'mem_percent': round(mem_percent, 2)
        }

        # check for log4j vulnerability
        if check_log4j_vulnerability(container):
            # if vulnerability is found, delete the container and its associated image
            print(f"Log4j vulnerability found in container {container_id}, deleting container and associated image...")
            container.remove(force=True)
            client.images.remove(container_image, force=True)
            # add information about the deleted container to the container_info list
            container_dict['vulnerability'] = 'log4j'
            container_dict['status'] = 'deleted'
            message = f"System {container.short_id} and {container.name} is under serious threat"
            send_email(message)
        else:
            # if vulnerability is not found, add container information to the container_info list
            container_dict['vulnerability'] = 'Log4j strings not found'
            message = f"System {container.short_id} and {container.name} is safe and secure"
            send_email(message)


        # append container information to list
        container_info.append(container_dict)

    return render(request, 'check_containers_for_log4_vulnerability.html', {'container_info': container_info})
