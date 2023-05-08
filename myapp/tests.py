import re
import os
from django.test import TestCase
from django.test import Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from myapp.views import scan_log4j
import threading
import time
#from django.core.mail import EmailMessage
from unittest.mock import patch, MagicMock
import smtplib
from email.message import EmailMessage
import pdb


# class Log4jTestCase(TestCase):
#     def test_file_contains_log4j_vulnerability(self):
#         with open('example.txt', 'r') as f:
#             log_file = f.read()
#         log4j_pattern = r'.*(org\.apache\.log4j|log4j\.core|org\.slf4j|javax\.xml\.parsers).*'
#         match = re.search(log4j_pattern, log_file)
#         self.assertIsNotNone(match)

# class UserLoginTests(TestCase):
#
#     def setUp(self):
#         self.user = User.objects.create_user(username='testuser', password='testpass')
#
#     def test_valid_login(self):
#         response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpass'})
#         self.assertEqual(response.status_code, 302)
#         self.assertRedirects(response, reverse('home'))
#
#     def test_invalid_login(self):
#         response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'wrongpass'})
#         self.assertEqual(response.status_code, 200)
#         self.assertContains(response, 'Invalid username or password.')


# class UserSignupTests(TestCase):
#
#     def test_signup_page(self):
#         response = self.client.post('/signup/', {'username': 'testuser', 'email': 'testuser@example.com', 'password': 'password', 'confirm-password': 'password'})
#         self.assertEqual(response.status_code, 302)
#
#     def test_signup_password_mismatch(self):
#         """
#         Test that a user cannot signup with password mismatch.
#         """
#         response = self.client.post('/signup/', {
#             'username': 'testuser',
#             'email': 'testuser@example.com',
#             'password': 'password1',
#             'confirm-password': 'password2'  # password mismatch
#         })
#         self.assertEqual(response.status_code, 200)
#         self.assertContains(response, "Passwords dont match")
#         self.assertFalse(User.objects.filter(username='testuser').exists())

# class AdminAccessTests(TestCase):
#
#     def setUp(self):
#         self.user = User.objects.create_superuser(username='admin', password='adminpass')
#
#     def test_admin_access(self):
#         self.client.login(username='admin', password='adminpass')
#         response = self.client.get(reverse('admin:index'))
#         self.assertEqual(response.status_code, 200)
#         self.assertContains(response, 'Site administration')

# class Log4jTestCase(TestCase):
#     def test_scan_log4j_positive(self):
#         # Create a temporary file containing a log4j string
#         with open('log4j_test_file.txt', 'w') as f:
#             f.write('test string with jmxremote')
#
#         # Make a POST request to scan the log file
#         with open('log4j_test_file.txt', 'rb') as f:
#             response = self.client.post(reverse('scan_log4j'), {'my_file': f})
#
#         # Verify that the response contains the expected log4j string
#         self.assertContains(response, 'test string with jmxremote')
#
#         # Remove the temporary file
#         os.remove('log4j_test_file.txt')
#
#     def test_scan_log4j_negative(self):
#         # Create a temporary file containing no log4j strings
#         with open('blank_page.txt', 'w') as f:
#             f.write('this is a test')
#
#         # Make a POST request to scan the log file
#         with open('bl.txt', 'rb') as f:
#             response = self.client.post(reverse('scan_log4j'), {'my_file': f})
#
#         # Verify that the response does not contain any log4j strings
#         self.assertNotContains(response, 'Pattern Not Found')
#
#         # Remove the temporary file
#         os.remove('blank_page.txt')


class PerformanceTests(TestCase):
    def setUp(self):
        self.client = Client()

    # Concurrent Users test
    # def test_concurrent_users(self):
    #     # Create 10 threads that make requests to the signup page at the same time
    #     def make_request():
    #         self.client.post('/signup/', {'username': 'testuser', 'email': 'testuser@example.com', 'password': 'password'})
    #         threads = [threading.Thread(target=make_request) for _ in range(10)]
    #         [thread.start() for thread in threads]
    #         [thread.join() for thread in threads]
    #
    #         # Verify that all requests were successful
    #         response = self.client.get('/')
    #         self.assertEqual(response.status_code, 200)
    #         self.assertContains(response, '10 users signed up')

    #Load Testing, Performance Testing and Stress Testing
    # def test_signup_performance(self):
    #     start_time = time.time()
    #     for i in range(100):
    #         self.client.post('/signup/', {'username': f'testuser_{i}', 'email': f'testuser{i}@example.com', 'password': 'password'})
    #     end_time = time.time()
    #     elapsed_time = end_time - start_time
    #     print(f'Signup of 100 users took {elapsed_time} seconds')



class SendEmailTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    def test_send_email_success(self):
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
        #pdb.set_trace()
        print("Email Sent Successfully")

    def test_send_email_failure(self):
        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        smtp_username = 'robindias2007@gmail.com'
        smtp_password = 'invalid_password'
        smtp_connection = smtplib.SMTP(smtp_server, smtp_port)
        smtp_connection.starttls()
        with self.assertRaises(smtplib.SMTPAuthenticationError):
            smtp_connection.login(smtp_username, smtp_password)
        print("Authentication Issues.Username and Password dont match")
