#!/usr/bin/env python3

from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from email.charset import Charset, QP
import sys

with open(sys.argv[1], 'rb') as f:
    json_content = f.read()

with open(sys.argv[2], 'rb') as f:
    artifact_content = f.read()

# Create a multipart message
msg = MIMEMultipart()

mime_bounadry = "DeviceTM_Artifact_Download_Boundary"
msg = MIMEMultipart(boundary=mime_bounadry)

# Add JSON content
json_part = MIMEBase('application', 'json')
json_part.set_payload(json_content)

# Set charset to utf-8
charset = Charset('utf-8')
charset.body_encoding = None # No encoding
json_part.set_charset(charset)

# Manually set Content-Type header to remove quotes around utf-8
json_part.replace_header('Content-Type', 'application/json; charset=utf-8')

# Set Content-Length header
json_part.add_header('Content-Length', str(len(json_content)))

# Remove MIME-Version header
del json_part['MIME-Version']

# Remove Content-Transfer-Encoding header
del json_part['Content-Transfer-Encoding']

msg.attach(json_part)

# Add artifact content
artifact_part = MIMEBase('application', 'octet-stream')
place_holder = "x" * len(artifact_content)
artifact_part.set_payload(place_holder)

# Set Content-Length header
artifact_part.add_header('Content-Length', str(len(artifact_content)))

# Set Content-Transfer-Encoding
artifact_part.add_header('Content-Transfer-Encoding', 'binary')

# Remove MIME-Version header
del artifact_part['MIME-Version']

msg.attach(artifact_part)

# Convert the message to a string
str_msg = msg.as_string()

# Calculate total length
start_boundary = "--" + mime_bounadry
total_length = len(str_msg.split(start_boundary,1)[1]) + len(start_boundary)

# Set Content-Length header
msg.add_header('Content-Length', str(total_length))

# Convert the message to a string
str_msg = msg.as_string()

# Replace with actual content
str_bytes = str_msg.encode()
str_bytes = str_bytes.replace(place_holder.encode(), artifact_content)

print("Writing artifact to file " + sys.argv[3])
with open(sys.argv[3], "wb") as text_file:
    text_file.write(str_bytes)
