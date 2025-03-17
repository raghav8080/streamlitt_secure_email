import streamlit as st
import smtplib
import ssl
import base64
import pymongo
import imaplib
import email
import datetime
import os
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.header import Header
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# MongoDB setup
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client["EmailEncryptionDB"]
collection = db["EncryptionData"]
file_collection = db["FileEncryptionData"]


# Generate RSA Key Pair
@st.cache_resource
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Generate AES Key
def generate_aes_key():
    return os.urandom(16)


# Generate IV
def generate_iv():
    return os.urandom(12)


# AES Encryption
def encrypt_aes(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message) + encryptor.finalize()
    return encrypted, encryptor.tag


# AES Decryption
def decrypt_aes(encrypted_message, key, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted


# RSA Encryption of AES Key
def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()


# RSA Decryption of AES Key
def decrypt_aes_key(encrypted_aes_key, private_key):
    decrypted_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


# Sending Email
def send_email(sender_email, sender_password, recipient, subject, encrypted_payload, file_attachments=None):
    port = 587
    smtp_server = "smtp.gmail.com"
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = recipient
    msg["Subject"] = Header(subject, 'utf-8').encode()
    msg["Message-ID"] = email.utils.make_msgid(domain='yourdomain.com')  # Replace with your domain

    # Attach encrypted payload as application/octet-stream with base64 encoding
    encrypted_part = MIMEApplication(encrypted_payload, Name="encrypted_data")
    encrypted_part.add_header('Content-Disposition', 'attachment', filename="encrypted_data.bin")
    encrypted_part['Content-Transfer-Encoding'] = 'base64'
    msg.attach(encrypted_part)

    # Add file attachments
    if file_attachments:
        for filename, encrypted_file in file_attachments:
            part = MIMEApplication(encrypted_file, Name=filename)
            part.add_header('Content-Disposition', 'attachment', filename=filename)
            part['Content-Transfer-Encoding'] = 'base64'
            msg.attach(part)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient, msg.as_string())
    except smtplib.SMTPException as e:
        st.error(f"Email sending failed: {e}")
        return None
    return msg["Message-ID"]


# Retrieve Email Using IMAP and Return Message ID
def retrieve_email(sender_email, sender_password, subject):
    imap_server = "imap.gmail.com"
    mail = imaplib.IMAP4_SSL(imap_server)
    try:
        mail.login(sender_email, sender_password)
    except imaplib.IMAP4.error as e:
        st.error("Authentication failed. Please check your email and password.")
        st.error(f"Error details: {e}")
        return None, None, None
    mail.select("inbox")

    result, data = mail.search(None, '(SUBJECT "' + subject + '")')
    email_ids = data[0].split() if data else []

    if not email_ids:
        return None, None, None

    for email_id in reversed(email_ids):
        result, msg_data = mail.fetch(email_id, "(RFC822)")
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)

        message_id = msg["Message-ID"]
        encrypted_message = None
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if content_type == "application/octet-stream" and part.get_filename() == "encrypted_data.bin":
                    encrypted_message = part.get_payload(decode=True)
                elif content_disposition and "attachment" in content_disposition:
                    filename = part.get_filename()
                    data = part.get_payload(decode=True)
                    attachments.append((filename, data))
        else:
            encrypted_message = msg.get_payload(decode=True)

        return encrypted_message, message_id, attachments

    return None, None, None


# Streamlit UI
st.title("Secure Email System")

private_key, public_key = generate_rsa_key_pair()

option = st.selectbox("Choose an option", ["Send Encrypted Email", "Receive and Decrypt Email"])

if option == "Send Encrypted Email":
    sender_email = st.text_input("Enter your Gmail address")
    sender_password = st.text_input("Enter your App Password (for 2FA accounts)", type="password",
                                    help="Go to Google Account > Security > App Passwords to generate this password")
    recipient = st.text_input("Enter recipient email")
    subject = st.text_input("Enter subject")
    body = st.text_area("Enter email body")

    # File upload
    uploaded_file = st.file_uploader("Attach a file", type=["txt", "pdf", "doc", "jpg", "png"])

    if st.button("Send Email"):
        aes_key = generate_aes_key()
        iv = generate_iv()

        # Prepare payload
        payload = {"message": body}
        file_attachments = []
        file_encryption_data = None

        if uploaded_file:
            file_data = uploaded_file.read()
            file_aes_key = generate_aes_key()
            file_iv = generate_iv()

            # Encrypt file
            encrypted_file, file_auth_tag = encrypt_aes(file_data, file_aes_key, file_iv)
            file_encrypted_key = encrypt_aes_key(file_aes_key, public_key)

            # Store file encryption details in database
            file_encryption_data = {
                "filename": uploaded_file.name,
                "encryptedAESKey": file_encrypted_key,
                "iv": base64.b64encode(file_iv).decode(),
                "authTag": base64.b64encode(file_auth_tag).decode()
            }

            # Add encrypted file as attachment
            file_attachments.append((uploaded_file.name, encrypted_file))

        # Encrypt payload
        encrypted_payload, auth_tag = encrypt_aes(json.dumps(payload).encode(), aes_key, iv)

        # Send email
        message_id = send_email(sender_email, sender_password, recipient, subject, encrypted_payload, file_attachments)

        if message_id:
            # Store encryption data
            document = {
                "subject": subject,
                "message_id": message_id,
                "timestamp": datetime.datetime.utcnow(),
                "encryptedAESKey": encrypt_aes_key(aes_key, public_key),
                "iv": base64.b64encode(iv).decode(),
                "authTag": base64.b64encode(auth_tag).decode()
            }
            collection.insert_one(document)

            # Store file encryption details if present
            if file_encryption_data:
                file_collection.insert_one({
                    "message_id": message_id,
                    "file_data": file_encryption_data
                })

            st.success("Encrypted email sent successfully!")

elif option == "Receive and Decrypt Email":
    sender_email = st.text_input("Enter your Gmail address")
    sender_password = st.text_input("Enter your App Password", type="password")
    subject = st.text_input("Enter the subject of the email to decrypt")

    if st.button("Retrieve and Decrypt Email"):
        encrypted_email, message_id, attachments = retrieve_email(sender_email, sender_password, subject)

        if not encrypted_email:
            st.error("Failed to retrieve encrypted email content.")
        else:
            doc = collection.find_one({"message_id": message_id})
            if doc:
                try:
                    # Decrypt payload AES key
                    encrypted_aes_key = doc["encryptedAESKey"]
                    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
                    iv = base64.b64decode(doc["iv"])
                    auth_tag = base64.b64decode(doc["authTag"])

                    # Decrypt payload
                    decrypted_payload = decrypt_aes(encrypted_email, aes_key, iv, auth_tag)
                    payload = json.loads(decrypted_payload.decode())

                    # Display message
                    st.text_area("Decrypted Message", payload.get("message"), height=200)

                    # Retrieve file encryption details from database
                    file_doc = file_collection.find_one({"message_id": message_id})
                    if file_doc and attachments:
                        file_encrypted_key = file_doc["file_data"]["encryptedAESKey"]
                        file_iv = base64.b64decode(file_doc["file_data"]["iv"])
                        file_auth_tag = base64.b64decode(file_doc["file_data"]["authTag"])
                        filename = file_doc["file_data"]["filename"]

                        file_aes_key = decrypt_aes_key(file_encrypted_key, private_key)

                        for attach_filename, encrypted_file in attachments:
                            if attach_filename == filename:
                                decrypted_file = decrypt_aes(encrypted_file, file_aes_key, file_iv, file_auth_tag)
                                st.download_button(
                                    label=f"Download decrypted {filename}",
                                    data=decrypted_file,
                                    file_name=filename
                                )
                except Exception as e:
                    st.error(f"Decryption failed: {str(e)}")
            else:
                st.error("No matching encryption data found for this email.")