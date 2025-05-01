import streamlit as st
import os
import hashlib
import base64
import uuid
import tempfile
import json
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets

# AWS Setup
def initialize_aws():
    # Check if credentials are configured
    if not os.path.exists(os.path.expanduser('~/.aws/credentials')) and \
       not ('AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ):
        st.error("AWS credentials not found. Please follow the setup instructions.")
        st.stop()
    
    # Initialize S3 and DynamoDB clients
    s3 = boto3.client('s3')
    dynamodb = boto3.resource('dynamodb')
    
    # Check if bucket exists, create it if it doesn't
    bucket_name = os.environ.get('S3_BUCKET_NAME', 'secure-cloud-storage-bucket')
    try:
        s3.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            # Create the bucket
            try:
                region = boto3.session.Session().region_name
                if region == 'us-east-1':
                    s3.create_bucket(Bucket=bucket_name)
                else:
                    s3.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                st.info(f"Created new S3 bucket: {bucket_name}")
            except Exception as create_error:
                st.error(f"Failed to create S3 bucket: {str(create_error)}")
                st.stop()
        else:
            st.error(f"Error accessing S3 bucket: {str(e)}")
            st.stop()
    
    # Check if tables exist, create them if they don't
    users_table_name = 'secure_storage_users'
    files_table_name = 'secure_storage_files'
    
    try:
        # Try to create users table if it doesn't exist
        try:
            users_table = dynamodb.create_table(
                TableName=users_table_name,
                KeySchema=[{'AttributeName': 'user_id', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'user_id', 'AttributeType': 'S'},
                                      {'AttributeName': 'username', 'AttributeType': 'S'}],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'username-index',
                        'KeySchema': [{'AttributeName': 'username', 'KeyType': 'HASH'}],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                    }
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            users_table.meta.client.get_waiter('table_exists').wait(TableName=users_table_name)
            st.info(f"Created users table: {users_table_name}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceInUseException':
                raise
            users_table = dynamodb.Table(users_table_name)
        
        # Try to create files table if it doesn't exist
        try:
            files_table = dynamodb.create_table(
                TableName=files_table_name,
                KeySchema=[{'AttributeName': 'file_id', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'file_id', 'AttributeType': 'S'},
                                      {'AttributeName': 'user_id', 'AttributeType': 'S'}],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'user-id-index',
                        'KeySchema': [{'AttributeName': 'user_id', 'KeyType': 'HASH'}],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                    }
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            files_table.meta.client.get_waiter('table_exists').wait(TableName=files_table_name)
            st.info(f"Created files table: {files_table_name}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceInUseException':
                raise
            files_table = dynamodb.Table(files_table_name)
            
    except Exception as table_error:
        st.error(f"Error setting up DynamoDB tables: {str(table_error)}")
        st.stop()
    
    return s3, dynamodb, bucket_name

# Security functions
def generate_salt():
    return secrets.token_bytes(16)

def hash_password(password, salt):
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,
        dklen=32
    )
    return password_hash

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_file(file_data, key):
    iv = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(iv, file_data, None)
    return encrypted_data, iv

def decrypt_file(encrypted_data, key, iv):
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(iv, encrypted_data, None)
    return decrypted_data

def encrypt_filename(filename, key):
    iv = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    encrypted_filename = aesgcm.encrypt(iv, filename.encode('utf-8'), None)
    return encrypted_filename, iv

def decrypt_filename(encrypted_filename, key, iv):
    aesgcm = AESGCM(key)
    decrypted_filename = aesgcm.decrypt(iv, encrypted_filename, None)
    return decrypted_filename.decode('utf-8')

# User management
def register_user(username, password):
    _, dynamodb, _ = initialize_aws()
    users_table = dynamodb.Table('secure_storage_users')
    
    # Check if user exists
    response = users_table.query(
        IndexName='username-index',
        KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(username)
    )
    
    if response['Items']:
        return False, "Username already exists"
    
    # Create new user
    user_id = str(uuid.uuid4())
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    
    user_data = {
        'user_id': user_id,
        'username': username,
        'password_hash': base64.b64encode(password_hash).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'created_at': datetime.now().isoformat()
    }
    
    users_table.put_item(Item=user_data)
    return True, "User registered successfully"

def login_user(username, password):
    _, dynamodb, _ = initialize_aws()
    users_table = dynamodb.Table('secure_storage_users')
    
    # Find user by username
    response = users_table.query(
        IndexName='username-index',
        KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(username)
    )
    
    if not response['Items']:
        return False, "Invalid username or password"
    
    user = response['Items'][0]
    user_id = user['user_id']
    
    stored_hash = base64.b64decode(user['password_hash'])
    salt = base64.b64decode(user['salt'])
    
    computed_hash = hash_password(password, salt)
    
    if secrets.compare_digest(computed_hash, stored_hash):
        return True, user_id
    else:
        return False, "Invalid username or password"

# File operations
def save_file(user_id, file, password):
    s3, dynamodb, bucket_name = initialize_aws()
    users_table = dynamodb.Table('secure_storage_users')
    files_table = dynamodb.Table('secure_storage_files')
    
    # Get user salt for key derivation
    response = users_table.get_item(Key={'user_id': user_id})
    if 'Item' not in response:
        return False, "User not found"
    
    user = response['Item']
    user_salt = base64.b64decode(user['salt'])
    
    # Derive encryption key
    key = derive_key(password, user_salt)
    
    # Read and encrypt file data
    file_data = file.read()
    encrypted_data, file_iv = encrypt_file(file_data, key)
    
    # Encrypt filename
    encrypted_filename, filename_iv = encrypt_filename(file.name, key)
    
    # Generate file ID
    file_id = str(uuid.uuid4())
    
    # Create temporary file for upload
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(encrypted_data)
        temp_file_path = temp_file.name
    
    # Upload encrypted file to S3
    try:
        s3.upload_file(
            Filename=temp_file_path,
            Bucket=bucket_name,
            Key=f'files/{user_id}/{file_id}'
        )
    except Exception as e:
        os.unlink(temp_file_path)
        return False, f"Error uploading file: {str(e)}"
    
    # Delete temporary file
    os.unlink(temp_file_path)
    
    # Save metadata to DynamoDB
    file_data = {
        'file_id': file_id,
        'user_id': user_id,
        'encrypted_filename': base64.b64encode(encrypted_filename).decode('utf-8'),
        'actual_filename': file.name,  # For display purposes
        'file_iv': base64.b64encode(file_iv).decode('utf-8'),
        'filename_iv': base64.b64encode(filename_iv).decode('utf-8'),
        'created_at': datetime.now().isoformat(),
        'size': len(encrypted_data)
    }
    
    files_table.put_item(Item=file_data)
    return True, "File uploaded successfully"

def get_user_files(user_id):
    _, dynamodb, _ = initialize_aws()
    files_table = dynamodb.Table('secure_storage_files')
    
    response = files_table.query(
        IndexName='user-id-index',
        KeyConditionExpression=boto3.dynamodb.conditions.Key('user_id').eq(user_id)
    )
    
    files = []
    for item in response['Items']:
        files.append({
            'id': item['file_id'],
            'filename': item['actual_filename'],
            'created_at': item.get('created_at', datetime.now().isoformat()),
            'size': item.get('size', 0)
        })
    
    return files

def download_file(file_id, user_id, password):
    s3, dynamodb, bucket_name = initialize_aws()
    users_table = dynamodb.Table('secure_storage_users')
    files_table = dynamodb.Table('secure_storage_files')
    
    # Get file metadata
    response = files_table.get_item(Key={'file_id': file_id})
    if 'Item' not in response:
        return False, "File not found"
    
    file_data = response['Item']
    
    # Verify user owns the file
    if file_data['user_id'] != user_id:
        return False, "Unauthorized access"
    
    # Get user salt for key derivation
    response = users_table.get_item(Key={'user_id': user_id})
    if 'Item' not in response:
        return False, "User not found"
    
    user = response['Item']
    user_salt = base64.b64decode(user['salt'])
    
    # Derive encryption key
    key = derive_key(password, user_salt)
    
    # Download encrypted file
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        try:
            s3.download_file(
                Bucket=bucket_name,
                Key=f'files/{user_id}/{file_id}',
                Filename=temp_file.name
            )
        except Exception as e:
            os.unlink(temp_file.name)
            return False, f"Error downloading file: {str(e)}"
        
        temp_file_path = temp_file.name
    
    # Read encrypted data
    with open(temp_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Delete temporary file
    os.unlink(temp_file_path)
    
    # Decrypt file
    try:
        file_iv = base64.b64decode(file_data['file_iv'])
        decrypted_data = decrypt_file(encrypted_data, key, file_iv)
        return True, (file_data['actual_filename'], decrypted_data)
    except Exception as e:
        return False, f"Decryption error: {str(e)}"

def delete_file(file_id, user_id):
    s3, dynamodb, bucket_name = initialize_aws()
    files_table = dynamodb.Table('secure_storage_files')
    
    # Get file metadata
    response = files_table.get_item(Key={'file_id': file_id})
    if 'Item' not in response:
        return False, "File not found"
    
    file_data = response['Item']
    
    # Verify user owns the file
    if file_data['user_id'] != user_id:
        return False, "Unauthorized access"
    
    # Delete from S3
    try:
        s3.delete_object(
            Bucket=bucket_name,
            Key=f'files/{user_id}/{file_id}'
        )
    except Exception:
        pass  # Continue even if storage deletion fails
    
    # Delete metadata from DynamoDB
    files_table.delete_item(Key={'file_id': file_id})
    
    return True, "File deleted successfully"

# Streamlit UI
def main():
    st.set_page_config(page_title="Secure Cloud Storage", page_icon="🔒")
    
    # Session state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    
    # App title
    st.title("Secure Cloud Storage")
    st.write("End-to-End Encrypted File Storage using Amazon S3")
    
    # AWS setup check
    if not os.path.exists(os.path.expanduser('~/.aws/credentials')) and \
       not ('AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ):
        st.error("""
        AWS credentials not found. Please follow these steps:
        
        1. Create an AWS account if you don't have one
        2. Create an IAM user with S3 and DynamoDB permissions
        3. Get the access key and secret key
        4. Set up AWS credentials using one of these methods:
           - Run `aws configure` in your terminal
           - Create a credentials file at ~/.aws/credentials
           - Set environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
        """)
        st.stop()
    
    # Authentication
    if not st.session_state.logged_in:
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Login")
                
                if submit:
                    if username and password:
                        success, message = login_user(username, password)
                        if success:
                            st.session_state.logged_in = True
                            st.session_state.user_id = message
                            st.session_state.username = username
                            st.session_state.password = password  # Store for encryption/decryption
                            st.rerun()
                        else:
                            st.error(message)
                    else:
                        st.error("Please enter both username and password")
        
        with tab2:
            with st.form("register_form"):
                new_username = st.text_input("New Username")
                new_password = st.text_input("New Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                submit = st.form_submit_button("Register")
                
                if submit:
                    if new_username and new_password:
                        if new_password != confirm_password:
                            st.error("Passwords do not match")
                        else:
                            success, message = register_user(new_username, new_password)
                            if success:
                                st.success(message)
                            else:
                                st.error(message)
                    else:
                        st.error("Please enter both username and password")
    
    else:
        st.write(f"Welcome, {st.session_state.username}!")
        
        # Logout button
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.username = None
            if 'password' in st.session_state:
                del st.session_state.password
            st.rerun()
        
        # File operations
        st.subheader("Upload File")
        uploaded_file = st.file_uploader("Choose a file", type=None)
        if uploaded_file is not None:
            if st.button("Upload"):
                with st.spinner("Encrypting and uploading file..."):
                    success, message = save_file(st.session_state.user_id, uploaded_file, st.session_state.password)
                if success:
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)
        
        # List files
        st.subheader("Your Files")
        with st.spinner("Loading your files..."):
            files = get_user_files(st.session_state.user_id)
        
        if files:
            for file in files:
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.write(f"{file['filename']} ({file['size'] / 1024:.1f} KB)")
                with col2:
                    if st.button("Download", key=f"download_{file['id']}"):
                        with st.spinner("Downloading and decrypting..."):
                            success, result = download_file(file['id'], st.session_state.user_id, st.session_state.password)
                        if success:
                            filename, data = result
                            st.download_button(
                                label="Save File",
                                data=data,
                                file_name=filename,
                                mime="application/octet-stream",
                                key=f"save_{file['id']}"
                            )
                        else:
                            st.error(result)
                with col3:
                    if st.button("Delete", key=f"delete_{file['id']}"):
                        with st.spinner("Deleting file..."):
                            success, message = delete_file(file['id'], st.session_state.user_id)
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
        else:
            st.info("No files uploaded yet")

if __name__ == "__main__":
    main()