import streamlit as st
import pandas as pd
import logging
import os
from io import BytesIO
from flask import Flask
from models import db, User
import boto3
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

# Create tables
with app.app_context():
    db.create_all()

def login():
    st.title("1NCE Signal Checker Tool")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.is_admin = user.is_admin
                st.success("Logged in successfully!")
                logger.info(f"User {username} logged in successfully")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")
                logger.warning(f"Failed login attempt for username: {username}")

def new_check():
    st.title("Submit a new Signal Check")
    st.write("Please upload a CSV file that contains at least longitude and latitude columns to start a new Signal Check.")
    
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        # Read the CSV file
        df = pd.read_csv(uploaded_file)
        
        # Get the number of rows (excluding header)
        num_rows = len(df)
        
        # Save the file locally
        file_path = os.path.join("uploads", uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Prepare file for upload
        file_buffer = BytesIO()
        df.to_csv(file_buffer, index=False)
        file_buffer.seek(0)
        
        # Check if file already exists in S3
        try:
            s3 = boto3.client('s3',
                aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
            )
            bucket_name = os.environ['S3_BUCKET_NAME']
            s3_file_key = f"uploads/{uploaded_file.name}"
            
            try:
                s3.head_object(Bucket=bucket_name, Key=s3_file_key)
                st.error(f"A file with the name '{uploaded_file.name}' already exists in S3. Please rename your file and try again.")
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == '404':
                    # File doesn't exist, proceed with upload
                    metadata = {'user': st.session_state.username}
                    s3.upload_fileobj(file_buffer, bucket_name, s3_file_key, ExtraArgs={'Metadata': metadata})
                    st.success(f"File uploaded successfully to S3. S3 File Key: {s3_file_key}")
                    st.success(f"Number of rows (excluding header): {num_rows}")
                else:
                    # Something else went wrong
                    st.error(f"An error occurred while checking for existing files: {str(e)}")
        except Exception as e:
            st.error(f"Failed to upload file to S3: {str(e)}")
    else:
        st.info("Please upload a CSV file to proceed.")

def running_check():
    st.title("Check Status of Signal Checks")
    st.write("This page shows all ongoing Signal Checks and allows Admins to mark Checks as completed.")
    
    try:
        # Initialize S3 client
        s3 = boto3.client('s3',
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
        )
        
        # List objects in the 'uploads/' prefix of the S3 bucket
        bucket_name = os.environ['S3_BUCKET_NAME']
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix='uploads/')
        
        if 'Contents' in response:
            st.subheader("Files in S3 bucket:")
            for obj in response['Contents']:
                # Get object metadata
                metadata = s3.head_object(Bucket=bucket_name, Key=obj['Key'])['Metadata']
                file_user = metadata.get('user', 'Unknown')
                
                # Check if the current user is an admin or the file owner
                if st.session_state.is_admin or file_user == st.session_state.username:
                    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
                    col1.write(obj['Key'])
                    col2.write(f"User: {file_user}")
                    
                    if col3.button("Delete", key=f"delete_{obj['Key']}"):
                        try:
                            s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                            st.success(f"File {obj['Key']} deleted successfully.")
                            st.experimental_rerun()
                        except Exception as e:
                            st.error(f"Failed to delete file {obj['Key']}: {str(e)}")
                    
                    if st.session_state.is_admin and col4.button("Mark Complete", key=f"complete_{obj['Key']}"):
                        try:
                            # Copy the object to the 'completed/' folder
                            new_key = f"completed/{obj['Key'].split('/')[-1]}"
                            s3.copy_object(Bucket=bucket_name, CopySource={'Bucket': bucket_name, 'Key': obj['Key']}, Key=new_key)
                            
                            # Delete the object from the 'uploads/' folder
                            s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                            
                            st.success(f"File {obj['Key']} marked as complete and moved to 'completed/' folder.")
                            st.experimental_rerun()
                        except Exception as e:
                            st.error(f"Failed to mark file {obj['Key']} as complete: {str(e)}")
        else:
            st.info("No files found in the S3 bucket.")
    
    except Exception as e:
        st.error(f"Failed to list files from S3: {str(e)}")

def completed_checks():
    st.title("Completed Checks")
    st.write("This page shows the list of completed signal checks.")
    
    try:
        # Initialize S3 client
        s3 = boto3.client('s3',
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
        )
        
        # List objects in the 'completed/' prefix of the S3 bucket
        bucket_name = os.environ['S3_BUCKET_NAME']
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix='completed/')
        
        if 'Contents' in response:
            st.subheader("Completed files in S3 bucket:")
            for obj in response['Contents']:
                # Get object metadata
                metadata = s3.head_object(Bucket=bucket_name, Key=obj['Key'])['Metadata']
                file_user = metadata.get('user', 'Unknown')
                
                col1, col2 = st.columns([2, 1])
                col1.write(obj['Key'])
                col2.write(f"User: {file_user}")
        else:
            st.info("No completed files found in the S3 bucket.")
    
    except Exception as e:
        st.error(f"Failed to list completed files from S3: {str(e)}")

def user_management():
    st.title("User Management")
    st.write("This page allows you to manage users. Only accessible for Admin Users.")
    
    # List all users
    with app.app_context():
        users = User.query.all()
        for user in users:
            st.write(f"Username: {user.username}, Admin: {user.is_admin}")
    
    # Add new user
    st.subheader("Add New User")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    is_admin = st.checkbox("Is Admin")
    if st.button("Add User"):
        with app.app_context():
            new_user = User(username=new_username, is_admin=is_admin)
            new_user.set_password(new_password)
            db.session.add(new_user)
            db.session.commit()
        st.success(f"User {new_username} added successfully!")
    
    # Update user password
    st.subheader("Update User Password")
    update_username = st.selectbox("Select User", [user.username for user in users])
    new_password = st.text_input("New Password", type="password", key="update_password")
    if st.button("Update Password"):
        with app.app_context():
            user = User.query.filter_by(username=update_username).first()
            if user:
                user.set_password(new_password)
                db.session.commit()
                st.success(f"Password updated for user {update_username}")
            else:
                st.error("User not found")

def get_s3_file_counts():
    try:
        s3 = boto3.client('s3',
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
        )
        bucket_name = os.environ['S3_BUCKET_NAME']
        
        uploads_response = s3.list_objects_v2(Bucket=bucket_name, Prefix='uploads/')
        completed_response = s3.list_objects_v2(Bucket=bucket_name, Prefix='completed/')
        
        uploads_count = uploads_response.get('KeyCount', 0)
        completed_count = completed_response.get('KeyCount', 0)
        
        return uploads_count, completed_count
    except Exception as e:
        logger.error(f"Failed to get S3 file counts: {str(e)}")
        return 0, 0

def main():
    try:
        if 'logged_in' not in st.session_state:
            st.session_state.logged_in = False
        
        if not st.session_state.logged_in:
            login()
        else:
            st.sidebar.title("1NCE Signal Checker")
            st.sidebar.write(f"Logged in as: {st.session_state.username}")
            pages = ["New Check", "Running Check", "Completed Checks"]
            if st.session_state.is_admin:
                pages.append("User Management")
            page = st.sidebar.radio("Go to", pages)
            
            # Get and display S3 file counts
            uploads_count, completed_count = get_s3_file_counts()
            st.sidebar.write(f"Checks in progress: {uploads_count}")
            st.sidebar.write(f"Checks completed: {completed_count}")
            
            if page == "New Check":
                new_check()
            elif page == "Running Check":
                running_check()
            elif page == "Completed Checks":
                completed_checks()
            elif page == "User Management" and st.session_state.is_admin:
                user_management()
            
            if st.sidebar.button("Logout"):
                st.session_state.logged_in = False
                st.session_state.username = None
                st.session_state.is_admin = False
                logger.info("User logged out")
                st.experimental_rerun()
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        st.error("An unexpected error occurred. Please try again later.")

if __name__ == "__main__":
    main()