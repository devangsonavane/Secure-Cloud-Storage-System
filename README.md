# 🔐 Secure Cloud Storage System with End-to-End Encryption

A fully functional Streamlit-based cloud storage system that encrypts files client-side before uploading them to AWS S3. The app provides secure registration, login, file upload, download, and deletion — all integrated with AWS DynamoDB and S3. Every file and filename is encrypted using AES-GCM, and keys are derived securely using PBKDF2-HMAC.

---

## 📌 Project Description

This application allows users to:
- Register and securely store hashed passwords with salt
- Upload files that are encrypted end-to-end (never stored as plaintext)
- Download and decrypt files using the correct password
- Delete files from S3 and associated metadata from DynamoDB
- View a list of uploaded files with metadata (name, size, timestamp)

This is ideal for users who want **secure, user-specific cloud file storage** where **AWS S3 never sees unencrypted content**.

---

## 🚀 Live Technologies Used

| Component      | Technology                          |
|----------------|--------------------------------------|
| Frontend       | [Streamlit](https://streamlit.io)    |
| Backend        | Python                               |
| Encryption     | AES-GCM (from `cryptography`)        |
| Key Derivation | PBKDF2-HMAC (SHA256)                 |
| Cloud Storage  | [Amazon S3](https://aws.amazon.com/s3/) |
| Database       | [Amazon DynamoDB](https://aws.amazon.com/dynamodb/) |
| Session State  | Streamlit's `st.session_state`       |

---

## 🧱 Features

- 🔐 Secure User Registration with Salted Password Hashing
- 🔐 Login Authentication using Hashed Credentials
- 🗂 Upload Any File Type — Encrypted Before Leaving Local Device
- 📥 Secure File Download with AES Decryption
- 🗑 File Deletion (S3 + DynamoDB cleanup)
- 🔑 Per-user Key Derivation from Password
- 📜 Metadata storage with DynamoDB
- 🔄 Auto-create AWS resources (S3 bucket + DynamoDB tables)
- 🧼 Temporary files are cleaned up automatically

---

## 🖥️ Local Setup Instructions

### 1️⃣ Clone the Repo

git clone https://github.com/devangsonavane/Secure-Cloud-Storage-System.git
cd Secure-Cloud-Storage-System

### 2️⃣ Install Required Packages

pip install -r requirements.txt

### 3️⃣ Configure AWS Credentials

Choose any one method:

#### 🔹 Option 1: Use AWS CLI

aws configure

You’ll be prompted for:
- AWS Access Key ID
- AWS Secret Access Key
- Region (e.g., `us-east-1`)

#### 🔹 Option 2: Manually Create `~/.aws/credentials`

[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY

#### 🔹 Option 3: Set Environment Variables

export AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="YOUR_SECRET_KEY"
export S3_BUCKET_NAME="secure-cloud-storage-bucket"  # Optional override

### 4️⃣ Run the App

streamlit run secure_storage.py

---

## 🔐 How Security Works

| Mechanism              | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| Password Hashing       | PBKDF2 with SHA-256 and a random 128-bit salt                               |
| Key Derivation         | Secure AES-256 key derived from password + salt using PBKDF2                |
| File Encryption        | AES-GCM (Authenticated Encryption) with a 96-bit random IV per file         |
| Filename Encryption    | AES-GCM encrypted filenames for anonymity                                   |
| Authentication         | Passwords stored as hash+salt in DynamoDB                                   |
| No Plaintext Exposure  | Files are never stored or transmitted unencrypted                           |

---

## 📂 Project Structure


secure-cloud-storage/
├── secure_storage.py        # Main Streamlit app
├── requirements.txt         # Required Python packages
└── README.md                # Project documentation


---

## 🧪 Testing Checklist

- ✅ Register a new user
- ✅ Login with valid credentials
- ✅ Upload a file — confirm it encrypts & stores in S3
- ✅ View file listing with size & upload date
- ✅ Download and decrypt file correctly
- ✅ Delete file and metadata from S3 + DynamoDB
- ✅ Handle wrong password or unauthorized access gracefully

---

## 📄 requirements.txt


streamlit
boto3
cryptography


Add this file in your project root so others can install dependencies easily.

---

## 🤖 Future Improvements

- Multi-user file sharing (encrypted key wrapping)
- Expiry-based file deletion
- Email-based password reset (with encrypted recovery)
- Activity logs and audit trail
- Web hosting via Streamlit Sharing or EC2

---

## 👨‍💻 Author

**Devang Sonavane**  
Engineering Student | Secure Systems Enthusiast  
GitHub: [devangsonavane](https://github.com/devangsonavane)

---

## 📜 License

This project is licensed under the MIT License.  
See [LICENSE](LICENSE) for more info.

---

## 🙌 Acknowledgements

- [Streamlit](https://streamlit.io/)
- [AWS S3](https://aws.amazon.com/s3/)
- [AWS DynamoDB](https://aws.amazon.com/dynamodb/)
- [Cryptography Python Library](https://cryptography.io/en/latest/)
