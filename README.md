
# Quantum-Resistant Encryption CLI Tool

This project provides a Command-Line Interface (CLI) tool designed for managing quantum-resistant encryption, integrating with AWS S3, and benchmarking performance. The tool is designed to be simple, efficient, and secure, making it ideal for users who need to manage sensitive data in a post-quantum world.

## Features

- **Quantum-Resistant Encryption:** Encrypt and decrypt data using quantum-safe encryption algorithms.
- **AWS S3 Integration:** Upload, download, list, and delete encrypted files from AWS S3.
- **Performance Benchmarking:** Evaluate the performance of the encryption and decryption processes.
- **Configuration Management:** Easily view and update AWS settings through the CLI.

## Installation

### Cloning the Repository

1. **Clone the Repository:**
   Navigate to your desired directory and clone the repository using:
   
   ```bash
   git clone https://github.com/DHARANI2D/quantum-resistant-encryption.git
   ```

### Setting Up Virtual Environment

2. **Create a Virtual Environment:**
   Navigate to your project directory and create a virtual environment using:
   ```bash
   python3 -m venv venv
   ```

3. **Activate the Virtual Environment:**
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
   - On Windows:
     ```bash
     .\venv\Scripts\activate
     ```

4. **Install Dependencies:**
   With the virtual environment activated, install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the CLI Tool:**
   With the virtual environment active, you can run your CLI tool using:
   ```bash
   python console_app.py
   ```

6. **Deactivate the Virtual Environment:**
   When you're done, deactivate the virtual environment using:
   ```bash
   deactivate
   ```

## Usage

Run the CLI tool using the following command:

```bash
python quantcrypt.py
```

### Main Menu

Upon running the tool, you'll be presented with a vibrant and colorful main menu:

<img width="473" alt="Screenshot 2024-08-16 at 10 48 45 PM" src="https://github.com/user-attachments/assets/4810bf82-a3a7-449e-8b70-97b836d2077d">

You can select any operation by entering the corresponding number.

### Encrypting Data


To encrypt data:

1. Choose option \[01\] Encrypt Data.
2. Enter the data you wish to encrypt.
3. The tool will display the encrypted data.

### Decrypting Data

To decrypt data:

1. Choose option \[02\] Decrypt Data.
2. Enter the encrypted data you wish to decrypt.
3. The tool will display the decrypted data.

### Uploading to S3

To upload a file to AWS S3:

1. Choose option \[03\] Upload to S3.
2. Enter the file name and the data to be uploaded.
3. The tool will upload the file to the configured S3 bucket.

### Downloading from S3

To download a file from AWS S3:

1. Choose option \[04\] Download from S3.
2. Enter the file name.
3. The tool will download the file and display its contents.

### Listing S3 Files

To list all files in the S3 bucket:

1. Choose option \[05\] List S3 Files.
2. The tool will display a list of files stored in the configured S3 bucket.

### Benchmarking Performance

To benchmark the performance of encryption and decryption:

1. Choose option \[06\] Benchmark Performance.
2. The tool will run a series of benchmarks and display the results.

### View and Update Configuration

You can view and update the AWS configuration directly from the CLI:

- **View Configuration:** Choose option \[07\] View Configuration.
- **Update Configuration:** Choose option \[08\] Update Configuration.

## File Structure

```plaintext
Quantum-Resistant-Encryption/
├── aws_integration/
│   ├── s3_upload.py         # Handles AWS S3 operations
│   ├── config.py            # AWS configuration settings
│   ├── lambda_deploy.py     # Handles AWS Lambda deployment
│   ├── __init__.py          # AWS Integration package initializer
├── encryption_module/
│   ├── encryption.py        # Encryption logic
│   ├── decryption.py        # Decryption logic
│   ├── key_management.py    # Key management logic
│   ├── __init__.py          # Encryption Module package initializer
├── performance_benchmark/
│   ├── benchmark.py         # Performance benchmarking logic
│   ├── __init__.py          # Performance Benchmark package initializer
├── tests/
│   ├── test_encryption.py   # Unit tests for encryption
│   ├── test_decryption.py   # Unit tests for decryption
│   ├── test_key_management.py # Unit tests for key management
│   ├── test_s3_upload.py    # Unit tests for S3 operations
│   ├── test_benchmark.py    # Unit tests for benchmarking
│   ├── __init__.py          # Tests package initializer
├── console_app.py           # Main CLI application
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation
```

## Configuration

The configuration file `config.py` stores the AWS settings required for S3 operations. You can view and update these settings through the CLI or by editing the file directly.

Example `config.py`:

```python
aws_config = {
    "AWS_ACCESS_KEY_ID": "your-access-key-id",
    "AWS_SECRET_ACCESS_KEY": "your-secret-access-key",
    "AWS_REGION": "your-region",
    "AWS_S3_BUCKET_NAME": "your-bucket-name"
}
```

## Dependencies

- Python 3.7 or higher
- boto3 (AWS SDK for Python)
- cryptography (For encryption and decryption)
- pytest (For running unit tests)

Install dependencies using:

```bash
pip install -r requirements.txt
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
