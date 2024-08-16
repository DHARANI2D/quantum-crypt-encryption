def encrypt(data):
    """Encrypt data (dummy implementation)."""
    if data is None:
        return ""  # Return an empty string or handle None as appropriate
    return data[::-1]

def main():
    data = "This is a test string for encryption."
    encrypted_data = encrypt(data)
    print(f"Encrypted data: {encrypted_data}")

if __name__ == "__main__":
    main()
