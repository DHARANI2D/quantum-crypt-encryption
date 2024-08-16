def decrypt(data):
    """Decrypt data (dummy implementation)."""
    return data[::-1]

def main():
    data = "This is a test string for encryption."
    decrypted_data = decrypt(data)
    print(f"Decrypted data: {decrypted_data}")

if __name__ == "__main__":
    main()
