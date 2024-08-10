import hashlib
import os

def generate_random_file_hash(file_size=1024, hash_algorithm='sha256'):
    """
    Generate a random file-like byte sequence and calculate its hash.

    :param file_size: Size of the random file in bytes. Default is 1024 bytes.
    :param hash_algorithm: Hashing algorithm to use (e.g., 'sha256', 'md5'). Default is 'sha256'.
    :return: The computed hash of the random file content.
    """
    # Generate random bytes
    random_data = os.urandom(file_size)

    # Select the hash algorithm
    if hash_algorithm.lower() == 'sha256':
        hash_func = hashlib.sha256()
    elif hash_algorithm.lower() == 'md5':
        hash_func = hashlib.md5()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

    # Update the hash function with the random data
    hash_func.update(random_data)

    # Return the hex digest of the hash
    return hash_func.hexdigest()

if __name__ == "__main__":
    # Generate a random file hash
    random_hash = generate_random_file_hash(file_size=2048)  # Example with a 2KB random file
    print(f"Generated Random File Hash (SHA-256): {random_hash}")
