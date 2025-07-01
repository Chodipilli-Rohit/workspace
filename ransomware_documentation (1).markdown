# Ransomware Simulation Project Documentation

## Overview
This project demonstrates a controlled ransomware simulation using Python and AES-256 encryption in CBC mode. It is designed for educational purposes to understand malware behavior and defense mechanisms. The code includes secure key handling, file encryption/decryption, and basic code obfuscation. The simulation targets a test folder with specific file extensions (.txt, .doc, .pdf) and includes a working decryptor.

**Warning**: This code is for educational purposes only and should only be run in a controlled, isolated environment (e.g., a virtual machine) to prevent accidental data loss.

## Features
1. **AES Encryption**: Uses AES-256 in CBC mode to encrypt files securely.
2. **Secure Key Handling**: Generates a 256-bit key, obfuscates it using base64 encoding, and stores it in a file.
3. **File Targeting**: Encrypts files with specific extensions (.txt, .doc, .pdf) in a target directory.
4. **Decryptor**: Includes a decryption module to restore encrypted files.
5. **Code Obfuscation**: Implements basic obfuscation by encoding the encryption key.
6. **Logging**: Logs actions for debugging and monitoring.

## Requirements
- Python 3.8+
- `pycryptodome` library (`pip install pycryptodome`)
- Test environment (e.g.,彼此

System: virtual machine)

## How It Works
1. **Setup**: The script creates a test directory (`test_folder`) with sample text files for simulation.
2. **Key Generation**: A 256-bit AES key is generated and saved as a base64-encoded string in `key.txt`.
3. **Encryption**:
   - The script walks through the target directory, identifies files with specified extensions, and encrypts them using AES-256 in CBC mode.
   - Each file is padded, encrypted with a random IV, and saved with a `.enc` extension. The original file is deleted.
4. **Decryption**:
   - The decryptor loads the key from `key.txt`, decodes it, and decrypts `.enc` files, removing padding and restoring the original files.
5. **Obfuscation**: The key is stored in base64 format to obscure its raw form, providing a basic layer of obfuscation.

## Usage
1. Install the required library: `pip install pycryptodome`
2. Run the script: `python ransomware_simulation.py`
3. The script:
   - Creates a `test_folder` with sample files.
   - Encrypts the files, creating `.enc` versions.
   - Decrypts the `.enc` files to restore the originals.
4. Check the `key.txt` file for the encryption key and logs for debugging output.

## Defense Mechanisms
To defend against real ransomware, consider the following:
- **Regular Backups**: Maintain offline or cloud-based backups to restore data without paying the ransom.
- **Antivirus Software**: Use up-to-date antivirus to detect and block malicious code.
- **User Training**: Educate users to avoid phishing emails and suspicious downloads.
- **Access Controls**: Limit file access to prevent unauthorized encryption.
- **Network Segmentation**: Isolate critical systems to limit ransomware spread.

## Limitations
- This is a simplified simulation and does not include advanced persistence mechanisms, network communication, or ransom notes.
- The obfuscation is basic (base64 encoding) and not production-grade.
- The script targets only specific file extensions for demonstration purposes.

## Ethical Considerations
This project is for educational purposes only. Unauthorized use of ransomware-like code is illegal and unethical. Always obtain explicit permission before testing in any environment.