# File Encryption
### 📖 Detailed User Manual

#### Environmental preparedness
1. Install Python 3.8+
2. Install dependency libraries：
```bash
pip install cryptography tqdm
```

#### Basic usage

🔒 **Encrypted file**：
```bash
python file_cipher.py -e -i Sensitive_file.pdf
```
The procedure will:
1. Prompt for password (not displayed when entered)
2, Generate encrypted Files "Sensitive_Files.pdf.enc"
3. Show encrypted progress bar

🔓 **Declassified documents**：
```bash
python file_cipher.py -d -i Sensitive_file.pdf.enc
```
The procedure will:
1. Prompt for a password
2. Generate decrypted files "sensitive_files. pdf. dec"
3. Show decryption progress bar
4. Automatic Verification of Document Integrity
   
🔓 **Parameter**：
  -h, --help            Show this help message and exit
  -e, --encrypt         Encryption mode
  -d, --decrypt         Decryption mode
  -i INPUT [INPUT ...], --input INPUT [INPUT ...]
                        Input file path (multiple files supported)
  -o OUTPUT, --output OUTPUT
                        Output directory path (optional )
  -r, --recursive       Recursive Processing Directory

#### Advanced options

📂 **Specify the output file**：
```bash
python file_cipher.py -e -i data.xlsx -o secured_data.enc
python file_cipher.py -d -i secured_data.enc -o decrypted.xlsx
```
📂 **Bulk encryption file**：
```bashi
python file_cipher.py -e -i Encryption_directory -o Output_directory --recursive
```
   - Entering the password will recursively encrypt all files (including subdirectories) under the 'test' tree directory
   - The encrypted files are stored in the `encrypted` directory, maintaining the original directory structure
   - For example：
     ```
     c:/apps/test/doc/secret.txt 
     → c:/apps/encrypted/doc/secret.txt.enc
     ```
📂 **Bulk decryption file**：
```bashi
python file_cipher.py -d -i Encryption_directory -o Output_directory --recursive
```

🔐 **Password Security Features**：
- The recommended password length is at least 12 characters
- Support for special characters and spaces
- A password error will immediately stop decryption


#### ⚠️ Important note

1. **Password Management**：
   - Lost Password Will Result Data Permanently Unrecoverable
   - Recommended Use Password Manager to Save Password

2. **File extension**：
   - encrypted files are automatically added with the ".enc" extension
   - decrypt file to automatically add ".dec" extension

3. **Exception Handling**：
   - Press Ctrl + C to safely abort the operation
   - Network Drive recommendation to copy to local operation first
     
4. **Symbolic Link Processing**：
   - Does not follow symbolic links by default (additional code support required )
   
5. **Empty directory retention**：
   - Empty directories will not be preserved after encryption (to be handled separately)
     
6. **Permission issues**：
   - Windows systems need to run as an administrator to encrypt system files

