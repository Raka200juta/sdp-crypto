# 🔐 SDP Crypto - File Encryption Tool

## 📖 Overview
SDP Crypto adalah alat enkripsi/dekripsi file yang aman menggunakan **ECC (X25519) + AES-GCM**. Mendukung semua jenis file (PDF, video, images, dll.) dengan ukuran tidak terbatas. Format output: `.sdp`

**Fitur Unggulan:**
- ✅ **Folder Encryption** - Encrypt seluruh folder sekaligus
- ✅ **Absolute Path Support** - File/folder di mana saja di system
- ✅ **Recursive Processing** - Include semua subfolder
- ✅ **Military-grade Encryption** - X25519 + AES-256-GCM

---

## 🚀 Quick Start

### Installation
```bash
# 1. Install dependency
pip install cryptography

# 2. Download files SDP Crypto
# - sdp_crypto/ folder (semua file .py)
# - cli.py
# - requirements.txt
```

### Basic Usage (3 Steps)
```bash
# 1. Generate keys (sekali saja)
python3 cli.py generate-keys

# 2. Encrypt file
python3 cli.py encrypt document.pdf --public-key mykey_public.key

# 3. Decrypt file
python3 cli.py decrypt document.pdf.sdp --private-key mykey_private.key
```

---

## 📋 Command Reference

### 🔑 Key Management
```bash
# Generate key pair
python3 cli.py generate-keys
python3 cli.py generate-keys --name company
```

### 🔐 Encryption

#### Single File
```bash
# Basic encryption
python3 cli.py encrypt file.pdf --public-key public.key

# Custom output name
python3 cli.py encrypt video.mp4 --public-key public.key --output encrypted.sdp
```

#### Multiple Files
```bash
# Encrypt semua PDF
python3 cli.py encrypt-multiple "*.pdf" --public-key public.key

# Encrypt berbagai tipe file
python3 cli.py encrypt-multiple "*.pdf" "*.docx" "*.xlsx" --public-key public.key
```

#### Entire Folder 🆕
```bash
# Encrypt seluruh folder
python3 cli.py encrypt-folder ~/Documents/makan --public-key public.key

# Encrypt folder dengan subfolder
python3 cli.py encrypt-folder /path/to/folder --public-key public.key --recursive

# Encrypt ke output directory khusus
python3 cli.py encrypt-folder ~/makan --public-key public.key --output-dir ~/makan_encrypted
```

### 🔓 Decryption

#### Single File
```bash
# Basic decryption
python3 cli.py decrypt file.sdp --private-key private.key

# Decrypt ke folder tertentu
python3 cli.py decrypt data.sdp --private-key private.key --output-dir decrypted_files
```

#### Multiple Files
```bash
# Decrypt semua .sdp files
python3 cli.py decrypt-multiple "*.sdp" --private-key private.key
```

#### Entire Folder 🆕
```bash
# Decrypt seluruh folder
python3 cli.py decrypt-folder ~/makan_encrypted --private-key private.key

# Decrypt folder recursive
python3 cli.py decrypt-folder ~/encrypted_data --private-key private.key --recursive

# Decrypt ke directory tertentu
python3 cli.py decrypt-folder ~/makan_encrypted --private-key private.key --output-dir ~/makan_restored
```

### 🔍 File Checking
```bash
# Check single file
python3 cli.py check document.pdf.sdp
python3 cli.py check document.pdf.sdp --info

# Check semua file di folder
python3 cli.py check --dir .
```

---

## 💡 Usage Examples

### Example 1: Personal File Protection
```bash
# Encrypt file pribadi
python3 cli.py generate-keys --name personal
python3 cli.py encrypt diary.txt --public-key personal_public.key

# Decrypt ketika diperlukan
python3 cli.py decrypt diary.txt.sdp --private-key personal_private.key
```

### Example 2: Secure File Sharing
```bash
# Sender encrypt file untuk recipient
python3 cli.py encrypt report.pdf --public-key recipient_public.key
# Kirim report.pdf.sdp ke recipient

# Recipient decrypt file
python3 cli.py decrypt report.pdf.sdp --private-key recipient_private.key
```

### Example 3: Folder Protection 🆕
```bash
# Encrypt seluruh folder project
python3 cli.py encrypt-folder ~/Projects/myapp --public-key project_public.key --recursive

# Folder akan tersimpan sebagai: ~/Projects/myapp_encrypted

# Decrypt ketika perlu edit
python3 cli.py decrypt-folder ~/Projects/myapp_encrypted --private-key project_private.key --output-dir ~/Projects/myapp_restored
```

### Example 4: Batch File Processing
```bash
# Backup semua documents
python3 cli.py encrypt-multiple "*.pdf" "*.docx" "*.xlsx" --public-key backup_public.key

# Restore semua files
python3 cli.py decrypt-multiple "*.sdp" --private-key backup_private.key
```

### Example 5: Cross-Platform Absolute Path 🆕
```bash
# Windows
python3 cli.py encrypt-folder "C:\Users\yor\Documents\makan" --public-key public.key

# Linux
python3 cli.py encrypt-folder "/home/yor/makan" --public-key public.key

# Mac
python3 cli.py encrypt-folder "/Users/yor/Documents/makan" --public-key public.key

# Relative path
python3 cli.py encrypt-folder "../makan" --public-key public.key
```

---

## 🆕 Folder Encryption Features

### Preserve Directory Structure
```
Original Folder:
/home/yor/makan/
├── resep_rendang.pdf
├── menu_restaurant.docx
└── foto_makanan/
    ├── restaurant1.jpg
    └── restaurant2.png

Encrypted Folder:
/home/yor/makan_encrypted/
├── resep_rendang.pdf.sdp
├── menu_restaurant.docx.sdp
└── foto_makanan/
    ├── restaurant1.jpg.sdp
    └── restaurant2.png.sdp
```

### Recursive Processing
```bash
# Encrypt folder dan SEMUA subfolder
python3 cli.py encrypt-folder ~/Documents --public-key public.key --recursive

# Decrypt folder dan SEMUA subfolder
python3 cli.py decrypt-folder ~/Documents_encrypted --private-key private.key --recursive
```

### Auto Output Directory
```bash
# Default: folder_encrypted
python3 cli.py encrypt-folder ~/makan --public-key public.key
# Output: ~/makan_encrypted

# Custom output directory
python3 cli.py encrypt-folder ~/makan --public-key public.key --output-dir ~/backup_encrypted
```

---

## 🛡️ Security Features

### ✅ Guaranteed Security
- **X25519** - Elliptic Curve Cryptography untuk key exchange
- **AES-256-GCM** - Authenticated encryption
- **HKDF-SHA256** - Secure key derivation
- **Per-chunk encryption** - Memory efficient untuk file besar
- **SHA256 integrity check** - File tampering detection

### 🔒 Key Management
- **Private Key** → Simpan aman, jangan dibagikan
- **Public Key** → Boleh dibagikan untuk encryption
- **Ephemeral Keys** → Key pair baru untuk setiap encryption

### 📊 File Integrity
- Automatic SHA256 verification pada decryption
- Error jika file modified/corrupted
- Original filename preservation

---

## ⚡ Advanced Usage

### Wildcard Patterns
```bash
# Support berbagai wildcard pattern
python3 cli.py encrypt-multiple "*.pdf"           # Semua PDF
python3 cli.py encrypt-multiple "*.docx" "*.xlsx" # Multiple extensions
python3 cli.py encrypt-multiple "*"               # Semua files
python3 cli.py encrypt-multiple "project/**/*"    # Recursive
```

### Large File Handling
```bash
# Auto progress tracking untuk file >100MB
# Memory efficient - process per chunk (10MB default)
# No size limits - support file sampai terabyte
```

### Path Examples 🆕
```bash
# Absolute paths
python3 cli.py encrypt-folder "/home/user/secret_docs" --public-key public.key
python3 cli.py encrypt "/home/user/videos/vacation.mp4" --public-key public.key

# Relative paths
python3 cli.py encrypt-folder "../client_files" --public-key public.key
python3 cli.py encrypt "../../reports/q1.pdf" --public-key public.key

# Network paths (jika supported OS)
python3 cli.py encrypt-folder "/mnt/nas/documents" --public-key public.key
```

---

## 🚨 Troubleshooting

### Common Issues
```bash
# Error: Module not found
pip install cryptography

# Error: File not found
python3 cli.py encrypt /full/path/to/file.pdf --public-key public.key

# Error: Invalid key
ls -la *.key  # Pastikan file exists
```

### Folder Encryption Issues 🆕
```bash
# Folder tidak ditemukan
python3 cli.py encrypt-folder /path/that/exists --public-key public.key

# Permission denied
sudo python3 cli.py encrypt-folder /protected/folder --public-key public.key

# Output directory sudah ada
python3 cli.py encrypt-folder ~/makan --public-key public.key --output-dir ~/custom_output
```

### Performance Tips
```bash
# Untuk file sangat besar, gunakan SSD storage
# Batch processing lebih efisien untuk banyak file kecil
# Network drives mungkin lebih lambat
```

---

## 📁 File Structure Examples

### Before Encryption
```
/home/yor/documents/
├── work/
│   ├── report.pdf
│   └── data.xlsx
├── personal/
│   ├── photos/
│   │   └── vacation.jpg
│   └── notes.txt
└── projects/
    └── code.py
```

### After Folder Encryption
```
/home/yor/documents_encrypted/
├── work/
│   ├── report.pdf.sdp
│   └── data.xlsx.sdp
├── personal/
│   ├── photos/
│   │   └── vacation.jpg.sdp
│   └── notes.txt.sdp
└── projects/
    └── code.py.sdp
```

### After Folder Decryption
```
/home/yor/documents_restored/
├── work/
│   ├── report.pdf
│   └── data.xlsx
├── personal/
│   ├── photos/
│   │   └── vacation.jpg
│   └── notes.txt
└── projects/
    └── code.py
```

---

## 🔧 Technical Details

### Encryption Process
1. **Generate** ephemeral X25519 key pair
2. **Key exchange** ECDH dengan recipient public key
3. **Derive** AES-256 key menggunakan HKDF-SHA256
4. **Encrypt** file per 10MB chunks dengan AES-GCM
5. **Create** header JSON dengan metadata
6. **Write** .sdp file dengan format: `[header][encrypted_chunks][sha256_hash]`

### Supported Platforms
- ✅ Windows 10/11
- ✅ macOS 10.15+
- ✅ Linux (Ubuntu, CentOS, etc.)
- ✅ Python 3.7+

### Dependencies
- `cryptography>=41.0.0` - Only one dependency!

---

## 📞 Support

### Quick Test
```bash
# Test semua functionality
python3 cli.py generate-keys --name test
echo "Hello World" > test.txt
python3 cli.py encrypt test.txt --public-key test_public.key
python3 cli.py check test.txt.sdp --info
python3 cli.py decrypt test.txt.sdp --private-key test_private.key
cat test.txt  # Should show "Hello World"
```

### Folder Test 🆕
```bash
# Test folder encryption
mkdir -p ~/test_folder/subfolder
echo "File 1" > ~/test_folder/file1.txt
echo "File 2" > ~/test_folder/subfolder/file2.txt

python3 cli.py encrypt-folder ~/test_folder --public-key test_public.key --recursive
python3 cli.py decrypt-folder ~/test_folder_encrypted --private-key test_private.key --recursive

# Verify
diff -r ~/test_folder ~/test_folder_decrypted
```

### System Check
```bash
# Verify installation
python3 --version
python3 -c "import cryptography; print(f'Cryptography: {cryptography.__version__}')"
```

### Get Help
```bash
# Show all commands
python3 cli.py --help

# Show command-specific help
python3 cli.py encrypt-folder --help
python3 cli.py decrypt-folder --help
```

---

## 🎯 Summary

**SDP Crypto memberikan:**
- ✅ **Folder Encryption** - Entire folders dengan satu command
- ✅ **Absolute Path Support** - Files di mana saja di system
- ✅ **Military-grade encryption** (X25519 + AES-256-GCM)
- ✅ **All file types & sizes** support
- ✅ **Batch processing** untuk multiple files
- ✅ **Integrity verification**
- ✅ **Simple CLI interface**
- ✅ **Cross-platform compatibility**

**Perfect untuk:**
- 🔒 **Personal file protection**
- 🏢 **Enterprise data security**
- 📁 **Folder backup encryption**
- ☁️ **Secure cloud storage**
- 🤝 **Safe file sharing**
- 💾 **Encrypted backups**

**🎉 Your files are now secure anywhere in your system!**