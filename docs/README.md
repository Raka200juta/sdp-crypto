# 🔐 SDP Crypto - File Encryption Tool

## 📖 Overview
SDP Crypto adalah alat enkripsi/dekripsi file yang aman menggunakan **ECC (X25519) + AES-GCM**. Mendukung semua jenis file (PDF, video, images, dll.) dengan ukuran tidak terbatas. Format output: `.sdp`

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

# Output: company_private.key, company_public.key
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

# Encrypt ke folder tertentu
python3 cli.py encrypt-multiple "*.jpg" --public-key public.key --output-dir encrypted_files
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

# Decrypt ke folder tertentu
python3 cli.py decrypt-multiple "*.sdp" --private-key private.key --output-dir restored_files
```

### 🔍 File Checking
```bash
# Check single file
python3 cli.py check document.pdf.sdp
python3 cli.py check document.pdf.sdp --info

# Check semua file di folder
python3 cli.py check --dir .

# Check dengan detail info
python3 cli.py check secret.sdp --info
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

### Example 3: Batch File Processing
```bash
# Backup semua documents
python3 cli.py encrypt-multiple "*.pdf" "*.docx" "*.xlsx" --public-key backup_public.key

# Restore semua files
python3 cli.py decrypt-multiple "*.sdp" --private-key backup_private.key
```

### Example 4: Project Protection
```bash
# Encrypt seluruh project
python3 cli.py encrypt-multiple "src/**/*" "docs/**/*" --public-key project_public.key --output-dir encrypted_project

# Decrypt project
python3 cli.py decrypt-multiple "encrypted_project/*.sdp" --private-key project_private.key --output-dir restored_project
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

### Validation Commands
```bash
# Check encryption status
python3 cli.py check --dir .

# Verify private key validity
python3 -c "
from cryptography.hazmat.primitives.asymmetric import x25519
key_data = open('private.key', 'rb').read()
try:
    x25519.X25519PrivateKey.from_private_bytes(key_data)
    print('✅ Private key VALID')
except:
    print('❌ Private key INVALID')
"
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

### File Size Issues
```bash
# File sangat besar (>10GB) butuh waktu lebih lama
# Progress indicator akan muncul otomatis
# Memory usage tetap rendah berkat chunk processing
```

### Performance Tips
```bash
# Untuk file sangat besar, gunakan SSD storage
# Batch processing lebih efisien untuk banyak file kecil
# Network drives mungkin lebih lambat
```

---

## 📁 File Structure

### Before Encryption
```
my_documents/
├── report.pdf
├── data.xlsx
├── presentation.pptx
└── notes.txt
```

### After Encryption
```
my_documents/
├── report.pdf          # Original (optional: delete after encrypt)
├── report.pdf.sdp      # Encrypted
├── data.xlsx.sdp       # Encrypted
├── presentation.pptx.sdp
├── notes.txt.sdp
└── keys/
    ├── private.key     # KEEP SECURE
    └── public.key      # Can share
```

### After Decryption
```
decrypted_files/
├── report.pdf          # Restored original
├── data.xlsx          # Restored original
├── presentation.pptx
└── notes.txt
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
python3 cli.py encrypt --help
python3 cli.py encrypt-multiple --help
```

---

## 🎯 Summary

**SDP Crypto memberikan:**
- ✅ Military-grade encryption (X25519 + AES-256-GCM)
- ✅ Support semua file types dan sizes
- ✅ Batch processing untuk multiple files
- ✅ Integrity verification
- ✅ Simple CLI interface
- ✅ Cross-platform compatibility

**Perfect untuk:**
- 🔒 Personal file protection
- 🏢 Enterprise data security
- ☁️ Secure cloud storage
- 🤝 Safe file sharing
- 💾 Encrypted backups

**🎉 Ready to secure your files!**