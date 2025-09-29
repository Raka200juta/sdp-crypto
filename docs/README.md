# 📘 SDP CRYPTO - USER MANUAL

## 🎯 **OVERVIEW**
SDP Crypto adalah alat enkripsi/dekripsi file yang aman menggunakan **ECC (X25519) + AES-GCM**. Format output: `.sdp`

**Fitur Utama:**
- ✅ Enkripsi file apa saja (PDF, video, images, dll.)
- ✅ Ukuran file tidak terbatas
- ✅ Integritas data terjamin (SHA256 verification)
- ✅ CLI yang mudah digunakan

---

## 🚀 **INSTALASI CEPAT**

### **1. Prerequisites**
```bash
# Pastikan Python 3.7+ terinstall
python3 --version

# Install dependency
pip install cryptography
```

### **2. Download Files**
Download file-file berikut:
```
sdp_crypto/
├── __init__.py
├── core.py
├── key_utils.py
├── chunking.py
└── format.py
cli.py
requirements.txt
```

---

## 🔑 **GENERATE KEY PAIR**

**Generate sekali untuk semua file:**

```bash
# Generate key dengan nama default
python3 cli.py generate-keys

# Generate key dengan custom name
python3 cli.py generate-keys --name mycompany

# Generate key untuk user tertentu
python3 cli.py generate-keys --name alice
```

**Output:**
```
✅ Keys generated: mykey_private.key, mykey_public.key
```

**Keterangan:**
- 🔒 `private.key` → **SIMPAN AMAN**, jangan dibagikan
- 🔓 `public.key` → Boleh dibagikan untuk encrypt

---

## 🔐 **ENKRIPSI FILE**

### **Basic Usage**
```bash
# Encrypt file (auto output: filename.sdp)
python3 cli.py encrypt document.pdf --public-key public.key
```

### **Advanced Options**
```bash
# Encrypt dengan custom output name
python3 cli.py encrypt video.mp4 --public-key public.key --output encrypted_video.sdp

# Encrypt ke path tertentu
python3 cli.py encrypt data.xlsx --public-key public.key --output /path/to/encrypted/data.sdp
```

**Output:**
```
✅ Encrypted: document.pdf -> document.pdf.sdp
```

---

## 🔓 **DEKRIPSI FILE**

### **Basic Usage**
```bash
# Decrypt file (output ke current directory)
python3 cli.py decrypt file.sdp --private-key private.key
```

### **Advanced Options**
```bash
# Decrypt ke folder tertentu
python3 cli.py decrypt data.sdp --private-key private.key --output-dir decrypted_files

# Decrypt dengan path lengkap
python3 cli.py decrypt /path/to/file.sdp --private-key /path/to/private.key
```

**Output:**
```
✅ Decrypted: file.sdp -> ./original_filename.pdf
```

---

## 🔍 **CHECK ENCRYPTION STATUS**

### **Check Single File**
```bash
# Cek status file
python3 cli.py check document.pdf.sdp

# Cek dengan detail info
python3 cli.py check secret.sdp --info
```

### **Check All Files in Directory**
```bash
# Check semua file di current directory
python3 cli.py check --dir .

# Check directory tertentu
python3 cli.py check --dir /path/to/files
```

**Contoh Output:**
```
🔍 Checking encryption status in: /home/user/documents
============================================================
✅ ENCRYPTED          financial.pdf.sdp
✅ ENCRYPTED          backup.zip.sdp  
❌ NOT ENCRYPTED      notes.txt
❌ NOT ENCRYPTED      image.jpg
============================================================
📊 Summary: 2/4 files encrypted
```

---

## ⚡ **WORKFLOW EXAMPLES**

### **Workflow 1: File Pribadi**
```bash
# Untuk encrypt file pribadi
python3 cli.py generate-keys --name personal
python3 cli.py encrypt diary.txt --public-key personal_public.key
# File aman: diary.txt.sdp

# Untuk buka kembali
python3 cli.py decrypt diary.txt.sdp --private-key personal_private.key
```

### **Workflow 2: Berbagi File Aman**
```bash
# Anda generate keys
python3 cli.py generate-keys --name company
# Bagikan company_public.key ke teman

# Teman encrypt file untuk Anda
python3 cli.py encrypt laporan.pdf --public-key company_public.key
# Kirim laporan.pdf.sdp ke Anda

# Anda decrypt file dari teman
python3 cli.py decrypt laporan.pdf.sdp --private-key company_private.key
```

### **Workflow 3: Batch Processing**
```bash
# Encrypt semua PDF di folder
for file in *.pdf; do
    python3 cli.py encrypt "$file" --public-key public.key
done

# Decrypt semua .sdp files
for file in *.sdp; do
    python3 cli.py decrypt "$file" --private-key private.key --output-dir restored
done
```

### **Workflow 4: Encrypt Multiple Files**
```bash
# Encrypt semua PDF files
python3 cli.py encrypt-multiple "*.pdf" --public-key public.key

# Encrypt semua files dengan ekstensi tertentu
python3 cli.py encrypt-multiple "*.pdf" "*.docx" "*.xlsx" --public-key public.key

# Encrypt ke directory tertentu
python3 cli.py encrypt-multiple "*.jpg" "*.png" --public-key public.key --output-dir encrypted_images

# Encrypt files spesifik
python3 cli.py encrypt-multiple file1.pdf file2.docx report.xlsx --public-key public.key

# Encrypt semua files di folder (gunakan wildcard)
python3 cli.py encrypt-multiple "*" --public-key public.key
```

### **Workflow 5: Decrypt Multiple Files**
```bash
# Decrypt semua .sdp files
python3 cli.py decrypt-multiple "*.sdp" --private-key private.key

# Decrypt ke directory tertentu
python3 cli.py decrypt-multiple "*.sdp" --private-key private.key --output-dir decrypted_files

# Decrypt files spesifik
python3 cli.py decrypt-multiple file1.pdf.sdp file2.docx.sdp --private-key private.key
```

### **Workflow 6: Batch Processing Examples**
```bash
# Backup semua documents
python3 cli.py encrypt-multiple "*.pdf" "*.docx" "*.xlsx" --public-key backup_public.key --output-dir backup_encrypted

# Restore semua files
python3 cli.py decrypt-multiple "backup_encrypted/*.sdp" --private-key backup_private.key --output-dir restored

# Encrypt project folder
python3 cli.py encrypt-multiple "project/**/*" --public-key project_public.key --output-dir project_encrypted
```

### **Workflow 6: Batch Processing Examples**
```bash
# 1. Generate keys
python3 cli.py generate-keys --name project

# 2. Encrypt semua file project
python3 cli.py encrypt-multiple "*.py" "*.md" "*.json" --public-key project_public.key --output-dir encrypted_project

# 3. Check hasil
python3 cli.py check --dir encrypted_project

# 4. Decrypt ketika diperlukan
python3 cli.py decrypt-multiple "encrypted_project/*.sdp" --private-key project_private.key --output-dir restored_project
```

---

## 🛡️ **SECURITY BEST PRACTICES**

### **✅ DO**
- Simpan private key di tempat aman
- Gunakan password manager untuk private key
- Hapus file original setelah encrypt
- Backup private key di tempat aman
- Verify file setelah decrypt

### **❌ DON'T**
- Jangan bagikan private key
- Jangan simpan private key di cloud tanpa encryption
- Jangan hapus file .sdp sebelum decrypt sukses
- Jangan gunakan private key yang sama untuk semua purpose

---

## 🚨 **TROUBLESHOOTING**

### **Error: Module not found**
```bash
pip install cryptography
```

### **Error: File not found**
```bash
# Gunakan full path
python3 cli.py encrypt /full/path/to/file.pdf --public-key public.key
```

### **Error: Invalid key**
```bash
# Pastikan key file exists
ls -la *.key

# Key harus 32 bytes
python3 -c "print('Key size:', len(open('private.key', 'rb').read()), 'bytes')"
```

### **File besar (>1GB)**
```bash
# Auto handle, progress akan muncul otomatis
# Butuh waktu lebih lama untuk file sangat besar
```

---

## 📊 **FILE MANAGEMENT**

### **Structure Sebelum/Sesudah**
```
documents/
├── laporan.pdf          # File asli
├── data.xlsx           # File asli
├── laporan.pdf.sdp     # File encrypted (setelah encrypt)
├── data.xlsx.sdp       # File encrypted (setelah encrypt)
└── keys/
    ├── private.key     # SIMPAN AMAN
    └── public.key      # Boleh dibagikan
```

### **Setelah Decrypt**
```
decrypted/
├── laporan.pdf         # File asli (restored)
└── data.xlsx          # File asli (restored)
```

---

## 🔧 **VALIDASI KEY**

### **Cek Validitas Private Key**
```bash
# Buat validator sederhana
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

### **Test Key dengan Encrypt/Decrypt**
```bash
echo 'test' > test.txt
python3 cli.py encrypt test.txt --public-key public.key
python3 cli.py decrypt test.txt.sdp --private-key private.key
# Jika berhasil → key valid
```

## **WILDCARD SUPPORT**
Mendukung semua wildcard pattern:

- *.pdf - Semua PDF files

- *.docx - Semua Word documents

- *.* - Semua files dengan ekstensi

- * - Semua files

- project/**/* - Recursive (semua files di folder project)

- file?.txt - Pattern matching

---

## 🎯 **QUICK START SCRIPT**

```bash
#!/bin/bash
# quick_test.sh - Test semua functionality

echo "🧪 SDP Crypto Quick Test"
python3 cli.py generate-keys --name quicktest
echo "Secret data" > testfile.txt
python3 cli.py encrypt testfile.txt --public-key quicktest_public.key
python3 cli.py check testfile.txt.sdp --info
python3 cli.py decrypt testfile.txt.sdp --private-key quicktest_private.key
echo "Decrypted content:"
cat testfile.txt
rm testfile.txt testfile.txt.sdp quicktest_*.key
echo "✅ Test completed successfully!"
```

---

## 📞 **SUPPORT**

### **Test Basic Functionality**
```bash
python3 cli.py generate-keys --name test
echo "Hello World" > hello.txt
python3 cli.py encrypt hello.txt --public-key test_public.key
python3 cli.py decrypt hello.txt.sdp --private-key test_private.key
cat hello.txt  # Should show "Hello World"
```

### **Check System**
```bash
python3 --version
python3 -c "import cryptography; print(f'Cryptography: {cryptography.__version__}')"
```

---

**🎉 SELAMAT!** Anda sekarang bisa mengamankan file dengan enkripsi yang kuat. Untuk pertanyaan tambahan, lihat troubleshooting section atau buat issue baru.

**Keywords:** file encryption, ECC, AES-GCM, X25519, cybersecurity, data protection