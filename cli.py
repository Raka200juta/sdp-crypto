# cli.py
import argparse
import sys
import os
import json
import struct
from sdp_crypto import generate_keypair, encrypt_to_sdp, decrypt_from_sdp

def is_sdp_encrypted(file_path):
    """
    Check if file is SDP encrypted
    Returns: True if encrypted, False if not, None if error
    """
    try:
        if not os.path.exists(file_path):
            return False
            
        file_size = os.path.getsize(file_path)
        if file_size < 40:  # Minimum SDP file size
            return False
            
        with open(file_path, 'rb') as f:
            # Read header length
            header_len_bytes = f.read(4)
            if len(header_len_bytes) != 4:
                return False
                
            header_len = struct.unpack('>I', header_len_bytes)[0]
            
            # Read header JSON
            header_json = f.read(header_len)
            if len(header_json) != header_len:
                return False
                
            # Try to parse JSON header
            try:
                header = json.loads(header_json.decode('utf-8'))
                
                # Check for SDP signature fields
                required_fields = ['version', 'filename', 'ephemeral_public_key', 'salt', 'algorithm']
                if all(field in header for field in required_fields):
                    return True
                else:
                    return False
                    
            except (json.JSONDecodeError, UnicodeDecodeError):
                return False
                
    except Exception:
        return False

def get_sdp_file_info(file_path):
    """Get detailed info about SDP encrypted file"""
    if not is_sdp_encrypted(file_path):
        return None
        
    try:
        with open(file_path, 'rb') as f:
            header_len = struct.unpack('>I', f.read(4))[0]
            header_json = f.read(header_len)
            header = json.loads(header_json.decode('utf-8'))
            
            # Get file size info
            file_size = os.path.getsize(file_path)
            header_size = 4 + header_len
            footer_size = 32  # SHA256 hash
            
            # Estimate data size
            data_size = file_size - header_size - footer_size
            
            return {
                'filename': header.get('filename', 'Unknown'),
                'original_size': header.get('file_size', 0),
                'encrypted_size': file_size,
                'algorithm': header.get('algorithm', 'Unknown'),
                'timestamp': header.get('timestamp', 'Unknown'),
                'chunk_size': header.get('chunk_size', 0),
                'total_chunks': header.get('total_chunks', 0),
                'header_size': header_size,
                'data_size': data_size,
                'footer_size': footer_size
            }
    except Exception as e:
        return None

def check_files_in_directory(directory='.'):
    """Check all files in directory for encryption status"""
    print(f"🔍 Checking encryption status in: {os.path.abspath(directory)}")
    print("=" * 60)
    
    files = os.listdir(directory)
    results = []
    
    for file in files:
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path):
            is_encrypted = is_sdp_encrypted(file_path)
            status = "✅ ENCRYPTED" if is_encrypted else "❌ NOT ENCRYPTED"
            results.append((file, status, file_path))
    
    # Sort results: encrypted first
    results.sort(key=lambda x: x[1], reverse=True)
    
    for filename, status, file_path in results:
        print(f"{status:20} {filename}")
    
    # Summary
    encrypted_count = sum(1 for _, status, _ in results if status == "✅ ENCRYPTED")
    total_count = len(results)
    
    print("=" * 60)
    print(f"📊 Summary: {encrypted_count}/{total_count} files encrypted")
    
    return results

def main():
    parser = argparse.ArgumentParser(description="SDP Crypto - File Encryption Tool")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Generate keys command
    key_parser = subparsers.add_parser('generate-keys', help='Generate key pair')
    key_parser.add_argument('--name', default='mykey', help='Key name prefix')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('--public-key', required=True, help='Public key file')
    encrypt_parser.add_argument('--output', help='Output .sdp file')
    
    # Decrypt command  
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='.sdp file to decrypt')
    decrypt_parser.add_argument('--private-key', required=True, help='Private key file')
    decrypt_parser.add_argument('--output-dir', default='.', help='Output directory')
    
    # Checker command
    check_parser = subparsers.add_parser('check', help='Check encryption status')
    check_parser.add_argument('file', nargs='?', help='File to check (optional)')
    check_parser.add_argument('--dir', default='.', help='Directory to check')
    check_parser.add_argument('--info', action='store_true', help='Show detailed info')

    args = parser.parse_args()
    
    if args.command == 'generate-keys':
        # Generate keys
        private_key, public_key = generate_keypair()
        
        with open(f"{args.name}_private.key", "wb") as f:
            f.write(private_key)
        with open(f"{args.name}_public.key", "wb") as f:
            f.write(public_key)
            
        print(f"✅ Keys generated: {args.name}_private.key, {args.name}_public.key")
        
    elif args.command == 'encrypt':
        # Encrypt file
        with open(args.public_key, "rb") as f:
            pub_key = f.read()
            
        output_file = args.output or f"{args.file}.sdp"
        
        encrypt_to_sdp(pub_key, args.file, output_file)
        print(f"✅ Encrypted: {args.file} -> {output_file}")
        
    elif args.command == 'decrypt':
        # Decrypt file
        with open(args.private_key, "rb") as f:
            priv_key = f.read()
            
        decrypted_path = decrypt_from_sdp(priv_key, args.file, args.output_dir)
        print(f"✅ Decrypted: {args.file} -> {decrypted_path}")
        
    elif args.command == 'check':
        if args.file:
            # Check single file
            file_path = args.file
            if os.path.exists(file_path):
                if is_sdp_encrypted(file_path):
                    print(f"✅ {file_path} - ENCRYPTED (.sdp format)")
                    
                    if args.info:
                        info = get_sdp_file_info(file_path)
                        if info:
                            print("\n📋 File Details:")
                            print(f"  Original filename: {info['filename']}")
                            print(f"  Original size: {info['original_size']:,} bytes")
                            print(f"  Encrypted size: {info['encrypted_size']:,} bytes")
                            print(f"  Algorithm: {info['algorithm']}")
                            print(f"  Timestamp: {info['timestamp']}")
                            print(f"  Chunk size: {info['chunk_size']:,} bytes")
                            print(f"  Total chunks: {info['total_chunks']}")
                            print(f"  Header size: {info['header_size']} bytes")
                            print(f"  Data size: {info['data_size']:,} bytes")
                            print(f"  Footer size: {info['footer_size']} bytes")
                            
                            # Calculate overhead
                            overhead = info['encrypted_size'] - info['original_size']
                            overhead_pct = (overhead / info['original_size']) * 100 if info['original_size'] > 0 else 0
                            print(f"  Encryption overhead: {overhead:,} bytes ({overhead_pct:.2f}%)")
                else:
                    print(f"❌ {file_path} - NOT ENCRYPTED")
            else:
                print(f"❌ File not found: {file_path}")
        else:
            # Check directory
            check_files_in_directory(args.dir)
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()