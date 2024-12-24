#!/usr/bin/env python3
# Bitcoin Wallet Implementation
# Created: 2024-12-24 15:09:46 UTC
# Author: BRO200BS
# Version: 1.0.0

import os
import sys
import json
import time
import hmac
import getpass
import logging
import secrets
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Third-party imports with error handling
try:
    from Crypto.Hash import SHA256, RIPEMD160
    import base58
    import ecdsa
    from bech32 import bech32_encode, bech32_decode, convertbits
    from mnemonic import Mnemonic
    import qrcode
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as e:
    print(f"Error: Required package not found: {e}")
    print("Please install required packages using:")
    print("pip install pycryptodome base58 ecdsa mnemonic qrcode cryptography")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bitcoin_wallet.log'),
        logging.StreamHandler()
    ]
)

class WalletConfig:
    """Wallet configuration and constants"""
    
    NETWORKS = {
        'mainnet': {
            'name': 'mainnet',
            'pubkey_version': '00',
            'script_version': '05',
            'privkey_version': '80',
            'bech32_hrp': 'bc',
            'xprv_version': '0488ade4',
            'xpub_version': '0488b21e'
        },
        'testnet': {
            'name': 'testnet',
            'pubkey_version': '6F',
            'script_version': 'C4',
            'privkey_version': 'EF',
            'bech32_hrp': 'tb',
            'xprv_version': '04358394',
            'xpub_version': '043587cf'
        }
    }

    # Security parameters
    ENCRYPTION_ITERATIONS = 200000
    KEY_LENGTH = 32
    SALT_LENGTH = 32
    
    # Default paths
    DEFAULT_WALLET_DIR = Path.home() / '.bitcoin_wallet'
    
    @classmethod
    def get_network(cls, testnet: bool = False) -> dict:
        """Get network configuration"""
        return cls.NETWORKS['testnet' if testnet else 'mainnet']

class WalletSecurity:
    """Handle wallet security operations"""
    
    @staticmethod
    def generate_secure_password() -> str:
        """Generate a cryptographically secure password"""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(charset) for _ in range(32))

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(WalletConfig.SALT_LENGTH)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=WalletConfig.KEY_LENGTH,
            salt=salt,
            iterations=WalletConfig.ENCRYPTION_ITERATIONS
        )
        key = kdf.derive(password.encode())
        return key, salt

    @staticmethod
    def encrypt_data(data: str, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return ciphertext, encryptor.tag, iv

    @staticmethod
    def decrypt_data(ciphertext: bytes, tag: bytes, iv: bytes, key: bytes) -> str:
        """Decrypt data using AES-256-GCM"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

class BitcoinKeyGenerator:
    """Handle Bitcoin key generation and derivation"""
    
    def __init__(self, testnet: bool = False):
        self.network = WalletConfig.get_network(testnet)
        self.mnemo = Mnemonic("english")
def generate_mnemonic(self, strength: int = 256) -> str:
        """Generate a BIP39 mnemonic phrase"""
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("Invalid strength. Must be one of: 128, 160, 192, 224, 256")
        return self.mnemo.generate(strength=strength)

    def generate_seed_from_mnemonic(self, mnemonic: str, passphrase: str = "") -> bytes:
        """Generate seed from mnemonic phrase"""
        if not self.mnemo.check(mnemonic):
            raise ValueError("Invalid mnemonic phrase")
        return Mnemonic.to_seed(mnemonic, passphrase)

    def generate_master_key_pair(self, seed: bytes) -> Dict[str, str]:
        """Generate master private and public key pair"""
        # Generate master private key
        h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
        master_private_key = h[:32]
        chain_code = h[32:]

        # Generate master public key
        signing_key = ecdsa.SigningKey.from_string(master_private_key, curve=ecdsa.SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        
        return {
            'private_key': master_private_key.hex(),
            'public_key': verifying_key.to_string().hex(),
            'chain_code': chain_code.hex()
        }

class BitcoinAddress:
    """Handle Bitcoin address generation and validation"""

    def __init__(self, testnet: bool = False):
        self.network = WalletConfig.get_network(testnet)

    def generate_addresses(self, public_key: str) -> Dict[str, str]:
        """Generate all supported address types"""
        try:
            # Convert public key to bytes
            pub_key_bytes = bytes.fromhex(public_key)
            
            addresses = {
                'p2pkh': self._generate_p2pkh_address(pub_key_bytes),
                'p2sh_p2wpkh': self._generate_p2sh_p2wpkh_address(pub_key_bytes),
                'bech32': self._generate_bech32_address(pub_key_bytes)
            }
            
            # Generate QR codes for each address
            self._generate_address_qrcodes(addresses)
            
            return addresses
        
        except Exception as e:
            logging.error(f"Address generation failed: {str(e)}")
            raise

    def _generate_p2pkh_address(self, public_key: bytes) -> str:
        """Generate P2PKH address"""
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
        
        # Add version byte
        version_hash = bytes.fromhex(self.network['pubkey_version']) + ripemd160_hash
        
        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(version_hash).digest()).digest()[:4]
        
        # Combine and encode in base58
        binary_address = version_hash + checksum
        return base58.b58encode(binary_address).decode()

    def _generate_p2sh_p2wpkh_address(self, public_key: bytes) -> str:
        """Generate P2SH-P2WPKH address"""
        # Hash public key
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
        
        # Create redeem script
        redeem_script = bytes([0x00, 0x14]) + ripemd160_hash
        
        # Hash redeem script
        script_sha256 = hashlib.sha256(redeem_script).digest()
        script_ripemd160 = RIPEMD160.new(script_sha256).digest()
        
        # Add version byte
        version_hash = bytes.fromhex(self.network['script_version']) + script_ripemd160
        
        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(version_hash).digest()).digest()[:4]
        
        # Combine and encode in base58
        binary_address = version_hash + checksum
        return base58.b58encode(binary_address).decode()

    def _generate_bech32_address(self, public_key: bytes) -> str:
        """Generate Native SegWit (Bech32) address"""
        # Hash public key
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
        
        # Convert to 5-bit format
        converted_bits = convertbits(ripemd160_hash, 8, 5)
        if converted_bits is None:
            raise ValueError("Failed to convert bits for Bech32 address")
            
        # Encode as Bech32
        return bech32_encode(self.network['bech32_hrp'], converted_bits)

    def _generate_address_qrcodes(self, addresses: Dict[str, str]) -> None:
        """Generate QR codes for addresses"""
        try:
            qr_dir = WalletConfig.DEFAULT_WALLET_DIR / 'qrcodes'
            qr_dir.mkdir(parents=True, exist_ok=True)
            
            for addr_type, address in addresses.items():
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(address)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="black", back_color="white")
                img.save(qr_dir / f"{addr_type}_qr.png")
                
        except Exception as e:
            logging.warning(f"Failed to generate QR codes: {str(e)}")

class WalletStorage:
    """Handle wallet storage operations"""
    
    def __init__(self, wallet_dir: Path = None):
        self.wallet_dir = wallet_dir or WalletConfig.DEFAULT_WALLET_DIR
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
def save_wallet(self, wallet_data: dict, filename: str, password: str) -> None:
        """Save encrypted wallet data"""
        try:
            # Generate encryption key and salt
            key, salt = WalletSecurity.derive_key(password)
            
            # Prepare wallet data with metadata
            wallet_data.update({
                'last_modified': datetime.now(timezone.utc).isoformat(),
                'last_modified_by': 'BRO200BS',
                'version': '1.0.0'
            })
            
            # Convert wallet data to JSON
            json_data = json.dumps(wallet_data, indent=2)
            
            # Encrypt the data
            ciphertext, tag, iv = WalletSecurity.encrypt_data(json_data, key)
            
            # Prepare final encrypted wallet file content
            encrypted_data = {
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode(),
                'tag': base64.b64encode(tag).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'created_at': datetime.now(timezone.utc).isoformat(),
                'created_by': 'BRO200BS'
            }
            
            # Save to file
            wallet_path = self.wallet_dir / f"{filename}.wallet"
            with open(wallet_path, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
            
            logging.info(f"Wallet saved successfully to {wallet_path}")
            
        except Exception as e:
            logging.error(f"Failed to save wallet: {str(e)}")
            raise

    def load_wallet(self, filename: str, password: str) -> dict:
        """Load and decrypt wallet data"""
        try:
            wallet_path = self.wallet_dir / f"{filename}.wallet"
            
            if not wallet_path.exists():
                raise FileNotFoundError(f"Wallet file not found: {wallet_path}")
            
            # Read encrypted data
            with open(wallet_path, 'r') as f:
                encrypted_data = json.load(f)
            
            # Decode components
            salt = base64.b64decode(encrypted_data['salt'])
            iv = base64.b64decode(encrypted_data['iv'])
            tag = base64.b64decode(encrypted_data['tag'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            # Derive key and decrypt
            key, _ = WalletSecurity.derive_key(password, salt)
            json_data = WalletSecurity.decrypt_data(ciphertext, tag, iv, key)
            
            return json.loads(json_data)
            
        except Exception as e:
            logging.error(f"Failed to load wallet: {str(e)}")
            raise

class BitcoinWallet:
    """Main wallet class"""
    
    def __init__(self, testnet: bool = False):
        self.testnet = testnet
        self.key_generator = BitcoinKeyGenerator(testnet)
        self.address_generator = BitcoinAddress(testnet)
        self.storage = WalletStorage()

    def create_new_wallet(self, name: str, password: str) -> Dict[str, str]:
        """Create a new wallet with generated keys"""
        try:
            # Generate mnemonic and seed
            mnemonic = self.key_generator.generate_mnemonic()
            seed = self.key_generator.generate_seed_from_mnemonic(mnemonic)
            
            # Generate master keys
            master_keys = self.key_generator.generate_master_key_pair(seed)
            
            # Generate addresses
            addresses = self.address_generator.generate_addresses(master_keys['public_key'])
            
            # Prepare wallet data
            wallet_data = {
                'name': name,
                'network': 'testnet' if self.testnet else 'mainnet',
                'mnemonic': mnemonic,
                'master_keys': master_keys,
                'addresses': addresses,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'created_by': 'BRO200BS'
            }
            
            # Save wallet
            self.storage.save_wallet(wallet_data, name, password)
            
            return wallet_data
            
        except Exception as e:
            logging.error(f"Failed to create wallet: {str(e)}")
            raise

class UserInterface:
    """Handle user interaction"""
    
    def __init__(self):
        self.wallet = None

    @staticmethod
    def clear_screen():
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def print_banner():
        """Print wallet banner"""
        banner = f"""
╔══════════════════════════════════════════════╗
║             Bitcoin Wallet Generator          ║
║                                              ║
║          Created: 2024-12-24 15:11:26        ║
║          User: BRO200BS                      ║
║          Version: 1.0.0                      ║
╚══════════════════════════════════════════════╝
"""
        print(banner)

    def main_menu(self):
        """Display main menu and handle user input"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            print("\nMain Menu:")
            print("1. Create New Wallet")
            print("2. Load Existing Wallet")
            print("3. View Wallet Info")
            print("4. Generate New Address")
            print("5. Backup Wallet")
            print("6. Exit")
            
            choice = input("\nEnter your choice (1-6): ")
            
            try:
                if choice == '1':
                    self._create_wallet()
                elif choice == '2':
                    self._load_wallet()
                elif choice == '3':
                    self._view_wallet_info()
                elif choice == '4':
                    self._generate_new_address()
                elif choice == '5':
                    self._backup_wallet()
                elif choice == '6':
                    print("\nGoodbye!")
                    break
                else:
                    print("\nInvalid choice. Please try again.")
                
                input("\nPress Enter to continue...")
                
            except Exception as e:
                print(f"\nError: {str(e)}")
                input("\nPress Enter to continue...")

    def _create_wallet(self):
        """Handle wallet creation"""
        print("\nCreate New Wallet")
        print("----------------")
        
        name = input("Enter wallet name: ").strip()
        if not name:
            raise ValueError("Wallet name cannot be empty")
        
        password = getpass.getpass("Enter strong password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            raise ValueError("Passwords do not match")
        
        use_testnet = input("Use testnet? (y/n): ").lower() == 'y'
        
        self.wallet = BitcoinWallet(testnet=use_testnet)
        wallet_data = self.wallet.create_new_wallet(name, password)
        
        print("\nWallet created successfully!")
        print("\nIMPORTANT: Write down your mnemonic phrase:")
        print("\n" + wallet_data['mnemonic'] + "\n")
        print("WARNING: This is the ONLY time you'll see this phrase!")
        
        self._save_paper_backup(wallet_data)

    def _load_wallet(self):
        """Handle wallet loading"""
        if not self.wallet:
            print("\nLoad Existing Wallet")
            print("-------------------")
            
            name = input("Enter wallet name: ").strip()
            password = getpass.getpass("Enter password: ")
            
            storage = WalletStorage()
            wallet_data = storage.load_wallet(name, password)
            
            self.wallet = BitcoinWallet(testnet='testnet' in wallet_data['network'])
            print("\nWallet loaded successfully!")
        else:
            print("\nWallet is already loaded!")

    def _save_paper_backup(self, wallet_data: dict):
        """Generate paper backup"""
        backup_path = WalletConfig.DEFAULT_WALLET_DIR / 'paper_backup'
        backup_path.mkdir(parents=True, exist_ok=True)
        
        filename = f"BACKUP_{wallet_data['name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(backup_path / filename, 'w') as f:
            f.write("BITCOIN WALLET BACKUP\n")
            f.write("====================\n\n")
            f.write(f"Created: {wallet_data['created_at']}\n")
            f.write(f"Network: {wallet_data['network']}\n\n")
            f.write("Mnemonic Phrase:\n")
            f.write(f"{wallet_data['mnemonic']}\n\n")
            f.write("Addresses:\n")
            for addr_type, address in wallet_data['addresses'].items():
                f.write(f"{addr_type}: {address}\n")

def main():
    """Main entry point"""
    try:
        ui = UserInterface()
        ui.main_menu()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user. Exiting safely...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        print(f"\nAn unexpected error occurred: {str(e)}")
    finally:
        print("\nGoodbye!")

if __name__ == "__main__":
    main()
