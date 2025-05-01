import os
import argparse
import base64
import tempfile
import sys
import logging
import re
from getpass import getpass
from tqdm import tqdm
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from hashlib import blake2b
import hmac

# 安全配置参数
CHUNK_SIZE = 64 * 1024        # 64KB分块处理
RSA_KEY_SIZE = 4096           # RSA密钥长度
SALT_LENGTH = 32              # 盐值长度
NONCE_LENGTH = 12             # ChaCha20随机数长度
SCRYPT_KEY_LENGTH = 32        # 派生密钥长度
MIN_PASSWORD_LENGTH = 12      # 最小密码长度
HMAC_KEY_LENGTH = 64          # HMAC密钥长度

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secure_cipher.log'),
        logging.StreamHandler()
    ]
)

class SecureFileCipher:
    """安全文件加密器（修复版）"""
    def __init__(self, password):
        self._validate_password(password)
        self.password = password.encode('utf-8')
        self.backend = default_backend()

    def _validate_password(self, password):
        """强制密码复杂度策略"""
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"密码至少需要{MIN_PASSWORD_LENGTH}个字符")
        if not re.search(r"[A-Z]", password):
            raise ValueError("密码必须包含至少一个大写字母")
        if not re.search(r"[a-z]", password):
            raise ValueError("密码必须包含至少一个小写字母")
        if not re.search(r"\d", password):
            raise ValueError("密码必须包含至少一个数字")
        if not re.search(r"[!@#$%^&*()_+=-]", password):
            raise ValueError("密码必须包含至少一个特殊符号")

    def _derive_keys(self, salt):
        """安全的密钥派生函数（Scrypt）"""
        kdf = Scrypt(
            salt=salt,
            length=SCRYPT_KEY_LENGTH + HMAC_KEY_LENGTH,
            n=2**20,  # 符合OWASP推荐参数
            r=8,
            p=1,
            backend=self.backend
        )
        derived = kdf.derive(self.password)
        return derived[:SCRYPT_KEY_LENGTH], derived[SCRYPT_KEY_LENGTH:]

    def _generate_header(self, salt, nonce, hmac_key):
        """生成带HMAC签名的文件头"""
        header_data = salt + nonce
        signature = hmac.new(hmac_key, header_data, digestmod=blake2b).digest()
        return header_data + signature

    def _validate_header(self, header, hmac_key):
        """验证文件头完整性"""
        if len(header) != SALT_LENGTH + NONCE_LENGTH + 64:
            raise ValueError("无效的文件头长度")
        
        header_data = header[:SALT_LENGTH+NONCE_LENGTH]
        received_signature = header[SALT_LENGTH+NONCE_LENGTH:]
        
        expected_signature = hmac.new(hmac_key, header_data, digestmod=blake2b).digest()
        if not hmac.compare_digest(received_signature, expected_signature):
            raise ValueError("文件头完整性验证失败")

    def encrypt_file(self, input_path, output_path, pub_key):
        """安全加密流程"""
        logging.info(f"启动加密：{input_path} → {output_path}")
        
        try:
            # 生成加密参数
            salt = os.urandom(SALT_LENGTH)
            nonce = os.urandom(NONCE_LENGTH)
            chacha_key, hmac_key = self._derive_keys(salt)
            
            # 使用RSA公钥加密ChaCha密钥
            encrypted_key = pub_key.encrypt(
                chacha_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            
            # 构建带签名的文件头
            header = self._generate_header(salt, nonce, hmac_key)
            
            # 计算文件哈希
            file_hash = self._calculate_file_hash(input_path)
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # 写入元数据
                fout.write(base64.urlsafe_b64encode(header) + b'\n')
                fout.write(base64.urlsafe_b64encode(encrypted_key) + b'\n')
                fout.write(base64.urlsafe_b64encode(file_hash) + b'\n')
                
                # 一次性加密整个文件
                cipher = ChaCha20Poly1305(chacha_key)
                plaintext = fin.read()
                encrypted = cipher.encrypt(nonce, plaintext, None)
                fout.write(base64.urlsafe_b64encode(encrypted) + b'\n')
            
            logging.info(f"加密成功：{output_path}")
        
        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            logging.error(f"加密失败：{str(e)}")
            raise

    def decrypt_file(self, input_path, output_path, priv_key):
        """安全解密流程"""
        logging.info(f"启动解密：{input_path} → {output_path}")
        
        temp_file = None
        try:
            with open(input_path, 'rb') as fin:
                # 读取元数据
                header = base64.urlsafe_b64decode(fin.readline().strip())
                encrypted_key = base64.urlsafe_b64decode(fin.readline().strip())
                stored_hash = base64.urlsafe_b64decode(fin.readline().strip())
                
                # 解析并验证文件头
                salt = header[:SALT_LENGTH]
                nonce = header[SALT_LENGTH:SALT_LENGTH+NONCE_LENGTH]
                _, hmac_key = self._derive_keys(salt)  # 仅派生HMAC密钥用于验证
                self._validate_header(header, hmac_key)
                
                # 解密ChaCha密钥
                try:
                    chacha_key = priv_key.decrypt(
                        encrypted_key,
                        asym_padding.OAEP(
                            mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
                            algorithm=hashes.SHA512(),
                            label=None
                        )
                    )
                except ValueError as e:
                    logging.error("密钥解密失败，可能是密钥不匹配或数据损坏", exc_info=True)
                    raise ValueError(f"密钥解密失败：{str(e)}") from e
                
                # 创建安全临时文件
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    temp_file = tmp.name
                    cipher = ChaCha20Poly1305(chacha_key)
                    
                    # 一次性解密整个文件
                    encrypted_data = base64.urlsafe_b64decode(fin.read().strip())
                    decrypted = cipher.decrypt(nonce, encrypted_data, None)
                    tmp.write(decrypted)
                
                # 验证完整性
                actual_hash = self._calculate_file_hash(temp_file)
                if actual_hash != stored_hash:
                    raise ValueError("文件哈希不匹配，可能被篡改")
                
                # 安全移动文件
                if os.path.exists(output_path):
                    os.remove(output_path)
                os.replace(temp_file, output_path)
                logging.info(f"解密成功：{output_path}")
        
        except Exception as e:
            if output_path and os.path.exists(output_path):
                os.remove(output_path)
            logging.error(f"解密失败：{str(e)}", exc_info=True)
            raise
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception as e:
                    logging.warning(f"临时文件清理失败：{str(e)}")

    def _calculate_file_hash(self, file_path):
        """计算文件的BLAKE2b哈希"""
        h = blake2b(digest_size=64)
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.digest()
        except IOError as e:
            raise RuntimeError(f"文件读取失败：{str(e)}") from e

def generate_rsa_keypair():
    """生成RSA密钥对"""
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def find_files(paths, recursive=False):
    file_list = []
    for path in paths:
        if os.path.isfile(path):
            file_list.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_list.append(os.path.join(root, file))
                if not recursive:
                    break  # 非递归模式时只处理顶层目录
    return file_list

def main():
    """命令行接口"""
    parser = argparse.ArgumentParser(
        description="安全文件加密工具 v5.0（支持批量处理）",
        epilog="使用示例：\n"
               "  加密多个文件：python cipher.py -e -i file1.txt file2.jpg -k pub_key.pem\n"
               "  解密文件：python cipher.py -d -i encrypted.enc -k private_key.pem"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true', help='加密模式')
    group.add_argument('-d', '--decrypt', action='store_true', help='解密模式')
    
    parser.add_argument('-i', '--input', required=True, nargs='+', help='输入文件路径（支持多个文件）')
    parser.add_argument('-o', '--output', help='输出目录路径（可选）')
    parser.add_argument('-r', '--recursive', action='store_true', help='递归处理目录')
    parser.add_argument('-k', '--key', required=True, help='加密模式使用公钥文件路径，解密模式使用私钥文件路径')
    
    args = parser.parse_args()
    
    try:
        # 替换输入路径以支持递归
        args.input = find_files([os.path.normpath(p) for p in args.input], args.recursive)

        # 密码输入
        print("\n=== 安全文件加密系统 ===")
        password = getpass("请输入密码：")
        cipher = SecureFileCipher(password)

        # 加载密钥
        if args.encrypt:
            # 加密模式：加载公钥
            with open(args.key, "rb") as key_file:
                pub_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            priv_key = None
        else:
            # 解密模式：加载私钥
            with open(args.key, "rb") as key_file:
                priv_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            pub_key = None  # 解密不需要公钥

        # 预处理输出目录
        output_dir = None
        if args.output:
            output_dir = os.path.normpath(args.output)
            os.makedirs(output_dir, exist_ok=True)
            if not os.path.isdir(output_dir):
                raise ValueError("输出路径必须是一个目录")

        # 覆盖提示控制变量
        overwrite_all = False
        skip_files = []
        
        # 预处理检查所有输出文件
        for input_path in args.input:
            input_path = os.path.normpath(input_path)
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"输入文件不存在：{input_path}")

            # 生成输出路径
            if output_dir:
                # 保留原始路径结构
                relative_path = os.path.relpath(input_path, start=os.path.commonpath(args.input))
                output_path = os.path.join(output_dir, relative_path + ('.enc' if args.encrypt else '.dec'))
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
            else:
                base_name = os.path.splitext(input_path)[0]
                output_path = f"{base_name}.enc" if args.encrypt else f"{base_name}.dec"

            if os.path.exists(output_path) and not overwrite_all:
                print(f"\n! 输出文件已存在：{output_path}")
                overwrite = input(f"是否覆盖？(y/n/a[全部覆盖]/q[退出]): ").lower()
                if overwrite == 'q':
                    print("操作已取消")
                    return
                elif overwrite == 'n':
                    skip_files.append(input_path)
                    continue
                elif overwrite == 'a':
                    overwrite_all = True

        # 批量处理
        success_count = 0
        for input_path in args.input:
            input_path = os.path.normpath(input_path)
            if input_path in skip_files:
                continue

            try:
                # 生成最终输出路径
                if output_dir:
                    base_name = os.path.basename(input_path)
                    output_path = os.path.join(output_dir, base_name + ('.enc' if args.encrypt else '.dec'))
                else:
                    base_name = os.path.splitext(input_path)[0]
                    output_path = f"{base_name}.enc" if args.encrypt else f"{base_name}.dec"

                # 执行操作前再次检查覆盖
                if os.path.exists(output_path) and not overwrite_all:
                    if input(f"覆盖 {output_path}? (y/n): ").lower() != 'y':
                        continue

                # 执行操作
                if args.encrypt:
                    cipher.encrypt_file(input_path, output_path, pub_key)
                else:
                    cipher.decrypt_file(input_path, output_path, priv_key)
                
                success_count += 1

            except Exception as e:
                logging.error(f"处理文件 {input_path} 失败：{str(e)}", exc_info=True)
                if os.path.exists(output_path):
                    try:
                        os.remove(output_path)
                    except Exception as cleanup_err:
                        logging.error(f"清理失败文件时出错：{cleanup_err}")
                continue

        print(f"\n操作完成：成功处理 {success_count}/{len(args.input)} 个文件")
    
    except KeyboardInterrupt:
        print("\n操作被用户终止")
        sys.exit(130)
    except Exception as e:
        logging.error(f"运行错误：{str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
