import os
import argparse
import base64
import tempfile
import sys
import logging
from getpass import getpass
from tqdm import tqdm
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from hashlib import blake2b

# 配置参数
CHUNK_SIZE = 64 * 1024        # 64KB分块处理
RSA_KEY_SIZE = 4096           # RSA密钥长度
SALT_LENGTH = 32              # 盐值长度
IV_AES_LENGTH = 16            # AES初始化向量长度
NONCE_CHACHA_LENGTH = 12      # ChaCha20随机数长度
DERIVED_KEY_LENGTH = 128      # 派生密钥长度

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cipher.log'),
        logging.StreamHandler()
    ]
)

class StreamProcessor:
    """流式填充处理器"""
    def __init__(self, mode='encrypt'):
        if mode not in ['encrypt', 'decrypt']:
            raise ValueError("模式必须是 'encrypt' 或 'decrypt'")
        
        self.mode = mode
        self.buffer = bytearray()
        self.processor = (
            padding.PKCS7(128).padder() if mode == 'encrypt'
            else padding.PKCS7(128).unpadder()
        )

    def process_chunk(self, chunk, is_final=False):
        self.buffer.extend(chunk)
        if not is_final:
            return b''

        try:
            # 处理空文件特殊情况
            if not self.buffer and self.mode == 'encrypt':
                self.buffer = bytearray(b'\x10' * 16)  # PKCS7填充空文件

            processed = self.processor.update(bytes(self.buffer)) + self.processor.finalize()
            
            # 加密时验证块大小
            if self.mode == 'encrypt' and len(processed) % 16 != 0:
                raise ValueError(f"填充后数据长度异常：{len(processed)}字节")
            
            return processed
        except ValueError as e:
            raise RuntimeError(f"填充错误：{str(e)}") from e
        finally:
            self.buffer.clear()

class SecureFileCipher:
    """安全文件加密器（修复上下文管理器问题版）"""
    def __init__(self, password):
        if len(password) < 12:
            logging.warning("建议使用至少12个字符的强密码")
        self.password = password.encode('utf-8')
        self.backend = default_backend()

    def _derive_keys(self, salt):
        """密钥派生函数"""
        try:
            # 第一层：Scrypt密钥拉伸
            kdf1 = Scrypt(
                salt=salt,
                length=96,
                n=2**20,
                r=8,
                p=3,
                backend=self.backend
            )
            intermediate_key = kdf1.derive(self.password)

            # 第二层：PBKDF2-HMAC
            kdf2 = PBKDF2HMAC(
                algorithm=hashes.SHA3_512(),
                length=DERIVED_KEY_LENGTH,
                salt=salt[::-1],
                iterations=200000,
                backend=self.backend
            )
            derived_key = kdf2.derive(intermediate_key)
            
            if len(derived_key) != DERIVED_KEY_LENGTH:
                raise ValueError(f"派生密钥长度错误：预期{DERIVED_KEY_LENGTH}字节，实际{len(derived_key)}字节")
            
            return derived_key
        except Exception as e:
            raise RuntimeError(f"密钥派生失败：{str(e)}") from e

    def _validate_encryption_params(self, keys, iv_aes, nonce_chacha):
        """加密参数验证"""
        param_checks = [
            (keys[0], 32, "AES密钥"),
            (keys[1], 32, "ChaCha20密钥"),
            (iv_aes, IV_AES_LENGTH, "AES IV"),
            (nonce_chacha, NONCE_CHACHA_LENGTH, "ChaCha20 Nonce")
        ]
        
        for param, expected_len, name in param_checks:
            if len(param) != expected_len:
                raise ValueError(f"{name}长度错误：预期{expected_len}字节，实际{len(param)}字节")

    def _encrypt_chunk(self, chunk, keys, iv_aes, nonce_chacha):
        """修复后的分块加密方法"""
        try:
            self._validate_encryption_params(keys, iv_aes, nonce_chacha)
            
            # 创建加密器（移除with语句）
            encryptor = Cipher(
                algorithms.AES(keys[0]),
                modes.CBC(iv_aes),
                backend=self.backend
            ).encryptor()
            
            aes_encrypted = encryptor.update(chunk) + encryptor.finalize()
            
            # ChaCha20-Poly1305二次加密
            chacha = ChaCha20Poly1305(keys[1])
            return chacha.encrypt(nonce_chacha, aes_encrypted, None)
        except Exception as e:
            logging.error(f"分块加密失败：{str(e)}")
            raise

    def _generate_rsa_components(self):
        """生成 RSA 私钥和公钥"""
        try:
            # 生成 RSA 私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE,
                backend=self.backend
            )
            # 从私钥派生公钥
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            raise RuntimeError(f"RSA 密钥生成失败：{str(e)}") from e

    def encrypt_file(self, input_path, output_path):
        """加密文件主流程"""
        logging.info(f"启动加密：{input_path} → {output_path}")
        
        try:
            # 生成加密参数
            salt = os.urandom(SALT_LENGTH)
            iv_aes = os.urandom(IV_AES_LENGTH)
            nonce_chacha = os.urandom(NONCE_CHACHA_LENGTH)
            derived_key = self._derive_keys(salt)
            keys = (
                derived_key[:32],   # AES-256
                derived_key[32:64], # ChaCha20
                derived_key[64:96], # RSA包装密钥
                derived_key[96:]    # HMAC密钥
            )
            
            # 生成RSA组件
            priv_key, pub_key = self._generate_rsa_components()
            rsa_encrypted_key = pub_key.encrypt(
                keys[0],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            
            # 构建文件头
            header = (
                salt
                + iv_aes
                + nonce_chacha
                + rsa_encrypted_key
                + priv_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            
            # 计算文件哈希
            file_hash = self._calculate_file_hash(input_path)
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # 写入文件头
                fout.write(base64.urlsafe_b64encode(header) + b'\n')
                fout.write(base64.urlsafe_b64encode(file_hash) + b'\n')
                
                # 流式处理
                processor = StreamProcessor('encrypt')
                file_size = os.path.getsize(input_path)
                
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="加密进度") as pbar:
                    while True:
                        chunk = fin.read(CHUNK_SIZE)
                        is_final = not chunk
                        processed = processor.process_chunk(chunk, is_final=is_final)
                        
                        if processed:
                            encrypted = self._encrypt_chunk(processed, keys, iv_aes, nonce_chacha)
                            fout.write(base64.urlsafe_b64encode(encrypted) + b'\n')
                        
                        if is_final:
                            break
                        pbar.update(len(chunk))
            
            logging.info(f"加密成功：{output_path}")
        
        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            logging.error(f"加密失败：{str(e)}")
            raise

    def decrypt_file(self, input_path, output_path):
        """解密文件主流程"""
        logging.info(f"启动解密：{input_path} → {output_path}")
        
        try:
            with open(input_path, 'rb') as fin:
                # 读取文件头
                header = base64.urlsafe_b64decode(fin.readline().strip())
                stored_hash = base64.urlsafe_b64decode(fin.readline().strip())
                
                # 解析头数据
                salt = header[:SALT_LENGTH]
                iv_aes = header[SALT_LENGTH:SALT_LENGTH+IV_AES_LENGTH]
                nonce_chacha = header[SALT_LENGTH+IV_AES_LENGTH:SALT_LENGTH+IV_AES_LENGTH+NONCE_CHACHA_LENGTH]
                rsa_key_length = RSA_KEY_SIZE // 8
                rsa_encrypted_key = header[SALT_LENGTH+IV_AES_LENGTH+NONCE_CHACHA_LENGTH:SALT_LENGTH+IV_AES_LENGTH+NONCE_CHACHA_LENGTH+rsa_key_length]
                priv_key = serialization.load_der_private_key(
                    header[SALT_LENGTH+IV_AES_LENGTH+NONCE_CHACHA_LENGTH+rsa_key_length:],
                    password=None,
                    backend=self.backend
                )
                
                # 密钥派生
                derived_key = self._derive_keys(salt)
                keys = (
                    derived_key[:32],
                    derived_key[32:64],
                    derived_key[64:96],
                    derived_key[96:]
                )
                
                # 解密AES密钥
                aes_key = priv_key.decrypt(
                    rsa_encrypted_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA512(),
                        label=None
                    )
                )
                
                # 创建安全临时文件
                temp_file = None
                try:
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        temp_file = tmp.name
                        processor = StreamProcessor('decrypt')
                        
                        with open(temp_file, 'wb') as fout:
                            file_size = os.path.getsize(input_path) - fin.tell()
                            with tqdm(total=file_size, unit='B', unit_scale=True, desc="解密进度") as pbar:
                                while True:
                                    line = fin.readline()
                                    if not line:
                                        processed = processor.process_chunk(b'', is_final=True)
                                        if processed:
                                            fout.write(processed)
                                        break
                                    
                                    encrypted = base64.urlsafe_b64decode(line.strip())
                                    chacha = ChaCha20Poly1305(keys[1])
                                    aes_data = chacha.decrypt(nonce_chacha, encrypted, None)
                                    
                                    # 创建解密器（移除with语句）
                                    decryptor = Cipher(
                                        algorithms.AES(aes_key),
                                        modes.CBC(iv_aes),
                                        backend=self.backend
                                    ).decryptor()
                                    
                                    decrypted = decryptor.update(aes_data) + decryptor.finalize()
                                    processed = processor.process_chunk(decrypted)
                                    if processed:
                                        fout.write(processed)
                                    
                                    pbar.update(len(line))
                    
                    # 验证完整性
                    actual_hash = self._calculate_file_hash(temp_file)
                    if actual_hash != stored_hash:
                        raise ValueError("文件完整性验证失败")
                    
                    # Windows兼容处理
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    os.replace(temp_file, output_path)
                    logging.info(f"解密成功：{output_path}")
                
                finally:
                    if temp_file and os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass
        
        except Exception as e:
            if output_path and os.path.exists(output_path):
                os.remove(output_path)
            logging.error(f"解密失败：{str(e)}")
            raise

    def _calculate_file_hash(self, file_path):
        """计算文件BLAKE2b哈希"""
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
               "  加密多个文件：python cipher.py -e -i file1.txt file2.jpg\n"
               "  加密整个目录：python cipher.py -e -i dir/*\n"
               "  指定输出目录：python cipher.py -e -i data.txt -o ./encrypted/"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true', help='加密模式')
    group.add_argument('-d', '--decrypt', action='store_true', help='解密模式')
    
    parser.add_argument('-i', '--input', required=True, nargs='+', help='输入文件路径（支持多个文件）')
    parser.add_argument('-o', '--output', help='输出目录路径（可选）')
    parser.add_argument('-r', '--recursive', action='store_true', help='递归处理目录')
    
    args = parser.parse_args()
    
    try:
        # 替换输入路径以支持递归
        args.input = find_files([os.path.normpath(p) for p in args.input], args.recursive)

        # 密码输入
        print("\n=== 安全文件加密系统 ===")
        password = getpass("请输入密码：")
        cipher = SecureFileCipher(password)

        # 预处理输出目录
        output_dir = None
        if args.output:
            output_dir = os.path.normpath(args.output)
            os.makedirs(output_dir, exist_ok=True)  # 确保目录存在
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
                os.makedirs(os.path.dirname(output_path), exist_ok=True)  # 自动创建子目录
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
                    overwrite_all = True  # 标记后续全部覆盖

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
                    cipher.encrypt_file(input_path, output_path)
                else:
                    cipher.decrypt_file(input_path, output_path)
                
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