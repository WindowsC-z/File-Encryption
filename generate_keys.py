from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
print("当前工作目录:", os.getcwd())
# 生成私钥
private_key = rsa.generate_private_key(
       public_exponent=65537,
       key_size=4096,
       backend=default_backend()
   )

# 保存私钥为 PEM 文件
with open("private_key.pem", "wb") as f:
       f.write(private_key.private_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PrivateFormat.PKCS8,
           encryption_algorithm=serialization.NoEncryption()
       ))

# 生成公钥
public_key = private_key.public_key()
with open("public_key.pem", "wb") as f:
       f.write(public_key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo
       ))

print("密钥对已生成：private_key.pem 和 public_key.pem")