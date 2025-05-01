###安全文件加密工具 v5.0（支持批量处理）###

options:
  -h, --help            show this help message and exit
  -e, --encrypt         加密模式
  -d, --decrypt         解密模式
  -i INPUT [INPUT ...], --input INPUT [INPUT ...]
                        输入文件路径（支持多个文件）
  -o OUTPUT, --output OUTPUT
                        输出目录路径（可选）
  -r, --recursive       递归处理目录
  -k KEY, --key KEY     加密模式使用公钥文件路径，解密模式使用私钥文件路径

使用示例： 加密多个文件：python cipher.py -e -i file1.txt file2.jpg -k public_key.pem 解密文件：python cipher.py -d -i encrypted.enc -k
private_key.pem
           加密整个目录：python cipher.py -e -i my_folder -k public_key.pem -r 解密文件python cipher.py -d -i my_folder -k private_key.pem -r

#生成密钥对#
运行generate_keys.py  将在其工作目录下生成public_key.pem和private_key.pem
