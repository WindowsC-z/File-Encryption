# 文件加密
### 📖 详细使用说明

#### 环境准备
1. 安装Python 3.8+
2. 安装依赖库：
```bash
pip install cryptography tqdm
```

#### 基本使用

🔒 **加密文件**：
```bash
python file_cipher.py -e -i 敏感文件.pdf
```
程序将：
1. 提示输入密码（输入时不会显示）
2. 生成加密文件 `敏感文件.pdf.enc`
3. 显示加密进度条

🔓 **解密文件**：
```bash
python file_cipher.py -d -i 敏感文件.pdf.enc
```
程序将：
1. 提示输入密码
2. 生成解密文件 `敏感文件.pdf.dec`
3. 显示解密进度条
4. 自动验证文件完整性
🔓 **参数**：
  -h, --help            show this help message and exit
  -e, --encrypt         加密模式
  -d, --decrypt         解密模式
  -i INPUT [INPUT ...], --input INPUT [INPUT ...]
                        输入文件路径（支持多个文件）
  -o OUTPUT, --output OUTPUT
                        输出目录路径（可选）
  -r, --recursive       递归处理目录

#### 高级选项

📂 **指定输出文件**：
```bash
python file_cipher.py -e -i data.xlsx -o secured_data.enc
python file_cipher.py -d -i secured_data.enc -o decrypted.xlsx
```
📂 **批量加密文件**：
```bashi
python file_cipher.py -e -i 指定加密目录 -o 指定输出目录 --recursive
```

🔐 **密码安全特性**：
- 密码长度建议至少16字符
- 支持特殊字符和空格
- 密码错误会立即终止解密


#### ⚠️ 重要注意事项

1. **密码管理**：
   - 丢失密码将导致数据永久不可恢复
   - 建议使用密码管理器保存密码

2. **文件扩展名**：
   - 加密文件自动添加 `.enc` 扩展名
   - 解密文件自动添加 `.dec` 扩展名

3. **异常处理**：
   - 按Ctrl+C可安全中止操作
   - 网络驱动器建议先复制到本地操作
