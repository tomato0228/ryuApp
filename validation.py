import hashlib
import os
import json
import random
from binascii import b2a_hex, a2b_hex


def read_host_v(path):
    with open(os.getcwd() + "/configure/" + path, 'r', encoding='utf-8') as file:
        content = file.read()
    content = content.replace("'", '"')
    data = json.loads(content)
    return data


def generate_random_str(randomlength=16):
    """
    生成一个指定长度的随机字符串
    """
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str


def hash_key(node, count):
    x = hashlib.sha256()
    r = node
    for i in range(0, count):
        x.update(r.encode())
        r = x.hexdigest()
    # print(r)
    return r


def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')


# 加密函数
def aesencrypt(text, aeskey):
    key = aeskey.encode('utf-8')
    mode = AES.MODE_ECB
    text = add_to_16(text)
    cryptos = AES.new(key, mode)
    cipher_text = cryptos.encrypt(text)
    # print("加密数据：%s",  cipher_text)
    # print("加密数据：%s",  b2a_hex(cipher_text))
    return b2a_hex(cipher_text)


# 解密后，去掉补足的空格用strip() 去掉
def aesdecrypt(text, aeskey):
    key = aeskey.encode('utf-8')
    mode = AES.MODE_ECB
    cryptor = AES.new(key, mode)
    # print("待解密数据：%s",  text)
    # print("待解密数据：%s",  a2b_hex(text))
    plain_text = cryptor.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')
