import chardet
import dns

print(dns.__file__)

data = b'\xe4\xbd\xa0\xe5\xa5\xbd'  # Example bytes (UTF-8 encoded "你好")
detected = chardet.detect(data)
print(detected)
