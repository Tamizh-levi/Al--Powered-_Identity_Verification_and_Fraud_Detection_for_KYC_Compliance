data = open(r"D:\react\smart-kyc-backend\app.py", "rb").read()
clean_data = data.replace(b"\xC2\xA0", b" ")
open("app.py", "wb").write(clean_data)
print("Cleaned hidden characters!")
