import zlib

filename = input("Enter the file name:")

try:
    with open(f"{filename}", "rb") as file:
        file = file.read()
        output = zlib.decompress(file[12:])
        output = output[16:-7]
        print(output.decode('utf-8').replace("#", "\n#"))
        file = open(f"{filename}_","wb")
        file.write(output)
        file.close()

except FileNotFoundError:
    print("This file doesn't exist!")
