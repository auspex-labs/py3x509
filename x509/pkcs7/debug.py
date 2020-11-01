def show_bytes(string):
    print("--------------")
    for byte in string:
        print(hex(ord(byte)))
    print("\n--------------")


def write_to_file(what, where):
    ff = open(where, "w")
    ff.write(str(what))
    ff.close()
