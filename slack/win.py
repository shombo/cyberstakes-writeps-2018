import sys
import os

def get_bin_files_names():
    with open("bin_file_strip.txt", "r") as f:
        names = f.read().split()
    return names

def get_norm_files_names():
    with open("file_names_strip.txt", "r") as f:
        names = f.read().split()
    return names

def transfer_files():
    bin_files = get_bin_files_names()
    norm_files = get_norm_files_names()
    bin_file_mod = map(lambda x : "/bin/" + x, bin_files)
    for i in norm_files + bin_file_mod:
        norm = i
        bak = i + ".bak"
        os.system("./diskbot.py disk.img -f {} ./transfer/".format(norm))
        os.system("./diskbot.py disk.img -f {} ./transfer/".format(bak))

def make_dirs():
    if not os.path.isdir("./transfer"):
        os.mkdir("./transfer")
    if not os.path.isdir("./zips"):
        os.mkdir("./zips")

if __name__ == "__main__":
    make_dirs()
    size = os.listdir("./transfer/")
    if len(size) == 0:
        transfer_files()
    bin_files = get_bin_files_names()
    norm_files = get_norm_files_names()
    for f in norm_files + bin_files:
        norm = open("./transfer/" + f, "r").read()
        back = open("./transfer/" + f + ".bak", "r").read()
        print(f)
        assert len(norm) == len(back)
        first = ""
        second = ""
        started = False
        for i in range(len(norm)):
            if norm[i] != back[i] or (started and i + 1 < len(norm) and norm[i+1:] != back[i+1:]):
                first += norm[i]
                second += back[i]
                started = True
        first = first.strip("A")
        second = second.strip("A")
        if first != "":
            f_name = "./zips/{}.gz".format(f)
            norm_name = "./zips/{}".format(f)
            with open(f_name, "wb") as fi:
                fi.write(first)
                fi.write(second)
            os.system("gunzip {}".format(f_name))
            os.system("tar -xvf {} -C ./zips".format(norm_name))
    win = ""
    for i in range(32):
        win += open("./zips/{}".format(i),"r").read()
    print(win)
