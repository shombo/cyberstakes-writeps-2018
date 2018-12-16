import random
import string
from Crypto.Cipher import AES
f = open("log", "r")
text = f.read()
f.close()

KEY="SAKMWLIJKEOMEDOR"
WRITEOUT=False
def new_cipher(s,key=KEY):
  cipher = AES.new(key, AES.MODE_ECB)
  decrypted  = cipher.decrypt(s.decode("hex"))
  if WRITEOUT:
    random_name = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
    f = open("out/"+random_name,"w")
    f.write(decrypted)
    f.close()
  if "ACI" in decrypted:
    print decrypted

def test(s,key=KEY):
  try:
    new_cipher(s[16:],key) 
  except:
    pass
  try:
    new_cipher(s,key=KEY) 
  except:
    pass
  try:
    new_cipher(s[::-1],key=KEY) 
  except:
    pass
  new_s = ""
  i = 0
  while i+4 <= len(s):
    new_s += s[i:i+4][::-1]
    i+=4
  try:
    new_cipher(new_s[16:],key=KEY)
  except:
    pass
  try:
    new_cipher(new_s,key=KEY)
  except:
    pass
  try:
    new_cipher(new_s[::-1],key=KEY)
  except:
    pass
  
def to_octal(s):
    try:
      s = s.replace("r","1").replace("w","1").replace("x","1").replace("-","0")
      return int(s,2)
    except:
      return s
def int_to_hex(s):
  return hex(int(s,10)).replace("0x","")

def user_item_to_hex(s):
  return int_to_hex(s.split(":")[1]).replace("0x","")

def calculate_perms(mask_s,perm_s):
  perm = to_octal(perm_s.split(":")[2])
  if "::" in str( mask_s):
    mask = to_octal(mask_s.split("::")[1])
  else:
    mask = to_octal(mask_s)
  return mask,perm,int(perm) & mask
 
special_item = {"list": [], "perms": []}
items = text.split("# file: ")
parsed_items = {}
for f in items:
  cur_mask = 000
  if "user::" in f:
    f = f.replace("user::","")
    
  if "user:" not in f:
    continue
  #print f
  f_list = f.split("\n")
  path = f_list[0]
  if path == ".hidden/1/2/3/4/5/7/5f":
    mask = f.split("mask::")[1].split("\n")[0]
    for line in f_list[1:]:
      if "user::" in line:
        continue
      elif "user:" in line:
        special_item["list"].append( user_item_to_hex(line)[-4:] )
        perm,mask,final = calculate_perms(mask,line)
        special_item["perms"].append(final) 
    continue
  user = user_item_to_hex(f_list[4])
  mask,perm,final_perm = calculate_perms(f_list[6],f_list[4]) 
  parsed_items[path] = { "user" : user, "mask" : mask, "perm" : perm, "effective_perm" : final_perm}

print "".join(special_item["list"]).decode("hex")


def solve_by_sorted_order(keys,items):
#  print "trying order:"
#  print str(keys)
  perm_list = []
  data_list = []
  data_list_reversed = []
  data_list_middle = []
  for key in keys:
    perm_list.append(str(items[key]["effective_perm"]))
    data_list.append(items[key]["user"])
    reversed_entry = items[key]["user"][::-1]
    data_list_reversed.append(reversed_entry)
    middle_entry = items[key]["user"][:-2] + items[key]["user"][-2:]
    data_list_middle.append(middle_entry)

  #print "".join(perm_list)

  test( "".join(data_list))
  test( "".join(data_list_reversed))
  test( "".join(data_list_middle))

print parsed_items 
print special_item
parsed_item_keys = parsed_items.keys()
parsed_item_keys.sort()
print parsed_item_keys
by_filename_sort = dict()
for key in parsed_item_keys:
  new_key = key.split("/")[-1:][0]
  by_filename_sort[new_key] = key

by_filename_keys = by_filename_sort.keys()
by_filename_keys.sort()
by_filename = []
for k in by_filename_keys:
  by_filename.append(by_filename_sort[k])

sorted_time_keys = ".hidden/2/4/5/6/7/b1 .hidden/1/4/6/7/11 .hidden/1/2/3/4/6/7/4b .hidden/2/3/5/6/7/59 .hidden/1/2/3/7/be .hidden/0/1/2/3/5/6/7/d1 .hidden/1/4/7/af .hidden/0/3/5/6/7/e5 .hidden/1/4/5/6/7/e9 .hidden/1/2/4/6/7/26 .hidden/0/1/2/3/4/5/6/7/06 .hidden/0/3/4/7/15".split(" ")

solve_by_sorted_order(parsed_item_keys, parsed_items)
solve_by_sorted_order(parsed_item_keys[::-1], parsed_items)
solve_by_sorted_order(by_filename, parsed_items)
solve_by_sorted_order(by_filename[::-1], parsed_items)
solve_by_sorted_order(sorted_time_keys, parsed_items)
#solve_by_sorted_order(sorted_time_keys[::-1], parsed_items)
