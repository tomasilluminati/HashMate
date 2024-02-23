import hashlib
import binascii
import zlib
import re
import sys
import time
from lib.style import colorize_text
from lib.hash_lib import HASH_LIB
from sys import exit as syexit
from os import path, walk



def detect_algorithm(hash_input):
    found_algorithms = []
    for regex_pattern, algorithms in HASH_LIB.items():
        if re.match(regex_pattern, hash_input, re.IGNORECASE):
            found_algorithms.extend(algorithms)
    return found_algorithms if found_algorithms else None

def is_a_hash(hash_input):
    for regex_pattern in HASH_LIB.keys():
        if re.match(regex_pattern, hash_input):
            return True
    return False


def calculate_string_hash(string, algorithm, salt=None):

    string = string.encode()

    if salt != None:
        string += salt.encode()
    

    if algorithm == "sha1":
        hash_calculated = hashlib.sha1(string).hexdigest()
    elif algorithm == "sha224":
        hash_calculated = hashlib.sha224(string).hexdigest()
    elif algorithm == "sha256":
        hash_calculated = hashlib.sha256(string).hexdigest()
    elif algorithm == "sha384":
        hash_calculated = hashlib.sha384(string).hexdigest()
    elif algorithm == "sha512":
        hash_calculated = hashlib.sha512(string).hexdigest()
    elif algorithm == "md5":
        hash_calculated = hashlib.md5(string).hexdigest()
    elif algorithm == "blake2b":
        hash_calculated = hashlib.blake2b(string).hexdigest()
    elif algorithm == "blake2s":
        hash_calculated = hashlib.blake2s(string).hexdigest()
    elif algorithm == "ripemd160":
        hash_calculated = hashlib.new("ripemd160", string).hexdigest()
    
    elif algorithm == "md4":
        hash_calculated = hashlib.new("md4", string).hexdigest()
    elif algorithm == "md5-sha1":
        hash_calculated = hashlib.new("md5-sha1", string).hexdigest()
    elif algorithm == "sm3":
        hash_calculated = hashlib.new("sm3", string).hexdigest()
    elif algorithm == "sha3-224":
        hash_calculated = hashlib.new("sha3_224", string).hexdigest()
    elif algorithm == "sha3-384":
        hash_calculated = hashlib.new("sha3_384", string).hexdigest()
    elif algorithm == "sha512-256":
        hash_calculated = hashlib.new("sha512_256", string).hexdigest()
    elif algorithm == "sha3-256":
        hash_calculated = hashlib.new("sha3_256", string).hexdigest()
    elif algorithm == "sha3-512":
        hash_calculated = hashlib.new("sha3_512", string).hexdigest()
    elif algorithm == "sha512-224":
        hash_calculated = hashlib.new("sha512_224", string).hexdigest()
    elif algorithm == "whirlpool":
        hash_calculated = hashlib.new("whirlpool", string).hexdigest()

    elif algorithm == "crc32":
        hash_calculated = binascii.crc32(string)
        hash_calculated = str(hex(int(hash_calculated)))
        hash_calculated = hash_calculated[2:]
        
    elif algorithm == "doublemd5":
        hash_md5 = hashlib.md5(string).hexdigest()
        hash_calculated = hashlib.md5(hash_md5.encode()).hexdigest()
        

    return hash_calculated


def calculate_file_hash(path, algorithm, block_size, salt=None):
    
    if salt != None:
        
        salt = salt.encode()
    
    if algorithm == "sha1":
        hash_calculated = hashlib.sha1()
    elif algorithm == "sha224":
        hash_calculated = hashlib.sha224()
    elif algorithm == "sha256":
        hash_calculated = hashlib.sha256()
    elif algorithm == "sha384":
        hash_calculated = hashlib.sha384()
    elif algorithm == "sha512":
        hash_calculated = hashlib.sha512()
    elif algorithm == "crc32":
        crc32_calculated = 0
    elif algorithm == "blake2b":
        hash_calculated = hashlib.blake2b()
    elif algorithm == "blake2s":
        hash_calculated = hashlib.blake2s()
    elif algorithm == "ripemd160":
        hash_calculated = hashlib.new("ripemd160")
    elif algorithm == "md5":
        hash_calculated = hashlib.md5()
    elif algorithm == "doublemd5":
        hash_calculated = hashlib.md5()
        double_hash_calculated = hashlib.md5()
    elif algorithm == "md4":
        hash_calculated = hashlib.new("md4")
    elif algorithm == "md5-sha1":
        hash_calculated = hashlib.new("md5-sha1")
    elif algorithm == "sm3":
        hash_calculated = hashlib.new("sm3")
    elif algorithm == "sha3-224":
        hash_calculated = hashlib.new("sha3_224")
    elif algorithm == "sha3-256":
        hash_calculated = hashlib.new("sha3_256")
    elif algorithm == "sha3-384":
        hash_calculated = hashlib.new("sha3_384")
    elif algorithm == "sha3-512":
        hash_calculated = hashlib.new("sha3_512")
    elif algorithm == "sha512-224":
        hash_calculated = hashlib.new("sha512_224")
    elif algorithm == "sha512-256":
        hash_calculated = hashlib.new("sha512_256")
    elif algorithm == "whirlpool":
        hash_calculated = hashlib.new("whirlpool")
    
    else:
        print(colorize_text("Error: Invalid algorithm", "red"))
        syexit()

    # Calculate the file hash in blocks
    with open(path, 'rb') as file:
        for block in iter(lambda: file.read(block_size), b''):
            
            if salt != None:
                
                block = block + salt
            
            if algorithm == "crc32":
                crc32_calculated = zlib.crc32(block, crc32_calculated)
            elif algorithm == "doublemd5":
                hash_calculated.update(block)
                double_hash_calculated.update(hash_calculated.digest()) 
            elif algorithm == "doublesha1":
                hash_calculated.update(block)
                double_hash_calculated.update(hash_calculated.digest())
            else:
                hash_calculated.update(block)

    # Return the hash in hexadecimal format
    if algorithm == "crc32":
        return '%08x' % (crc32_calculated & 0xffffffff)
    elif algorithm == "doublemd5":
        return double_hash_calculated.hexdigest()  
    else:
        return hash_calculated.hexdigest()


def calculate_hashes_directory(directory, algorithm, block_size):
    
    hashes = {}

    # Traverse through all the files in the directory
    for root, _, files in walk(directory, block_size):
        for file in files:
            full_path = path.join(root, file)
            
            file_hash = calculate_file_hash(full_path, algorithm, block_size)
            hashes[full_path] = file_hash

    print(hashes)

    return hashes

def detect_hash_type_dehash(hash_value):
    # Define the mapping of length to hash type
    hash_types = {
        32: 'MD5',
        40: 'SHA1',
        56: 'SHA224',
        64: 'SHA256',
        96: 'SHA384',
        128: 'SHA512',
        8:  'CRC32'
    }

    # Get the length of the hash
    length = len(hash_value)

    # Check if the length is in the dictionary
    if length in hash_types and all(c in '0123456789abcdefABCDEF' for c in hash_value):
        return hash_types[length]

    
    
    # If it doesn't match any known type
    return 'Error'

def dehashing(wordlist, hash_value, hash_functions, salts=[]):

    if salts == None:
        salts = [""]

        
    for hash_type, hash_func in hash_functions.items():
        for word in wordlist:
            for salt in salts:

                if hash_type == "crc32":  
                    word_hash = hash_func((word + salt).encode())
                elif hash_type == "ripemd160":
                    word_hash = hashlib.new("ripemd160", (word + salt).encode()).hexdigest()
                elif hash_type == "md4":
                    word_hash = hashlib.new("md4", (word + salt).encode()).hexdigest()
                elif hash_type == "md5-sha1":
                    word_hash = hashlib.new("md5-sha1", (word + salt).encode()).hexdigest()
                elif hash_type == "sm3":
                    word_hash = hashlib.new("sm3", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-224":
                    word_hash = hashlib.new("sha3_224", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-384":
                    word_hash = hashlib.new("sha3_384", (word + salt).encode()).hexdigest()
                elif hash_type == "sha512-256":
                    word_hash = hashlib.new("sha512_256", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-256":
                    word_hash = hashlib.new("sha3_256", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-512":
                    word_hash = hashlib.new("sha3_512", (word + salt).encode()).hexdigest()
                elif hash_type == "sha512-224":
                    word_hash = hashlib.new("sha512_224", (word + salt).encode()).hexdigest()
                elif hash_type == "whirlpool":
                    word_hash = hashlib.new("whirlpool", (word + salt).encode()).hexdigest()
                elif hash_type == "doublemd5":
                    word_hash = hashlib.md5((word + salt).encode()).hexdigest() 
                    word_hash = hashlib.md5(word_hash.encode()).hexdigest()  
                else:
                    word_hash = hash_func((word + salt).encode()).hexdigest()

                if word_hash == hash_value:
                    
                    return word, salt
                
    return "Error"


def dehashing_threading(wordlist, hash_value, hash_functions, result, salts=[], salt_result=[]):

    

    if salts == None:
        salts = [""]


    total_combinations = len(wordlist) * len(hash_functions) * len(salts)
    current_iteration = 0

    for hash_type, hash_func in hash_functions.items():
        for word in wordlist:
            for salt in salts:
                current_iteration += 1
                show_progress(current_iteration, total_combinations)

                if hash_type == "crc32": 
                    word_hash = hash_func((word + salt).encode())
                elif hash_type == "ripemd160":
                    word_hash = hashlib.new("ripemd160", (word + salt).encode()).hexdigest()
                elif hash_type == "md4":
                    word_hash = hashlib.new("md4", (word + salt).encode()).hexdigest()
                elif hash_type == "md5-sha1":
                    word_hash = hashlib.new("md5-sha1", (word + salt).encode()).hexdigest()
                elif hash_type == "sm3":
                    word_hash = hashlib.new("sm3", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-224":
                    word_hash = hashlib.new("sha3_224", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-384":
                    word_hash = hashlib.new("sha3_384", (word + salt).encode()).hexdigest()
                elif hash_type == "sha512-256":
                    word_hash = hashlib.new("sha512_256", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-256":
                    word_hash = hashlib.new("sha3_256", (word + salt).encode()).hexdigest()
                elif hash_type == "sha3-512":
                    word_hash = hashlib.new("sha3_512", (word + salt).encode()).hexdigest()
                elif hash_type == "sha512-224":
                    word_hash = hashlib.new("sha512_224", (word + salt).encode()).hexdigest()
                elif hash_type == "whirlpool":
                    word_hash = hashlib.new("whirlpool", (word + salt).encode()).hexdigest()
                elif hash_type == "doublemd5":
                    word_hash = hashlib.md5((word + salt).encode()).hexdigest()
                    word_hash = hashlib.md5(word_hash.encode()).hexdigest()
                else:
                    word_hash = hash_func((word + salt).encode()).hexdigest()

                if word_hash == hash_value:
                    result.append(word)
                    salt_result.append(salt)

    return "Error"



def show_progress(iteration, total):
    progress = (iteration / total) * 100
    bar_length = 50
    filled_length = int(bar_length * progress // 100)
    bar = colorize_text("=", "red", "bold") * filled_length + '-' * (bar_length - filled_length)
    sys.stdout.write(f'\r{colorize_text("Progress:", "yellow")} [{bar}] {progress:.2f}%  ')
    sys.stdout.flush()
    time.sleep(0.001)

def calculate_total_time(start_time):
    end_time = time.time()
    total_time = end_time - start_time
    return total_time

def format_time(seconds):
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "{:02}:{:02}:{:02}".format(int(hours), int(minutes), int(seconds))

