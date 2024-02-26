import argparse
import os 
import threading
import curses
from lib.style import *
from lib.help_and_errors import *
from lib.utils import *
from datetime import datetime
from sys import exit as syexit
from re import match


def main(calculate, id_hash, compare, dehash, algorithm_list, hash, string, file, directory, export, algorithm, h1, h2, wordlist, t, block_size, man, salt, salt_wordlist):
    
    
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y-%m-%d %H:%M:%S")
    current_dir = os.getcwd()
    file_pattern =  r'\.[a-zA-Z0-9]+$'
    valid_algorithm_list = ["md5", 
                            "sha1", 
                            "sha224", 
                            "sha256", 
                            "sha384", 
                            "sha512", 
                            "crc32", 
                            "blake2b", 
                            "blake2s", 
                            "ripemd160", 
                            "doublemd5",
                            "md4",
                            "md5-sha1",
                            "sm3",
                            "sha3-224",
                            "sha3-384",
                            "sha512-256",
                            "sha3-256",
                            "sha3-512",
                            "sha512-224",
                            "whirlpool",
                            "ntlm"]
    
    

    

    if export is not None:
        
        if not export.startswith("./") and not export.startswith("../") and not export.startswith("/"):
            
            export = f"./{export}"
        
        if match(r".*/(?:[^/]+\.[a-zA-Z0-9]+|[^/]+)$", export):
            
            if export.startswith("../"):
                export_path = os.path.normpath(os.path.join(current_dir, export))
            else:
                export_path = os.path.normpath(os.path.join(current_dir, export.lstrip("./")))
                
            
        else:
            
            print(colorize_text("Error: You need to provide a file name", "red"))
            syexit()
            
    
    if wordlist is not None:
        
        if not wordlist.startswith("./") and not wordlist.startswith("../") and not wordlist.startswith("/"):
            
            wordlist = f"./{wordlist}"
        
        if match(r".*/(?:[^/]+\.[a-zA-Z0-9]+|[^/]+)$", wordlist):
            
            if wordlist.startswith("../"):
                wordlist = os.path.normpath(os.path.join(current_dir, wordlist))
            else:
                wordlist = os.path.normpath(os.path.join(current_dir, wordlist.lstrip("./")))
                
            
        else:
            
            print(colorize_text("Error: You need to provide a wordlist file name", "red"))
            syexit()
            
            
            
    if salt_wordlist is not None:
        
        if not salt_wordlist.startswith("./") and not salt_wordlist.startswith("../") and not salt_wordlist.startswith("/"):
            
            salt_wordlist = f"./{salt_wordlist}"
        
        if match(r".*/(?:[^/]+\.[a-zA-Z0-9]+|[^/]+)$", salt_wordlist):
            
            if salt_wordlist.startswith("../"):
                salt_wordlist = os.path.normpath(os.path.join(current_dir, salt_wordlist))
            else:
                salt_wordlist = os.path.normpath(os.path.join(current_dir, salt_wordlist.lstrip("./")))
                
            
        else:
            
            print(colorize_text("Error: You need to provide a salt wordlist file name", "red"))
            syexit()


    if file is not None:
        
        if not file.startswith("./") and not file.startswith("../") and not file.startswith("/"):
            
            file = f"./{file}"
        
        if match(r".*/(?:[^/]+\.[a-zA-Z0-9]+|[^/]+)$", file):
            
            if file.startswith("../"):
                
                file = os.path.normpath(os.path.join(current_dir, file))
            else:
                file = os.path.normpath(os.path.join(current_dir, file.lstrip("./")))
                
            
        else:
            
            print(colorize_text("Error: You need to provide a file name", "red"))
            syexit()
            

    if directory is not None:
        
        if re.search(file_pattern, directory):
            
            print(colorize_text("Error: You need to provide a dir not a file", "red"))
            syexit()
            
        else:
            
            directory = os.path.normpath(os.path.join(current_dir, directory))

    
    
    
    
    if calculate:
        
        if block_size == None:
            block_size = 4096
        elif block_size < 128:
            block_size = 128
        
        if algorithm == None:
            algorithm = "sha256"
        else:
            algorithm = algorithm.lower()
            if algorithm not in valid_algorithm_list:
                print(invalid_algo(algorithm))
                syexit()
            
            
        
        if hash != None:
            print(not_required_errors("--hash"))
            syexit()
        if h1 != None:
            print(not_required_errors("--h1"))
            syexit()
        if h2 != None:
            print(not_required_errors("--h2"))
            syexit()
        if wordlist != None:
            print(not_required_errors("--wordlist"))
            syexit()
        if t != None:
            print(not_required_errors("--t"))
            syexit()
        
        if (string != None and file != None) or (string != None and directory != None) or (directory!= None and file!=None) or (directory!=None and file!=None and string!=None):
            
            print(colorize_text("Error: You can only choose one (--string, --file, --dir)", "red"))
            syexit()
            
      
        if string != None:
            
            if export != None:
                
                try:
                    init_banner()
                    


                    string_hash = calculate_string_hash(string, algorithm)
                        
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nSTRING:", "cyan", "bold")+colorize_text(f" {string}", "yellow"))
                    print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                    
                    print(colorize_text("\nLENGHT:", "cyan", "bold")+colorize_text(f" {len(string_hash)}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {string_hash}", "yellow"))
                    separator("cyan")
                    with open(f"{export_path}", "w") as export_file:
                            
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n\n")
                        export_file.write(f"ALGORITHM: {algorithm.upper()}\n\n")
                        export_file.write(f"LENGHT: {len(string_hash)}\n\n")
                        export_file.write(f"STRING: {string}\n\n")
                        export_file.write(f"HASH: {string_hash}\n\n")
                except:
                    print(colorize_text("Error: Error calculating hash", "red"))
                    syexit()
                
                
                
            else:
                try:
                    init_banner()

                    string_hash = calculate_string_hash(string, algorithm)
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nSTRING:", "cyan", "bold")+colorize_text(f" {string}", "yellow"))
                    print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                    print(colorize_text("\nLENGHT:", "cyan", "bold")+colorize_text(f" {len(string_hash)}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {string_hash}", "yellow"))
                    separator("cyan")
                except:
                    print(colorize_text("Error: Error calculating hash", "red"))
                    syexit()
            
        elif file != None:
            if export != None:
                
                try:
                    init_banner()


                    file_hash = calculate_file_hash(file, algorithm, block_size)
                    
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {file}", "yellow"))
                    print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                    print(colorize_text("\nLENGHT:", "cyan", "bold")+colorize_text(f" {len(file_hash)}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {file_hash}", "yellow"))
                    separator("cyan")
                    with open(f"{export_path}", "w") as export_file:
                            
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n\n")
                        export_file.write(f"ALGORITHM: {algorithm.upper()}\n\n")
                        export_file.write(f"LENGHT: {len(file_hash)}\n\n")
                        export_file.write(f"FILE: {file}\n\n")
                        export_file.write(f"HASH: {file_hash}\n\n")
                except:
                    print(colorize_text("Error: Error calculating hash", "red"))
                    syexit()
                
                
                
            else:
                try:
                    init_banner()


                    file_hash = calculate_file_hash(file, algorithm, block_size)
                    
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {file}", "yellow"))
                    print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                    print(colorize_text("\nLENGHT:", "cyan", "bold")+colorize_text(f" {len(file_hash)}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {file_hash}", "yellow"))
                    separator("cyan")
                except:
                    print(colorize_text("Error: Error calculating hash", "red"))
                    syexit()
                         
        elif directory != None:
            
            if export != None:
                try:
                    hashes = calculate_hashes_directory(directory, algorithm, block_size)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nDIR:", "cyan", "bold")+colorize_text(f" {directory}", "yellow"))
                    separator("cyan")
                    with open(f"{export_path}", "w") as export_file:
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n\n")
                        export_file.write(f"DIR: {directory}\n\n")
                        export_file.write(f"{'-'*(len(directory)+6)}\n\n")
                    for path, hash_value in hashes.items():
                        print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {path}", "yellow"))
                        print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
    
                        print(colorize_text("\nLENGHT:", "cyan", "bold")+colorize_text(f" {len(hash_value)}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash_value}", "yellow"))
                        separator("cyan")
                        with open(f"{export_path}", "a") as export_file:
                        
                            export_file.write(f"FILE: {path}\n\n")
                            export_file.write(f"ALGORITHM: {algorithm.upper()}\n\n")
                            export_file.write(f"LENGHT: {len(hash_value)}\n\n")
                            export_file.write(f"HASH: {hash_value}\n\n")
                            export_file.write(f"{'-'*100}\n\n")
                except:
                        print(colorize_text("Error: Error calculating hash", "red"))
                        syexit()

            

            else:
                
                try:
                    hashes = calculate_hashes_directory(directory, algorithm, block_size)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nDIR:", "cyan", "bold")+colorize_text(f" {directory}", "yellow"))
                    separator("cyan")
                    
                    for path, hash_value in hashes.items():
                        print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {path}", "yellow"))
                        print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash_value}", "yellow"))
                        separator("cyan")
                    
                except:
                    print(colorize_text("Error: Error calculating hash", "red"))
                    syexit()
        
        
        
        
        
        
        
        
        else:
            
            print(required_errors("--string, --file or --dir"))   
    
    elif id_hash:
        
        if string != None:
            print(not_required_errors("--string"))
            syexit()
        if h1 != None:
            print(not_required_errors("--h1"))
            syexit()
        if h2 != None:
            print(not_required_errors("--h2"))
            syexit()
        if wordlist != None:
            print(not_required_errors("--wordlist"))
            syexit()
        if t != None:
            print(not_required_errors("--t"))
            syexit()
        if directory != None:
            print(not_required_errors("--dir"))
            syexit()
        if block_size != None:
            print(not_required_errors("--block-size"))
            syexit()

        
        
        if hash != None and file != None:
            
            print(colorize_text("Error: You can only choose one (--hash or --file)", "red"))
            syexit() 
            
        if hash == None and file == None:
            print(colorize_text("Error: You need to provide a --hash or --file", "red"))
            syexit()
            
        
        if hash != None:

            print(hash)

            if is_a_hash(hash):

                if export != None:
                    
                    
                    algorithms_lst = detect_algorithm(hash)
                    
                    
                    init_banner()
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                    print(colorize_text(f"\nPOSSIBLE ALGORITHMS:", "yellow", "bold"))
                    
                    for algo_ in algorithms_lst:
                        print(colorize_text(f"\n                      [+] {algo_}", "green", "bold"))
                        
                    separator("cyan")
                    
                    with open(f"{export_path}", "w") as export_file:
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n")
                        export_file.write(f"\nHASH: {hash}\n")
                        export_file.write(f"\nPOSSIBLE ALGORITHMS:")
                        
                        for algo_ in algorithms_lst:
                            export_file.write("\n")
                            export_file.write(f"\n                      [+] {algo_}")
                    
                    
                    
                
                
                
                else:
                    
                    
                    algorithms_lst = detect_algorithm(hash)
                    
                    
                    init_banner()
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                    print(colorize_text(f"\nPOSSIBLE ALGORITHMS:", "yellow", "bold"))
                    
                    for algo_ in algorithms_lst:
                        print(colorize_text(f"\n                      [+] {algo_}", "green", "bold"))
                        
                    separator("cyan")
                        
                        
                    
            
            
            
            
            
            
            
            
            else:
                print(colorize_text("Error: Unknown hash type", "red"))
                syexit() 
                
            
            
            
            
        elif file != None:
            
            if export != None:
                
                with open(file, 'r') as file:
                    hashes = file.read().splitlines()
                    file.close()
                with open(f"{export_path}", "w") as export_file:
                    export_file.write("##############################")
                    export_file.write("\n##          REPORT          ##")
                    export_file.write("\n##############################\n\n")
                    export_file.write(f"DATE: {formatted_date_time}\n")
                    init_banner()
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    separator("cyan")
                    for hash_ in hashes:
                        export_file.write(f"\nHASH: {hash_}")
                        export_file.write(f"\nPOSSIBLE ALGORITHMS:")
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash_}", "yellow"))
                        print(colorize_text(f"\nPOSSIBLE ALGORITHMS:", "yellow", "bold"))
                        try:
                            algo = detect_algorithm(hash_)
                            for a in algo:
                                export_file.write("\n")
                                export_file.write(f"\n                      [+] {a}")
                                
                                print(colorize_text(f"\n                      [+] {a}", "green", "bold"))
                            export_file.write("\n\n")
                            separator("cyan")
                        except:
                                print(colorize_text(f"\n                      [-] {'Unknown hash type'}", "red", "bold"))
                                separator("cyan")
                    
            
            
            else:
                
                
                with open(file, 'r') as file:
                    hashes = file.read().splitlines()
                    init_banner()
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    separator("cyan")
                    for hash_ in hashes:
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash_}", "yellow"))
                        print(colorize_text(f"\nPOSSIBLE ALGORITHMS:", "yellow", "bold"))
                        try:
                            algo = detect_algorithm(hash_)
                            for a in algo:
                                print(colorize_text(f"\n                      [+] {a}", "green", "bold"))
                            separator("cyan")
                        except:
                                print(colorize_text(f"\n                      [-] {'Unknown hash type'}", "red", "bold"))
                                separator("cyan")
                        
                    
        
        
        
        
        else:
            
            print(required_errors("--hash or --file"))
 
    elif compare:
        
        if hash != None:
            print(not_required_errors("--hash"))
            syexit()
        if string != None:
            print(not_required_errors("--string"))
            syexit()
        if file != None:
            print(not_required_errors("--file"))
            syexit()
        if directory != None:
            print(not_required_errors("--dir"))
            syexit()
        if wordlist != None:
            print(not_required_errors("--wordlist"))
            syexit()
        if t != None:
            print(not_required_errors("--t"))
            syexit()
        if block_size != None:
            print(not_required_errors("--block-size"))
            syexit()

            
        if h1 == None or h2 == None or (h1 == None and h2 == None):
            
            print(colorize_text("Error: You need to provide a -h1 and -h2", "red"))
            syexit()    
        
        if is_a_hash(h1):
            
            if is_a_hash(h2):
                
                        if export != None:
                                if h1 == h2:

                                            init_banner()
                                            print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                                            print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "green"))
                                            print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "green"))
                                            print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" MATCH", "green", "bold"))
                                            separator("cyan")
                                            
                                            with open(f"{export_path}", "w") as export_file:
                                                export_file.write("##############################")
                                                export_file.write("\n##          REPORT          ##")
                                                export_file.write("\n##############################\n\n")
                                                export_file.write(f"DATE: {formatted_date_time}\n\n")
                                                export_file.write(f"HASH 1 {h1}\n\n")
                                                export_file.write(f"HASH 2: {h2}\n\n")
                                                export_file.write(f"RESULT: MATCH\n\n")
                                
                                elif len(h1) != len(h2):
                                    
                                            init_banner()
                                            print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                                            print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "yellow"))
                                            print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "yellow"))
                                            print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" LENGHT UNMATCH", "red", "bold"))
                                            separator("cyan")
                                            
                                            with open(f"{export_path}", "w") as export_file:
                                                export_file.write("##############################")
                                                export_file.write("\n##          REPORT          ##")
                                                export_file.write("\n##############################\n\n")
                                                export_file.write(f"DATE: {formatted_date_time}\n\n")
                                                export_file.write(f"HASH 1 {h1}\n\n")
                                                export_file.write(f"HASH 2: {h2}\n\n")
                                                export_file.write(f"RESULT: LENGHT UNMATCH\n\n")
                                    
                                    
                                else:

                                            init_banner()
                                            print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "yellow"))
                                            print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "yellow"))
                                            print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" UNMATCH", "red", "bold"))
                                            diff_positions = [i for i, (c1, c2) in enumerate(zip(h1, h2)) if c1 != c2]

                                
                                            marked_h1 = ''.join(colorize_text(c, "red", "bold") if i in diff_positions else colorize_text(c, "yellow") for i, c in enumerate(h1))
                                            marked_h2 = ''.join(colorize_text(c, "red", "bold") if i in diff_positions else colorize_text(c, "yellow") for i, c in enumerate(h2))

                                            print(colorize_text("\nMARKED HASH 1:", "cyan", "bold") + colorize_text(f" {marked_h1}", "yellow"))
                                            print(colorize_text("\nMARKED HASH 2:", "cyan", "bold") + colorize_text(f" {marked_h2}", "yellow"))

                                            with open(f"{export_path}", "w") as export_file:
                                                export_file.write("##############################")
                                                export_file.write("\n##          REPORT          ##")
                                                export_file.write("\n##############################\n")
                                                export_file.write(f"DATE: {formatted_date_time}\n\n")
                                                export_file.write(f"HASH 1 {h1}\n\n")
                                                export_file.write(f"HASH 2: {h2}\n\n")
                                                export_file.write(f"RESULT: UNMATCH\n\n")
                                            
                        else:        
                                
                                if h1 == h2:

                                            init_banner()
                                            print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                                            print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "green"))
                                            print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "green"))
                                            print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" MATCH", "green", "bold"))
                                            separator("cyan")
                                
                                elif len(h1) != len(h2):
                                    
                                            init_banner()
                                            print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                                            print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "yellow"))
                                            print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "yellow"))
                                            print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" LENGHT UNMATCH", "red", "bold"))
                                            separator("cyan")
                                    
                                    
                                else:

                                            init_banner()
                                            print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                                            print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "yellow"))
                                            print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "yellow"))
                                            print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" UNMATCH", "red", "bold"))
                                            diff_positions = [i for i, (c1, c2) in enumerate(zip(h1, h2)) if c1 != c2]

                                
                                            marked_h1 = ''.join(colorize_text(c, "red", "bold") if i in diff_positions else colorize_text(c, "yellow") for i, c in enumerate(h1))
                                            marked_h2 = ''.join(colorize_text(c, "red", "bold") if i in diff_positions else colorize_text(c, "yellow") for i, c in enumerate(h2))

                                            print(colorize_text("\nMARKED HASH 1:", "cyan", "bold") + colorize_text(f" {marked_h1}", "yellow"))
                                            print(colorize_text("\nMARKED HASH 2:", "cyan", "bold") + colorize_text(f" {marked_h2}", "yellow"))
                                            
            else:
                print(colorize_text("Error: -h2 is a invalid hash type", "red"))
        else:
            print(colorize_text("Error: -h1 is a invalid hash type", "red"))
                    
    elif dehash:
        
        if string != None:
            print(not_required_errors("--string"))
            syexit()
        if h1 != None:
            print(not_required_errors("--h1"))
            syexit()
        if h2 != None:
            print(not_required_errors("--h2"))
            syexit()
        if block_size != None:
            print(not_required_errors("--block-size"))
            syexit()
        if directory != None:
            print(not_required_errors("--dir"))
            syexit()
    
    
        if file != None and hash!=None:
            
            print(colorize_text("Error: You can only choose one (--hash or --file)", "red"))
            syexit()
        
        if file == None and hash==None:
            
            print(colorize_text("Error: You need to provide a --hash or --file", "red"))
            syexit()
        

        
        if hash != None:
            
            
            

            
            if t == None:
                t = 4
            
            hash_functions = {
                        "md5": hashlib.md5,
                        "sha1": hashlib.sha1,
                        "sha224": hashlib.sha224,
                        "sha256": hashlib.sha256,
                        "sha384": hashlib.sha384,
                        "sha512": hashlib.sha512,
                        "blake2b": hashlib.blake2b,
                        "blake2s": hashlib.blake2s,
                        "crc32": binascii.crc32,
                        "ripemd160": hashlib.new,
                        "doublemd5": hashlib.md5,
                        "sm3": hashlib.new,
                        "md4": hashlib.new,
                        "md5-sha1": hashlib.new,
                        "sha3-224": hashlib.new,
                        "sha3-256": hashlib.new,
                        "sha3-512": hashlib.new,
                        "sha512-224": hashlib.new,
                        "sha512-256": hashlib.new,
                        "whirlpool": hashlib.new,
                        "ntlm" : hashlib.new,
                    }
            
            
            if export != None:
                
                try:
                    
                    with open(wordlist, "r") as wordlist_file:
                        wordlist_content = [line.strip() for line in wordlist_file if line.strip()]
                        
                except FileNotFoundError:
                    
                    print(colorize_text("Error: The wordlist file was not found", "red"))
                    exit()
                
                except:
                    
                    print(colorize_text("Error: You need to provide a wordlist", "red"))
                    exit()
                
                
                
                if not wordlist_content:
                    print(colorize_text("Error: The wordlist is empty", "red"))
                    syexit()
                
                
                if len(wordlist_content) == 1:    
                    hash_type = detect_hash_type_dehash(hash)
                    if hash_type == "Error":
                        print(colorize_text("Error: The hash is not valid, it must be one of the allowed ones (--algorithm-list)", "red"))
                        syexit()
                    
                    
                    start_time = time.time()
                    

                    result = dehashing(wordlist_content, hash, hash_functions)
                    
                    total_time_seconds = calculate_total_time(start_time)

                    total_time_formatted = format_time(total_time_seconds)
                    
                    if result == "Error":
                        
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))
                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" FAIL", "red", "bold"))
                        
                        
                        
                        separator("cyan")
                        with open(f"{export_path}", "w") as export_file:
                            export_file.write("##############################")
                            export_file.write("\n##          REPORT          ##")
                            export_file.write("\n##############################\n\n")
                            export_file.write(f"DATE: {formatted_date_time}\n\n")
                            export_file.write(f"TIME ELAPSED: {total_time_formatted}\n\n")
                            export_file.write(f"HASH: {hash}\n\n")
                            export_file.write(f"WORDS TRIED: {len(wordlist_content)}\n\n")
                            export_file.write(f"RESULT: FAIL\n\n")
                            
                        
                    else:
                        
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))

                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" {result}", "green", "bold"))
                        separator("cyan")
                        with open(f"{export_path}", "w") as export_file:
                            export_file.write("##############################")
                            export_file.write("\n##          REPORT          ##")
                            export_file.write("\n##############################\n\n")
                            export_file.write(f"DATE: {formatted_date_time}\n\n")
                            export_file.write(f"TIME ELAPSED: {total_time_formatted}\n\n")
                            export_file.write(f"HASH: {hash}\n\n")
                            export_file.write(f"WORDS TRIED: {len(wordlist_content)}\n\n")

                            export_file.write(f"RESULT: {result}\n\n")

                
                if len(wordlist_content) > 1:
                    
                    hash_type = detect_hash_type_dehash(hash)
                    if hash_type == "Error":
                        print(colorize_text("Error: The hash is not valid, it must be one of the allowed ones (--algorithm-list)", "red"))
                        syexit()
                    
                    if len(wordlist_content) < t:
                        t = len(wordlist_content)
                        
                    
                    words_block = len(wordlist_content) // t
                    sublists = [wordlist_content[i:i + words_block] for i in range(0, len(wordlist_content), words_block)]
                    
                    threads = []
                    resul_t=[]
                    
                    start_time = time.time()
                    
                    curses.setupterm()
                    sys.stdout.write(curses.tigetstr('civis').decode())
                    sys.stdout.flush()
                    print(colorize_text("\nHASHMATE - TESTING WORDS:\n", "cyan", "bold"))
                    
                    progress_thread = threading.Thread(target=show_progress, args=(0, 1))
                    progress_thread.start()
                    
                    
                    
                    for sublist in sublists:

                        thread = threading.Thread(target=dehashing_threading, args=(sublist, hash, hash_functions, resul_t))
                        thread.start()
                        threads.append(thread)
                    
                    progress_thread.join()
                    
                    for thread in threads:
                        thread.join()
                        
                    total_time_seconds = calculate_total_time(start_time)

                    total_time_formatted = format_time(total_time_seconds)
                    
                    sys.stdout.write(curses.tigetstr('cnorm').decode())
                    sys.stdout.flush()
                    
                    
                    if len(resul_t) == 0:
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))
                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" FAIL", "red", "bold"))
                        separator("cyan")
                        with open(f"{export_path}", "w") as export_file:
                            export_file.write("##############################")
                            export_file.write("\n##          REPORT          ##")
                            export_file.write("\n##############################\n\n")
                            export_file.write(f"DATE: {formatted_date_time}\n\n")
                            export_file.write(f"TIME ELAPSED: {total_time_formatted}\n\n")
                            export_file.write(f"HASH: {hash}\n\n")
                            export_file.write(f"WORDS TRIED: {len(wordlist_content)}\n\n")
                            export_file.write(f"RESULT: FAIL\n\n")
                    else:
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))
                       
                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" {resul_t[0]}", "green", "bold"))
                        separator("cyan")
                        with open(f"{export_path}", "w") as export_file:
                            export_file.write("##############################")
                            export_file.write("\n##          REPORT          ##")
                            export_file.write("\n##############################\n\n")
                            export_file.write(f"DATE: {formatted_date_time}\n\n")
                            export_file.write(f"TIME ELAPSED: {total_time_formatted}\n\n")
                            export_file.write(f"HASH: {hash}\n\n")
                            export_file.write(f"WORDS TRIED: {len(wordlist_content)}\n\n")
                            export_file.write(f"RESULT: {resul_t[0]}\n\n")
            
            
            else:
                
                try:
                    
                    with open(wordlist, "r") as wordlist_file:
                        wordlist_content = [line.strip() for line in wordlist_file if line.strip()]
                        
                except FileNotFoundError:
                    
                    print(colorize_text("Error: The wordlist file was not found", "red"))
                    exit()
                
                except:
                    
                    print(colorize_text("Error: You need to provide a wordlist", "red"))
                    exit()
                
                
                
                if not wordlist_content:
                    print(colorize_text("Error: The wordlist is empty", "red"))
                    syexit()
                
                
                if len(wordlist_content) == 1:    
                    hash_type = detect_hash_type_dehash(hash)
                    if hash_type == "Error":
                        print(colorize_text("Error: The hash is not valid, it must be one of the allowed ones (--algorithm-list)", "red"))
                        syexit()
                    
                    
                    start_time = time.time()
                    

                    result = dehashing(wordlist_content, hash, hash_functions)
                    
                    total_time_seconds = calculate_total_time(start_time)

                    total_time_formatted = format_time(total_time_seconds)
                    
                    if result == "Error":
                        
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))
                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" FAIL", "red", "bold"))
                        separator("cyan")
                        
                    else:
                        
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))
                    
                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" {result}", "green", "bold"))
                        separator("cyan")

                
                if len(wordlist_content) > 1:
                    
                    hash_type = detect_hash_type_dehash(hash)
                    if hash_type == "Error":
                        print(colorize_text("Error: The hash is not valid, it must be one of the allowed ones (--algorithm-list)", "red"))
                        syexit()
                    
                    if len(wordlist_content) < t:
                        t = len(wordlist_content)
                        
                    
                    words_block = len(wordlist_content) // t
                    sublists = [wordlist_content[i:i + words_block] for i in range(0, len(wordlist_content), words_block)]
                    
                    threads = []
                    resul_t=[]
                    
                    curses.setupterm()
                    sys.stdout.write(curses.tigetstr('civis').decode())
                    sys.stdout.flush()
                    
                    print(colorize_text("\nHASHMATE - TESTING WORDS:\n", "cyan", "bold"))
                    start_time = time.time()
                    try:
                        progress_thread = threading.Thread(target=show_progress, args=(0, 1))
                        progress_thread.start()
                    except KeyboardInterrupt: 
                            sys.stdout.write(curses.tigetstr('cnorm').decode())
                            sys.stdout.flush()
                            sys.exit(0)

                    
                    try:
                        for sublist in sublists:

                        
                            thread = threading.Thread(target=dehashing_threading, args=(sublist, hash, hash_functions, resul_t))
                            
                            thread.start()
                            threads.append(thread)
                    except KeyboardInterrupt: 
                        progress_thread.join()
                        sys.stdout.write(curses.tigetstr('cnorm').decode())
                        sys.stdout.flush()
                        sys.exit(0)
                    
                    progress_thread.join()
                    
                    for thread in threads:
                        thread.join()
                        
                    total_time_seconds = calculate_total_time(start_time)

                    total_time_formatted = format_time(total_time_seconds)
                    print("\n")


                    sys.stdout.write(curses.tigetstr('cnorm').decode())
                    sys.stdout.flush()
                    
                    if len(resul_t) == 0:
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))
                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" FAIL", "red", "bold"))
                        separator("cyan")
                    else:
                        init_banner()
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nTIME ELAPSED:", "cyan", "bold")+colorize_text(f" {total_time_formatted}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nWORDS TRIED:", "cyan", "bold")+colorize_text(f" {len(wordlist_content)}", "yellow"))

                        print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" {resul_t[0]}", "green", "bold"))
                        separator("cyan")
        
        
        else:
            
            print(colorize_text("Error: You need to provide a hash", "red"))
        
            
    
    
    elif man:
        
        if hash != None:
            print(not_required_errors("--hash"))
            syexit()
        if string != None:
            print(not_required_errors("--string"))
            syexit()
        if file != None:
            print(not_required_errors("--file"))
            syexit()
        if directory != None:
            print(not_required_errors("--dir"))
            syexit()
        if export != None:
            print(not_required_errors("-oN"))
            syexit()
        if wordlist != None:
            print(not_required_errors("--wordlist"))
            syexit()
        if t != None:
            print(not_required_errors("--t"))
            syexit()
        if block_size != None:
            print(not_required_errors("--block-size"))
            syexit()
        if h1 != None:
            print(not_required_errors("-h1"))
            syexit()
        if h2 != None:
            print(not_required_errors("-h1"))
            syexit()

            
            
        print_manual()
        syexit()
    
    
    elif algorithm_list:
        
        if hash != None:
            print(not_required_errors("--hash"))
            syexit()
        if string != None:
            print(not_required_errors("--string"))
            syexit()
        if file != None:
            print(not_required_errors("--file"))
            syexit()
        if directory != None:
            print(not_required_errors("--dir"))
            syexit()
        if export != None:
            print(not_required_errors("-oN"))
            syexit()
        if wordlist != None:
            print(not_required_errors("--wordlist"))
            syexit()
        if t != None:
            print(not_required_errors("--t"))
            syexit()
        if block_size != None:
            print(not_required_errors("--block-size"))
            syexit()
        if h1 != None:
            print(not_required_errors("-h1"))
            syexit()
        if h2 != None:
            print(not_required_errors("-h1"))
            syexit()

            
        init_banner()
        print(colorize_text("\nALGORITHMS ALLOWED TO CALCULATE:", "cyan", "bold"))
        print(colorize_text("\n\n                      [+] MD5", "green", "bold"))
        print(colorize_text("\n                      [+] MD4", "green", "bold"))
        print(colorize_text("\n                      [+] MD5-SHA1", "green", "bold"))
        print(colorize_text("\n                      [+] DOUBLE MD5", "green", "bold"))
        print(colorize_text("\n                      [+] SHA1", "green", "bold"))
        print(colorize_text("\n                      [+] SHA224", "green", "bold"))
        print(colorize_text("\n                      [+] SHA256", "green", "bold"))
        print(colorize_text("\n                      [+] SHA384", "green", "bold"))
        print(colorize_text("\n                      [+] SHA512", "green", "bold"))
        print(colorize_text("\n                      [+] SHA512-224", "green", "bold"))
        print(colorize_text("\n                      [+] SHA512-256", "green", "bold"))
        print(colorize_text("\n                      [+] SHA3-224", "green", "bold"))
        print(colorize_text("\n                      [+] SHA3-256", "green", "bold"))
        print(colorize_text("\n                      [+] SHA3-384", "green", "bold"))
        print(colorize_text("\n                      [+] SHA3-512", "green", "bold"))
        print(colorize_text("\n                      [+] WHIRLPOOL", "green", "bold"))
        print(colorize_text("\n                      [+] SM3", "green", "bold"))
        print(colorize_text("\n                      [+] CRC32", "green", "bold"))
        print(colorize_text("\n                      [+] BLAKE2B", "green", "bold"))
        print(colorize_text("\n                      [+] BLAKE2S", "green", "bold"))
        print(colorize_text("\n                      [+] RIPEMD160", "green", "bold"))
        print(colorize_text("\n                      [+] NTLM", "green", "bold"))
        
        separator("cyan")
        syexit()
        

if __name__ == "__main__":
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="HashGen - Hash Toolkit")
    group_main = parser.add_mutually_exclusive_group(required=True)


    group_main.add_argument('--calculate', action='store_true', help="Calculation Mode")
    group_main.add_argument('--id-hash', action='store_true', help="Identification Mode")
    group_main.add_argument('--compare', action='store_true', help="Compare Mode")
    group_main.add_argument('--dehash', action='store_true', help="DeHash Mode")
    group_main.add_argument('--algorithm-list', action='store_true', help="Show a list of allowed algorithms")
    group_main.add_argument('--man', action='store_true', help="Manual")


    
    parser.add_argument("--hash", required=False, help="Hash to analyze", type=str)
    parser.add_argument("--string", required=False, help="String to encrypt", type=str)
    parser.add_argument("--file", required=False, help="Path to the file", type=str)
    parser.add_argument("--dir", required=False, help="Path to the directory", type=str)
    
    
    parser.add_argument("-oN", required=False, help="Export the file (Name with extension)", type=str)
    parser.add_argument("--algorithm", required=False, help="Hash algorithm to use (Default SHA256)", type=str)
    parser.add_argument("--wordlist", required=False, help="Path to the wordlist (Only .txt)", type=str)
    parser.add_argument("-h1", required=False, help="Hash 1 to Compare", type=str)
    parser.add_argument("-h2", required=False, help="Hash 2 to Compare", type=str)
    
    
    
    parser.add_argument("--block-size", required=False, help="Block Size", type=int)
    parser.add_argument("-t", required=False, help="Number of thread to dehash", type=int)
    
    parser.add_argument("-s", required=False, help="Salt for the hash", type=str)
    parser.add_argument("--salt-wordlist", required=False, help="Salt wordlist for the hash", type=str)
    
    args = parser.parse_args()

# Extract values from command line arguments



    calculate = args.calculate
    id_hash = args.id_hash
    compare = args.compare
    dehash = args.dehash
    algorithm_list = args.algorithm_list
    man = args.man

    hash = args.hash
    string = args.string
    file = args.file
    directory = args.dir
    
    
    export = args.oN
    algorithm = args.algorithm
    h1 = args.h1
    h2 = args.h2
    wordlist = args.wordlist
    
    
    
    block_size = args.block_size
    t = args.t
    salt = args.s
    salt_wordlist = args.salt_wordlist



    
    
    
    main(calculate, id_hash, compare, dehash, algorithm_list, hash, string, file, directory, export, algorithm, h1, h2, wordlist, t, block_size, man, salt, salt_wordlist)








