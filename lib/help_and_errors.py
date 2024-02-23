from lib.style import colorize_text
from os import path

def required_errors(param):
    return colorize_text(f"Error: {param} is required","red")

def not_required_errors(param):
    return colorize_text(f"Error: {param} is not required","red")

def invalid_hash(param):
    return colorize_text(f"Error: {param} is not a valid hash","red")

def invalid_algo(param):
    return colorize_text(f"Error: {param} is not a valid algorithm","red")

def print_manual():
    manual_text = """\n
    NAME
    
        HashMate - Hash Toolkit


    SYNOPSIS
    
        python3 hashmate.py [--calculate | --id-hash | --compare | --dehash | --algorithm-list] [options]


    DESCRIPTION
    
        HashMate is a toolkit for various hash operations.


    MODES
    
        --calculate         Calculation Mode
        --id-hash           Identification Mode
        --compare           Compare Mode
        --dehash            DeHash Mode
        --algorithm-list    Show a list of allowed algorithms


    CALCULATE OPTIONS 
    
        --string STRING       String to encrypt
        --file FILE           Path to the file
        --dir DIRECTORY       Path to the directory
        -oN EXPORT            Export the file (Name with extension)
        --algorithm ALGORITHM Hash algorithm to use (Default SHA256)
        --block-size SIZE     Block Size
        
        
    ID-HASH OPTIONS   
        
        --hash HASH           Hash to analyze
        -oN EXPORT            Export the file (Name with extension)
        
        
    COMPARE OPTIONS
        
        -h1 HASH1             Hash 1 to compare
        -h2 HASH2             Hash 2 to compare
        -oN EXPORT            Export the file (Name with extension)
    
    
    DEHASH OPTIONS
    
        --hash HASH           Hash to analyze
        --wordlist WORDLIST   Path to the wordlist (Only .txt)
        -t THREADS            Number of threads to dehash
        
        
    EXAMPLES
    
        Example usages of hashmate:
        
        
        $ python3 hashmate.py --calculate --string 'password' --algorithm md5
        
        $ python3 hashmate.py --id-hash --hash '5d41402abc4b2a76b9719d911017c592'
        
        $ python3 hashmate.py --compare -h1 "5d41402abc4b2a76b9719d911017c592" -h2 "5d41402abc4b2a76b9719d911017c593"
        
        $ python3 hashmate.py --dehash --hash 6fa14d5449c017f20dcd9709de5b4cd3
        
        $ python3 hashmate.py --algorithm-list


    AUTHOR
    
        Tomas Illuminati
    
    COPYRIGHT © Tomas Illuminati 2024
    
    \n"""
    print(manual_text)



