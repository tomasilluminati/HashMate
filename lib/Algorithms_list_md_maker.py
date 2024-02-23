from hash_lib import HASH_LIB

hash = HASH_LIB
algo = set()

with open("./Identifiable_Algorithms.md", "w") as file:
    file.write("## IDENTIFIABLE ALGORITHMS (In alphabetical order)\n\n")
    
    for k, v in hash.items():
        for i in v:
            algo.add(i)
    
    algo = sorted(algo)
    
    for a in algo:
        file.write(f"- {a}\n")
        
    file.write(f"\n\n#### TOTAL: {len(algo)}")
