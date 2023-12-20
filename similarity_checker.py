import re
import os
import csv
import argparse
import glob

i = 1


def parse_chosen_databases():
    if not args.vulndb:
        print('no databases given, give databases to compare via ')

    return args.vulndb.split(',')

def get_url(database_name):
    databases = csv.reader(open('database', 'r'), delimiter=',')
    for database in databases:
        if database_name == database[0]:
            return database[1]


def get_vlndb(url):
    global i
    os.system(f'curl {url} -o vlndb_{i}')
    i += 1

def unpack_vlndb():
    try:
        global i
        proc = subprocess.run([f'unzip vlndb_{i}'], shell=True, check=True, stdout=subprocess.PIPE)
        import pdb;pdb.set_trace()
        os.system(f'rm vlndb_{i}')
        os.system(f'mkdir vlndb_{i}')
        os.system(f'mv *.json ./vln_db{i}')
        i += 1
    except:
        i += 1
        pass 

def find_cves(report):
    f = open(report,'r')
    file = f.read()
    cves = re.findall(r'CVE-[0-9]*-[0-9]*', file)
    cves = set(cves)
    return cves

def calculate_similarity(set_a, set_b):
    intersection_of_sets = set_a.intersection(set_b)
    union_of_sets = set_a.union(set_b)
    smallest_set = min(len(set_a), len(set_b))

    # Jaccard similarity
    jaccard_similarity = len(intersection_of_sets) / len(union_of_sets)
    # with interiority
    jaccard_with_interiority = len(intersection_of_sets) / smallest_set

    return { 'jaccard_similarity': jaccard_similarity, 'jaccard_with_interiority': jaccard_with_interiority }


def lets_go():
    databases = parse_chosen_databases()
    for database in databases:
        url = get_url(database)
        get_vlndb(url)

    cves = []
    databases = glob.glob('./vlndb*')
    for database in databases:
        cves.append(find_cves(database))
    
    simis = []
    for base_cve in range(len(cves)-1):
        i = base_cve + 1
        for index in range(len(cves)):
            if not (i >= len(cves)):
                simis.append(calculate_similarity(cves[base_cve], cves[i]))
            i += 1

    print(simis)
    os.system('rm vlndb_*')

parser = argparse.ArgumentParser(description='Checks image and generates report accordingly')
parser.add_argument('--vulndb','-db', type=str,
                    help='Specifies the vulnerability database to be used')
args = parser.parse_args()
lets_go()
