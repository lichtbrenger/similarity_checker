import re
import os
import csv
import argparse
import glob
import subprocess

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

def unpack_vlndb():
    try:
        global i
        proc = subprocess.run([f'unzip vlndb_{i}'], shell=True, check=True, stdout=subprocess.PIPE)
        os.system(f'rm vlndb_{i}')
        os.system(f'mkdir vlndb_{i}')
        os.system(f'mv *.json ./vlndb_{i}')
        i += 1
    except:
        i += 1
        pass 

def find_cves(report):
    if os.path.isfile(report):
        f = open(report,'r')
        file = f.read()
        cves = re.findall(r'CVE-[0-9]*-[0-9]*', file)
        cves = set(cves)
        return cves
    else:
        files = glob.glob(f'./{report}/*')
        all_cves = []
        for file in files:
            f = open(file,'r')
            file_2 = f.read()
            cves = re.findall(r'CVE-[0-9]*-[0-9]*', file_2)
            cves = set(cves)
            all_cves.extend(list(cves))
        all_cves = set(all_cves)
        return all_cves


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
    os.system('rm -r vlndb_*')
    databases = parse_chosen_databases()
    for database in databases:
        url = get_url(database)
        get_vlndb(url)
        unpack_vlndb()


    cves = []
    databases = glob.glob('./vlndb*')
    for database in databases:
        cves.append(find_cves(database))
    
    simis = []
    for base_cve in range(len(cves)-1):
        i = base_cve + 1
        for index in range(len(cves)):
            if not (i >= len(cves)):
                if not cves[base_cve] or not cves[i]:
                    import pdb;pdb.set_trace()
                simis.append(calculate_similarity(cves[base_cve], cves[i]))
            i += 1

    print(simis)
    os.system('rm -r vlndb_*')

parser = argparse.ArgumentParser(description='Checks image and generates report accordingly')
parser.add_argument('--vulndb','-db', type=str,
                    help='Specifies the vulnerability database to be used')
args = parser.parse_args()
lets_go()
