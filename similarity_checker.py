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
    database_1 = args.vulndb.split(',')[0]
    database_2 = args.vulndb.split(',')[1]
    databases = csv.reader(open('database', 'r'), delimiter=',')
    for database in databases:
        if database_1 == database[0]:
            return database[1]


def get_vlndb(url):
    global i
    os.system(f'curl {url} -o vlndb_{i}')
    i += 1


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


# set_a = find_cves(vlndb_1)
# set_b = find_cves(vlndb_2)
# result = calculate_similarity(set_a, set_b)
def lets_go():
    databases = parse_chosen_databases()
    import pdb;pdb.set_trace()
    for database in databases:
        url = get_url(database)
        get_vlndb(url)

    cves = []
    databases = glob.glob('./vlndb*')
    for database in databases:
        cves.append(find_cves(database))

    print(calculate_similarity(cves[0],cves[1]))

parser = argparse.ArgumentParser(description='Checks image and generates report accordingly')
parser.add_argument('--vulndb','-db', type=str,
                    help='Specifies the vulnerability database to be used')
parser.add_argument('--image','-i', type=str,
                    help='Specifies which image should be scanned')
parser.add_argument('--version','-v', nargs='?', const='arg_was_not_given', 
                    help='Optionally, provide an image_version')
args = parser.parse_args()
lets_go()
