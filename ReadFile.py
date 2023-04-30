
import csv
import os
def writeExcel(feature:dict, csv_file):
    value_list = list(feature.values())
    with open(csv_file, mode='a+', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(value_list)

def is_zero(f, tolerance=1e-6):
    return abs(f) < tolerance

def GetListOfpcapPaths(path):

    path_list = []
    with open(path, 'r') as file:
        # Read each line of the file
        for line in file:
            # Remove leading/trailing whitespace and newline characters
            path = line.strip()

            if line.startswith('#') or line == '\n':
                continue

            # Add the path to the list
            path_list.append(path)

    return path_list

def GetRidoffExtension(path):
    name_without_extension = os.path.splitext(path)[0]
    return name_without_extension