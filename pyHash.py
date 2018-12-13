#!/usr/bin/python -O

"""
Summary:
Point script to files, it will generate hashes
It will return the hashes to other scripts / tools
If ran directly, it will also create .md5 files for what was checked

# original author: https://github.com/srbrettle
Author: grimmvenom <grimmvenom@gmail.com>
"""
# Import libraries
import hashlib
import os
import sys
import argparse


def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', "-file", action='append', dest='file', required=True,
	                    help='-f <filepath.txt> \n.txt file to check hash of')
	arguments = parser.parse_args()
	
	files = list()
	for file in arguments.file:
		files.append(os.path.abspath(file))
		if not os.path.exists(file):
			parser.error("File does not exist, Exiting")
	
	arguments.file = files
	return arguments


class pyHash:
	def __init__(self, arguments):
		self.arguments = arguments
	
	def generate_hashes(self):
		data = dict()
		for file in self.arguments.file:
			data[file] = dict()
			with open(file, 'rb') as f:
				content = f.read()
				# data[file]['sha1'] = str(hashlib.sha1(content).hexdigest())  # SHA-1
				# data[file]['sha224'] = str(hashlib.sha224(content).hexdigest())  # SHA-224
				data[file]['sha256'] = str(hashlib.sha256(content).hexdigest())  # SHA-256
				# data[file]['sha384'] = str(hashlib.sha384(content).hexdigest())  # SHA-384
				# data[file]['sha512'] = str(hashlib.sha512(content).hexdigest())  # SHA-512
				# data[file]['sha3_224'] = str(hashlib.sha3_224(content).hexdigest()) # SHA-3-224
				data[file]['sha3_256'] = str(hashlib.sha3_256(content).hexdigest())  # SHA-3-256
				# data[file]['sha3_384'] = str(hashlib.sha3_384(content).hexdigest()) # SHA-3-384
				# data[file]['sha3_512'] = str(hashlib.sha3_512(content).hexdigest()) # SHA-3-512
				
				# MD5
				md5 = hashlib.md5()
				for i in range(0, len(content), 8192):
					md5.update(content[i:i + 8192])
				data[file]['md5'] = str(md5.hexdigest())
		
		return data
	
	def generate_md5_file(self, data):
		for path, hashes in data.items():
			md5_hash = str(hashes['md5'])
			print(path + ": md5 -> " + md5_hash)
			# Determine File Names and Paths
			filename = os.path.basename(path)
			basename = os.path.splitext(filename)
			md5_filename = str(os.path.splitext(filename)[0]) + ".md5"
			md5_path = path.replace(''.join(basename), md5_filename)
			
			if not os.path.exists(md5_path):
				print("Generating " + md5_path)
				with open(md5_path, 'w') as the_file:
					the_file.write(md5_hash)
			else:  # File Exists, Compare and overwrite if outdated
				with open(md5_path, 'r') as myfile:
					file_contents = myfile.read().replace('\n', '')
				if md5_hash != str(file_contents):
					print("Hashes do NOT Match for " + str(path))
					print("current md5:\n", md5_hash, "\nold md5:\n", file_contents)
					with open(md5_path, 'w') as the_file:  # Update md5 if outdated from current file
						the_file.write(md5_hash)


if __name__ == "__main__":
	arguments = get_arguments()
	hashes = pyHash(arguments)
	data = hashes.generate_hashes()
	hashes.generate_md5_file(data)
