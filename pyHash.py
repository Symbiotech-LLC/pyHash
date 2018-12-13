#!/usr/bin/python -O

"""
Summary:
Point script to files, it will generate hashes
It will return the hashes to other scripts / tools
If ran directly, it will also create .md5 files for what was checked

# original author: https://github.com/srbrettle
# also copied code from checksumdir library
Author: grimmvenom <grimmvenom@gmail.com>

# find /path/to/dir/ -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum
"""

# Import libraries
import hashlib
import os
import sys
import argparse
import re


def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', "-file", action='append', dest='files', required=True,
						help='-f <filepath.txt> \n.txt file to check hash of')
	arguments = parser.parse_args()
	
	files = list()
	for file in arguments.files:
		files.append(os.path.abspath(file))
		if not os.path.exists(file):
			parser.error("File does not exist, Exiting")
	
	arguments.files = files
	return arguments


class checksum:
	def __init__(self, arguments):
		self.arguments = arguments
		self.HASH_FUNCS = {
			'md5': hashlib.md5,
			'sha1': hashlib.sha1,
			'sha256': hashlib.sha256,
			'sha512': hashlib.sha512}
	
	def generate_hashes(self, files):
		data = dict()
		for file in files:
			if os.path.isdir(file) or file.endswith('.app'):
				data[file] = {'md5': str(self.dirhash(file, 'md5'))}
			else:
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
	
	def dirhash(self, dirname, hashfunc='md5', excluded_files=None, ignore_hidden=False,
		followlinks=False, excluded_extensions=None):
		hash_func = self.HASH_FUNCS.get(hashfunc)
		if not hash_func:
			raise NotImplementedError('{} not implemented.'.format(hashfunc))
		
		if not excluded_files:
			excluded_files = []
		
		if not excluded_extensions:
			excluded_extensions = []
		
		if not os.path.isdir(dirname):
			raise TypeError('{} is not a directory.'.format(dirname))
		hashvalues = []
		for root, dirs, files in os.walk(dirname, topdown=True, followlinks=followlinks):
			if ignore_hidden:
				if not re.search(r'/\.', root):
					hashvalues.extend(
						[self._filehash(os.path.join(root, f),
										hash_func) for f in files if not
						 f.startswith('.') and not re.search(r'/\.', f)
						 and f not in excluded_files
						 and f.split('.')[-1:][0] not in excluded_extensions
						 ]
					)
			else:
				hashvalues.extend(
					[
						self._filehash(os.path.join(root, f), hash_func)
						for f in files
						if f not in excluded_files
						   and f.split('.')[-1:][0] not in excluded_extensions
					]
				)
		return self._reduce_hash(hashvalues, hash_func)
	
	def _filehash(self, filepath, hashfunc):
		hasher = hashfunc()
		blocksize = 64 * 1024
		with open(filepath, 'rb') as fp:
			while True:
				data = fp.read(blocksize)
				if not data:
					break
				hasher.update(data)
		return hasher.hexdigest()
	
	def _reduce_hash(self, hashlist, hashfunc):
		hasher = hashfunc()
		for hashvalue in sorted(hashlist):
			hasher.update(hashvalue.encode('utf-8'))
		return hasher.hexdigest()


if __name__ == "__main__":
	arguments = get_arguments()
	hashes = checksum(arguments)
	data = hashes.generate_hashes(arguments.files)
	hashes.generate_md5_file(data)
