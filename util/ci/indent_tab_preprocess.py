#!/usr/bin/python3

import sys
import re

def main():
	if len(sys.argv) != 4:
		#print("Bad arguments")
		#print(sys.argv)
		exit()
	mlc_begin = sys.argv[1]
	mlc_end = sys.argv[2]
	file = open(sys.argv[3], "r")

	re_mlc_begin = "^.*{}".format(mlc_begin)
	re_mlc_begin_end = "^.*{}.*{}".format(mlc_begin, mlc_end)
	re_mlc_end = "^.*{}".format(mlc_end)
	
	lines = []
	
	#print(re_mlc_begin)
	#print(re_mlc_begin_end)
	#print(re_mlc_end)
	#print(file)

	limit = -1
	for line in file:
		if limit == -1:
			find = re.search(re_mlc_begin, line)
			if find:
				if not re.search(re_mlc_begin_end, line):
					find = re.search("^\\s*", line)
					limit = find.span()[1]
			lines.append(line)
		else:
			find = re.search(re_mlc_end, line)
			if find:
				begin = find.span()[1] - 2
				if begin > limit:
					lines.append(line[0:limit] + line[begin:])
				else:
					lines.append(line)
				limit = -1
			else:
				find = re.search("^$", line)
				if find:
					lines.append(line)
				else:
					find = re.search("^\\s*", line)
					if find:
						end = find.span()[1]
						if end > limit:
							lines.append(line[0:limit] + line[end:])
						else:
							lines.append(line)
					else:
						lines.append(line)
	
	file.close()
	file = open(sys.argv[3], "w")
	for line in lines:
		file.write(line)
	file.close()

if __name__ == "__main__":
	main()
