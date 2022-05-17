'''
This script can be used to perform ip, filehash and domian lookups from VirusTotal. 
- GS
'''
#!/usr/bin/python
from __future__ import print_function
import simplejson
import urllib
import urllib2
import fileinput
import time
import sys
import getopt

apiKey = "<API KEYS?"

# http://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
def stderrPrint(*objs):
	print(*objs, file=sys.stderr)
	
	

# http://stackoverflow.com/questions/493386/how-to-print-in-python-without-newline-or-space
def stdoutPrint(string):
	print(string, end="")
	
	
	
def getResourceFromStdInput(delimeter, batchLength):
	inputs = []
	input = ""
	i = 0;
	count = 0;
	for line in fileinput.input():
		i += 1
		input += line.replace("\n", delimeter)
		if(i == batchLength):
			if(input != ''):
				inputs.append(input.rstrip(delimeter))
			input = ""
			i = 0
		count += 1
	
	if(input != ''):
		inputs.append(input.rstrip(delimeter))

	#stderrPrint("Debug:")
	#stderrPrint(inputs)
	#stderrPrint("-------------------------------------")
	#stderrPrint(count)
	#stderrPrint("-------------------------------------")

	return (inputs, count)
	


def getJsonResponse_post(url, parameters):
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	
	response_dict = simplejson.loads(json)
	#print(response_dict)
	
	return response_dict
	
	
	
def extractFieldsFromJsonResonse(response_dict, fields):
	result = ""

	#stderrPrint("Debug:")
	#stderrPrint(type(response_dict))
	#stderrPrint("-------------------------------------")
	
	if(type(response_dict) is dict):
		for field in fields:
			try:
				result += str(response_dict[field]) + "\t"
			except:
				result += "-\t"
		result = result.rstrip("\t") + "\n"
		return result


	for res in response_dict:
		for field in fields:
			try:
				result += str(res[field]) + "\t"
			except:
				result += "-\t"
		result = result.rstrip("\t") + "\n"
	
	return result
	
	

def virustotal_filehash(resources, resultFields):
	
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": resources, "apikey": apiKey}
	
	#Test input
	#parameters = {"resource": "d5e69b57d5c4afdf9f5cffd6fd8ad58c, 2c8aa1bd6dff1cfe621dd35db09b8e3f, 99017f6eebbac24f351415dd410d522d", "apikey": "4c03db86b5b634ee72f213ddd4551a6bfa6a2d21f45d7bc8a9ef4bdcf9601c56"}
	
	response_dict = getJsonResponse_post(url, parameters)
	
	result = extractFieldsFromJsonResonse(response_dict, resultFields)
	
	return result
	
	
	
def virustotal_domain(resources, resultFields):
	url = "http://www.virustotal.com/vtapi/v2/url/report"
	parameters = {"resource": resources, "scan" : "1", "apikey": apiKey}

	response_dict = getJsonResponse_post(url, parameters)
	
	result = extractFieldsFromJsonResonse(response_dict, resultFields)
	
	return result
	
	

def virustotal_ip(resources, resultFields):
	url = "http://www.virustotal.com/vtapi/v2/ip-address/report"
	parameters = {"resource": resources, "scan" : "1", "apikey": apiKey}

	response_dict = getJsonResponse_post(url, parameters)
	
	result = extractFieldsFromJsonResonse(response_dict, resultFields)
	
	return result



def dispatch(batchLength, defaultFields, delimeter, header, func):
	inputs, count = getResourceFromStdInput(delimeter, batchLength)

	stderrPrint(header)
	stderrPrint("Looking up " + str(count) + " entries, " + str(len(inputs)) + " batches.")
	stderrPrint("Batch's length: " + str(batchLength) + " entires.")
	
	j = 0
	for i in inputs:
		stdoutPrint(func(i, defaultFields))
		# http://stackoverflow.com/questions/311627/how-to-print-date-in-a-regular-format-in-python
		stderrPrint("\t" + str(time.strftime("%Y-%m-%d %H:%M:%S")) + " - " + "Printed Batch# " + str(j) + ".")
		j += 1
		time.sleep(16)



def optMux(flagOpt):
	################################################################# Domain lookup
	if(flagOpt == 0):
		batchLength = 25
		defaultFields = ["resource", "positives", "total", "permalink"]
		delimeter = '\n'
		header = '=====================\n*** Domain Lookup ***\n====================='
		func = virustotal_domain
	
	################################################################# File Hash lookup
	elif(flagOpt == 1):
		batchLength = 25
		defaultFields = ["resource", "positives", "total", "permalink"]
		delimeter = ','
		header = '========================\n*** File Hash Lookup ***\n========================'
		func = virustotal_filehash
		
	################################################################# IP lookup
	elif(flagOpt == 2):
		batchLength = 25
		defaultFields = ["resource", "positives", "total", "permalink"]
		delimeter = '\n'
		header = '=====================\n*** Domain Lookup ***\n====================='
		func = virustotal_domain
	
	
	dispatch(batchLength, defaultFields, delimeter, header, func)


def main():
	flagOpt = 0;
	i = 0
	for arg in sys.argv:
		if sys.argv[i] in ("-i", "--ip"):
			flagOpt = 2
			del sys.argv[i]
		elif sys.argv[i] in ("-f", "--filehash"):
			flagOpt = 1
			del sys.argv[i]
		elif sys.argv[i] in ("-d", "--domain"):
			flagOpt = 0
			del sys.argv[i]
		i += 1


		
	
	#stderrPrint("flagOpt: " + str(flagOpt))
	#stderrPrint("sys.argv = " + str(sys.argv))
	optMux(flagOpt)


if __name__ == "__main__":
	main()
