#!/usr/bin/env python
# coding: utf-8

# Adapted from @Outflank and @_DaWouw 's InlineWhispers project. https://github.com/outflanknl/InlineWhispers
# All credit to them for the syswhispers regexp code

import re
# from pprint import pprint

functionsInName = "functions.txt"
fileInName = "syscalls.asm"
structsFileInName = "Syscalls.h"
fileOutName = fileInName.replace('.asm','.nim')

print(r"""
                                                                       
             %              ..%%%%%#               %/.                  
           /%%%%%,.%%%%%%%%%%%%%%%%%%%%%%%%%%%%.%%%%%%                  
       . #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.               
  %%*.%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% ,%%         
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.         
    #%%%%%%%%%%%%%%.                         %%%%%%%%%%%%%%%%           
      %%%%%%%(                                     %%%%%%%%%            
    &   %%#                                           .%%  ..           
     &&.                          .                     . #&            
      &&&&.               . %&&&&&&&&.                 &&&&             
       &&&&&&&.. .   . (&&&&&&&&&&&&&&&&&%. .     .&&&&&&&              
       .%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&               
         #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                
           ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                  
               &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                     
                   &&&&&&&&&&&&&&&&&&&&&&&&&&&                          
                            %&&&&&&&&.                                  
						NimlineWhispers
						@ajpc500 2021
""")
print("[i] in  {}".format(fileInName))
print("[i] out {}".format(fileOutName))

regexFunctionStart = re.compile(r'([a-z0-9]{1,70})(\s+PROC)', re.IGNORECASE)
regexFunctionEnd = re.compile(r'([a-z0-9]{1,70})(\s+ENDP)', re.IGNORECASE)
regexAsmComment = re.compile(r'([^;\r\n]*)', re.IGNORECASE)
regexHexNotation = re.compile(r'([^;\r\n]*[\s\+\[])([0-9a-f]{1,5})(?:h)([^;\r\n]*)', re.IGNORECASE)

def strip_chars(str):
	return str.strip("),;")

def parse_function_arg(arg_list):
	argType = argName = ''
	argTypeIndex = argNameIndex = 0

	arg_list = [strip_chars(a) for a in arg_list] # clean unneeded characters

	if len(arg_list) > 0:
		if len(arg_list) == 2:
			# TYPE Name
			argTypeIndex = 0
			argNameIndex = 1
		elif len(arg_list) == 3:
			if arg_list[0].upper() in ['IN','OUT'] and arg_list[2].upper() != 'OPTIONAL':
				# IN TYPE Name
				argTypeIndex = 1
				argNameIndex = 2
			elif arg_list[0].upper() not in ['IN','OUT'] and arg_list[2].upper() == 'OPTIONAL':
				# TYPE Name OPTIONAL
				argTypeIndex = 0
				argNameIndex = 1
			elif arg_list[0].upper() not in ['IN','OUT'] and arg_list[1].upper() == '*':
				# TYPE * Name
				argTypeIndex = 0
				argNameIndex = 1

		elif len(arg_list) == 4:
			if arg_list[0].upper() in ['IN','OUT'] and arg_list[1].upper() in ['IN','OUT']:
				# IN OUT TYPE Name
				argTypeIndex = 2
				argNameIndex = 3
			elif arg_list[0].upper() in ['IN','OUT'] and arg_list[1].upper() not in ['IN','OUT'] and arg_list[2].upper() == '*':
				# OUT TYPE * Name
				argTypeIndex = 1
				argNameIndex = 3
			elif arg_list[0].upper() in ['IN','OUT'] and arg_list[1].upper() not in ['IN','OUT'] and arg_list[2].upper() != '*' and arg_list[3].upper() == 'OPTIONAL':
				# OUT TYPE Name OPTIONAL
				argTypeIndex = 1
				argNameIndex = 2
		elif len(arg_list) == 5:
			if arg_list[0].upper() in ['IN','OUT'] and arg_list[1].upper() in ['IN','OUT'] and arg_list[3] == '*':
				# IN OUT TYPE * Name
				argTypeIndex = 2 
				argNameIndex = 4
			elif arg_list[0].upper() in ['IN','OUT'] and arg_list[1].upper() in ['IN','OUT'] and arg_list[4].upper() == 'OPTIONAL':
				# IN OUT TYPE Name OPTIONAL
				argTypeIndex = 2 
				argNameIndex = 3

		if argNameIndex != argTypeIndex: 
			return arg_list[argNameIndex], arg_list[argTypeIndex]
		else:
			print('[i] No idea what we\'re doing with function arg: {}.'.format(arg_list))				

functions = []
filterFunctions = False
try:
	with open(functionsInName, mode='r') as functionsIn:
		functions = ['Nt'+f[2:] if f[:2] == 'Zw' else f for f in [l.strip() for l in functionsIn.readlines()]]
		filterFunctions = len(functions) and "*" not in functions
		print('[i] Function filter file "{}" contains {} functions.'.format(functionsInName,len(functions)))
except:
	print('[i] Function filter file "{}" not found. So not filtering functions.'.format(functionsInName))

functionOutputs = {}
functionArgs = {}

try:
	with open(structsFileInName, mode='r') as structsIn:
		inFunction = False
		currentFunction = ''
		currentFunctionArgs = []
		for f in [l.strip() for l in structsIn.readlines()]:
			if f.startswith("EXTERN_C"):
				functionName = currentFunction = f.split()[2].split("(")[0]
				if functionName in functions:			
					inFunction = True
					functionOutputs[functionName] = f.split()[1]
					if f.endswith(");"):
						inFunction = False
						functionArgs[currentFunction] = []
			elif inFunction:
				arg = f.split()
				if len(arg) > 0:
					argType, argName = parse_function_arg(arg)
					currentFunctionArgs.append([argName, argType])
				if arg[-1].endswith(");"):
					inFunction = False
					functionArgs[currentFunction] = currentFunctionArgs
					currentFunctionArgs = []					
	print('[i] Found return types for {} functions.'.format(len(functionOutputs)))
	# pprint(functionArgs) # Useful for debug :D
except:
	print('[i] Functions and Structs file "{}" not found. We need this to get return types and args. Exiting...'.format(structsFileInName))
	exit()
		

def get_function_return_type(functionName):
	if functionName in functionOutputs:
		return functionOutputs[functionName]
	else:
		print('[i] We don\'t know the return type for {}, fix this manually.'.format(functionName))
		return 'UNKNOWN'

def get_function_arguments(functionName):
	if functionName in functionOutputs:
		argString = ""
		for arg in functionArgs[functionName]:
			if argString:
				argString += ", "
			argString += "{}: {}".format(arg[1], arg[0])
		return argString
	else:
		print('[i] We don\'t know the arguments for {}, fix this manually.'.format(functionName))
		return 'UNKNOWN_ARG: UNKNOWN_TYPE'

filterThisFunction = False
with open(fileInName, mode='r') as fileIn:
	lines = fileIn.readlines()
	lines.pop(0)	#remove .code line
	
	out = '{.passC:"-masm=intel".}\n\n'
	inFunction = False
	for line in lines:
		if inFunction:
			if regexFunctionEnd.match(line):
				inFunction = False
				out += '' if filterThisFunction else '    \"\"\"'+'\n'
			elif not filterThisFunction:
				mhex = regexHexNotation.match(line)
				if mhex:
					out += mhex[1]+'0x'+mhex[2]+mhex[3]+'\n'
				else:
					out += regexAsmComment.match(line)[1]+'\n'
		else:
			mstart = regexFunctionStart.match(line)
			if mstart:
				inFunction = True
				filterThisFunction = filterFunctions and not(mstart[1] in functions)
				out += '' if filterThisFunction else 'proc '+mstart[1]+ '*(' + get_function_arguments(mstart[1]) + ')' +': '+ get_function_return_type(mstart[1]) + ' {.asmNoStackFrame.} ='+'\n'
				out += '' if filterThisFunction else '    asm \"\"\"\n'
			elif not filterThisFunction:
				out += '\n'
	
	with open(fileOutName, mode='w') as fileOut:
		fileOut.write(out)
		fileOut.close()
		print("[+] Success! Outputted to {}".format(fileOutName))
	