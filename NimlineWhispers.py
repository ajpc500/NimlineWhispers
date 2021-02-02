#!/usr/bin/env python
# coding: utf-8

# Adapted from @Outflank and @_DaWouw 's InlineWhispers project. https://github.com/outflanknl/InlineWhispers
# All credit to them for the syswhispers regexp code

import re, random, string
import argparse
from pprint import pprint

class NimlineWhispers:

	def __init__(self, debug, randomise):
		self.debug = debug
		self.randomise = randomise

		self.functionsInName = "functions.txt"
		self.fileInName = "syscalls.asm"
		self.structsFileInName = "Syscalls.h"
		self.fileOutName = self.fileInName.replace('.asm','.nim')

		self.regexFunctionStart = re.compile(r'([a-z0-9]{1,70})(\s+PROC)', re.IGNORECASE)
		self.regexFunctionEnd = re.compile(r'([a-z0-9]{1,70})(\s+ENDP)', re.IGNORECASE)
		self.regexAsmComment = re.compile(r'([^;\r\n]*)', re.IGNORECASE)
		self.regexHexNotation = re.compile(r'([^;\r\n]*[\s\+\[])([0-9a-f]{1,5})(?:h)([^;\r\n]*)', re.IGNORECASE)

		self.functions = []
		self.filterFunctions = False
		self.functionOutputs = {}
		self.functionArgs = {}
		self.function_map = {}

		self.printBanner()
		self.read_required_functions_from_file()
		self.generate_function_args_mapping()
		self.produce_randomised_function_names()


	def printBanner(self):
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
		print("[i] in  {}".format(self.fileInName))
		print("[i] out {}".format(self.fileOutName))

	def produce_randomised_function_names(self):
		if self.randomise: print("[i] Producing randomised function mapping...")
		for function in self.functions:
			rand_val = ''.join(random.choices(string.ascii_letters, k=16))
			self.function_map[function] = rand_val if self.randomise else function
			if self.randomise: print("\t{} -> {}".format(function, rand_val))

	def strip_chars(self, str):
		return str.strip("),;")

	def parse_function_arg(self, arg_list):
		argType = argName = ''
		argTypeIndex = argNameIndex = 0

		arg_list = [self.strip_chars(a) for a in arg_list] # clean unneeded characters

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

	def get_function_return_type(self, functionName):
		if functionName in self.functionOutputs:
			return self.functionOutputs[functionName]
		else:
			print('[i] We don\'t know the return type for {}, fix this manually.'.format(functionName))
			return 'UNKNOWN'

	def get_function_arguments(self, functionName):
		if functionName in self.functionOutputs:
			argString = ""
			for arg in self.functionArgs[functionName]:
				if argString:
					argString += ", "
				argString += "{}: {}".format(arg[1], arg[0])
			return argString
		else:
			print('[i] We don\'t know the arguments for {}, fix this manually.'.format(functionName))
			return 'UNKNOWN_ARG: UNKNOWN_TYPE'

	def read_required_functions_from_file(self):
		try:
			with open(self.functionsInName, mode='r') as functionsIn:
				self.functions = ['Nt'+f[2:] if f[:2] == 'Zw' else f for f in [l.strip() for l in functionsIn.readlines()]]
				self.filterFunctions = len(self.functions) and "*" not in self.functions
				print('[i] Function filter file "{}" contains {} functions.'.format(self.functionsInName,len(self.functions)))
		except:
			print('[i] Function filter file "{}" not found. So not filtering functions.'.format(self.functionsInName))

	def generate_function_args_mapping(self):
		try:
			with open(self.structsFileInName, mode='r') as structsIn:
				inFunction = False
				currentFunction = ''
				currentFunctionArgs = []
				for f in [l.strip() for l in structsIn.readlines()]:
					if f.startswith("EXTERN_C"):
						functionName = currentFunction = f.split()[2].split("(")[0]
						if functionName in self.functions:			
							inFunction = True
							self.functionOutputs[functionName] = f.split()[1]
							if f.endswith(");"):
								inFunction = False
								self.functionArgs[currentFunction] = []
					elif inFunction:
						arg = f.split()
						if len(arg) > 0:
							argType, argName = self.parse_function_arg(arg)
							currentFunctionArgs.append([argName, argType])
						if arg[-1].endswith(");"):
							inFunction = False
							self.functionArgs[currentFunction] = currentFunctionArgs
							currentFunctionArgs = []					
			print('[i] Found return types for {} functions.'.format(len(self.functionOutputs)))
			
			if self.debug:
				pprint(self.functionArgs)
		except:
			print('[i] Functions and Structs file "{}" not found. We need this to get return types and args. Exiting...'.format(self.structsFileInName))
			exit()

	def write_inline_assembly_to_file(self):
		filterThisFunction = False
		with open(self.fileInName, mode='r') as fileIn:
			lines = fileIn.readlines()
			lines.pop(0)	#remove .code line
			
			out = '{.passC:"-masm=intel".}\n\n'

			if self.randomise:
				for function in self.functions:
					out += "# {} -> {}\n".format(function, self.function_map[function])

			inFunction = False
			currentFunction = ""
			for line in lines:
				if inFunction:
					if self.regexFunctionEnd.match(line):
						inFunction = False
						out += '' if filterThisFunction else '    \"\"\"'+'\n'
					elif not filterThisFunction:
						mhex = self.regexHexNotation.match(line)
						if mhex:
							out += mhex[1]+'0x'+mhex[2]+mhex[3]+'\n'
						else:
							out += re.sub(currentFunction, self.function_map[currentFunction], self.regexAsmComment.match(line)[1])+'\n'
				else:
					mstart = self.regexFunctionStart.match(line)
					if mstart:
						inFunction = True
						currentFunction = mstart[1]
						filterThisFunction = self.filterFunctions and not(mstart[1] in self.functions)
						out += '' if filterThisFunction else 'proc '+ self.function_map[mstart[1]] + '*(' + self.get_function_arguments(mstart[1]) + ')' +': '+ self.get_function_return_type(mstart[1]) + ' {.asmNoStackFrame.} ='+'\n'
						out += '' if filterThisFunction else '    asm \"\"\"\n'
					elif not filterThisFunction:
						out += '\n'
			
			with open(self.fileOutName, mode='w') as fileOut:
				fileOut.write(out)
				fileOut.close()
				print("[+] Success! Outputted to {}".format(self.fileOutName))

if __name__ == "__main__":

	parser = argparse.ArgumentParser(description="Convert SysWhispers output to Nim inline assembly.")
	parser.add_argument('--debug', action='store_true', help="Print mapped functions JSON")
	parser.add_argument('--randomise', action='store_true', help="Randomise the NT function names")

	args = parser.parse_args()

	nw = NimlineWhispers(args.debug, args.randomise)
	nw.write_inline_assembly_to_file()