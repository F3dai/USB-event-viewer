import os
import re
from datetime import datetime
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import ctypes, sys # for admin stuff
import smtplib, ssl # for email
import configparser # for importing settings

dumpFilename = 'evtxDump.xml'
configurationFile = 'usb.conf'
globalTime = datetime.now().strftime("%Y%m%d %H%M%S")

## Check Admin Rights ##

def is_admin():
	'''
	Function to check if the program is being run as admin or not
	'''
	try:
		return ctypes.windll.shell32.IsUserAnAdmin()
	except:
		return False

## Check Run Setting ##

def is_run():
	runScript = config.get('general', 'runScript')
	return runScript

## Check Email Notify Setting ##

def is_notify():
	notify = config.get('email', 'notify')
	
	if notify == 'on':
		notifyStatus = True
		
	else:
		notifyStatus = False
		logError('did not notify as setting is turned off...')

	return notifyStatus

## Import Settings ##

def import_settings():
	# Create global variables #
	global logDir, evtxLog, dumpDir, config
	
	config = configparser.ConfigParser()
	config.read(configurationFile)
	
	logDir = config.get('general', 'logDir')
	evtxLog = config.get('general', 'evtxLog')
	dumpDir = config.get('general', 'dumpDir')

## Convert evtx to xml ##

def evtxDumpFunc(evtxPath,xmlPath):
		# Function to convert an input .evtx file into an xml file #
		with open(xmlPath,'w') as xmlFile:
			with evtx.Evtx(evtxPath) as log:
				xmlFile.write(e_views.XML_HEADER)
				xmlFile.write("<Events>")
				for record in log.records():
					xmlFile.write(record.xml())
					xmlFile.write("</Events>")

def convert(directory):
	# Check if files exist #
	if os.path.exists(dumpDir) == False:
		print('\n[-] {} not detected, creating directory...'.format(dumpDir))
		os.mkdir(dumpDir)
		print('[+] Done. Commencing...')
		writeLog(getTime('unique') + ' [+] Created ' + dumpDir + '. Commencing...\n')
	else:
		print('\n[+] {} exists. Commencing...'.format(dumpDir))
		writeLog('{} [+] {} exists. Commencing...\n'.format(getTime('unique'), dumpDir))
	try:
		os.remove(dumpDir + dumpFilename) # Delete xml file
		print('\n[-] Removed: {}'.format(dumpFilename))
		writeLog(getTime('unique') + ' [-] Removed: {}\n'.format(dumpFilename))
	except:
		print('\n[+] {} does not exist. Commencing...'.format(dumpFilename))
		writeLog(getTime('unique') + ' [+] {} does not exist. Commencing...\n'.format(dumpFilename))
	
	# Start converting #
	
	print('\n[!] Converting: ' + evtxLog )
	writeLog('{} [!] Converting to xml: {}\n'.format(getTime('unique'), evtxLog))
	evtxDumpFunc(logDir+evtxLog,dumpDir+dumpFilename) # Conversion command
	print('[+] Done: ' + dumpFilename)
	writeLog('{} [+] Done converting! Output file: {}\n'.format(getTime('unique'), dumpFilename))
	
	return dumpFilename # Analyse and regex the log file

## Sanitise log file ##

def sanitise(xml):
		
	eventIdentifiers = [] 
	USBinstances = [] # Initialise empty array
	tmpDict = {} # Initialise empty dictionary
	
	print("\n[!] Sanitising...")
	
	# open files for reading and writing:
	with open(dumpDir + xml, 'r') as inputXmlFile: #, open(dumpDir + 'usb_raw.log', 'w+') as rawOutputFile: 
			
			deviceName = computerName = eventType = deviceMake = eventType = hostGuid = guid = timeCreated = eventID = userData = "Null" 
			for line in inputXmlFile: # Scan through lines of log file
			
				# Set all variables to null in case it doesn't exist in event #
			
				
				
				if '<Event xmlns=' in line: # Identify start of event
					
					try:
						guid = re.search('Guid="(.+?)"></Provider>', line)
						guid = guid.group(1)
					except:
						writeLog('\n{} [-] GUID regex error: {}'.format(getTime('unique'), line)) # suk ya mum
						logError('[-] GUID regex error: ' + line)
						
				elif 'TimeCreated' in line:
					
					try:
						timeCreated = re.search('<TimeCreated SystemTime="(.+?)"></TimeCreated>',line)
						timeCreated = timeCreated.group(1)
					except:
						writeLog('\n{} [-] Time regex error : {}'.format(getTime('unique'), line)) # suk ya mum
						logError('[-] Time regex error:' + line)
				
				elif '<EventID Qualifiers="">' in line:
					
					eventID = re.search('Qualifiers=\"\">(.+)</EventID>', line)
					eventID = eventID.group(1)

					
					
					if eventID == '1003': # the Driver Manager service is starting a host process
						eventType = 'USB in'
						
					if eventID == '1006':
						eventType = 'USB out'
					
					else: eventType == 'Other'
								   
				elif '<UserData>' in line:
					try:
						userData = re.search('<LifetimeId>(.+?)</LifetimeId>',line)
						userData = userData.group(1)

					except:
						writeLog('\n{} [-] UserData regex error: {}'.format(getTime('unique'), line)) # suk ya mum
						logError('[-] UserData regex error:' + line)
						
				elif 'HostGuid' in line:
					try:
						hostGuid = re.search('<HostGuid>(.+?)</HostGuid>',line)
						hostGuid = hostGuid.group(1)
					except:
						writeLog('\n{} [-] Host GUID regex error: {}'.format(getTime('unique'), line)) # suk ya mum
						logError('[-] Host GUID regex error' + line)
						
				elif 'InstanceId' in line:
					
					try:
						
						deviceMake = re.search('{(.+?)}',line)
						deviceMake = '{' + deviceMake.group(1) + '}'
					except:
						writeLog('\n{} [-] Device Make regex error: {}'.format(getTime('unique'), line)) # suk ya mum						
						logError('[-] Device Make regex error' + line)
						
					try:
						deviceName = re.search('#DISK&amp;(.+?)&amp;', line)
						deviceName = deviceName.group(1)
					except:
						writeLog('\n{} [-] Device Name regex error: {}'.format(getTime('unique'), line)) # suk ya mum						
						logError('[-] Device Name regex error' + line)
						
						
				elif '<Computer>' in line:
					
					try:
						computerName = re.search('<Computer>(.+?)<\/Computer>')
						computerName = computerName.group(1)
					except:
						writeLog('\n{} [-] Computer Name regex error: {}'.format(getTime('unique'), line)) # suk ya mum
						logError('[-] Computer Name regex error:' + line)
						
						
				elif '</Event>' in line:
					
					
					# Save as much data as possible
					tmpDict = {
						"Device Name" : deviceName,
						"Time" : timeCreated, 
						"Computer Name" : computerName,
						"Event ID" : eventID,
						"Status" : eventType,
						"USB Serial Number" : userData, 
						"Host GuID" : hostGuid, 
						"Device Make" : deviceMake, 
						"GuID" : guid, 
						
						 }
					
					writeLog(getTime('unique') + " [+] Found Event:\n Device Name: {}\n Time: {}\n Win Event ID: {}\n Status: {}\n USB  Serial Number: {}\n Host GuID: {}\n Device Make: {}\n GuID: {}\n Computer Name: {}\n".format(deviceName, timeCreated, eventID, eventType, userData, hostGuid, deviceMake, guid, computerName))

					USBinstances.append(tmpDict)
	
	print("[+] Done! Saved to:", logDir + xml)
	writeLog('\n{} [+] Done! Saved to: {}{}\n'.format(getTime('unique'), logDir, xml))
	return USBinstances

## Remove xml files ##

def clear(directory):
	for file in directory:
		if file.endswith(".evtx") == False:
			os.remove(logDir + file)
			print("[!] Removed: " + file)
			writeLog(getTime('unique') + ' [!] Removed file: ' + file)

## Display and write events ##

def showEvents(events):
	# Output single instances
	readableFilename = 'viewUSB.log'
	
	writeLog('{} [+] Displaying and writing for all events found. Writing files to: {}\n'.format(getTime('unique'), readableFilename))
	
	instaces = [] # Initiate empty array for single instances
	
	with open(dumpDir + readableFilename, 'w+') as readableLogFile:
			
			count = 1 # Event Counter
			
			for event in events: 
				
				if event['Status'] == "USB in" or event['Status'] == "USB out": # Only display in and out instances

					print('\n## EVENT {} ##\n'.format(count))
					writeLog('{} [+] Found single deduped event: {} \n'.format(getTime('unique'), count))
					readableLogFile.write('\n## EVENT {} ##\n\n'.format(count))

					maximumCount = 5 # Maximum fields to display
					instaces.append(event)
					for key, value in event.items():
						
						if maximumCount == 0:
							break

						readableLogFile.write('{} : {} \n'.format(key, value))
						print('{} : {} '.format(key, value))
						#writeLog('{} : {} '.format(key, value))
						
						maximumCount -= 1
					writeLog('{} [+] Written event to: {}\n'.format(getTime('unique'), dumpDir + readableFilename))
					count += 1
			
	
	return instaces				

## Check Authorised Devices ##

def checkAuthorised(USBinstaces):

	authUSBlist = config.get('authorised devices', 'authorised')
	
	unauthList = [] # Initialise array for unauthorised instances

	for event in USBinstaces:
		authSerial = event['USB Serial Number'][1:-1]
		
		if authSerial not in authUSBlist:
			unauthList.append(event)
			
	return unauthList

## Notify unauthorised events by email ##	

def notifyEmail(unauthList):
	
	sender_id = config.get('email', 'sender')
	sender_pass = config.get('email', 'password')
	receiver_id = config.get('email', 'receiver')
	
	message = '''
	From: USB Notify <{}>
	To: <{}>
	Subject: Unauthorised USB detected
	
	{} unauthorised USB instance(s) has been detected.
	
	Information regarding the instance(s):'''.format(sender_id, receiver_id, len(unauthList))
	
	
	for items in unauthList:
		
	
		messageAddition = '''
		
		Device Name: {}
		Time: {}
		Event ID: {}
		Status: {}
		USB Serial Number: {}
		Host GuID: {}
		Make: {}
		GuID: {}'''.format(items['Device Name'], items['Time'], items['Event ID'], items['Status'], items['USB Serial Number'], items['Host GuID'], items['Device Make'], items['GuID'])
		
		message = message + messageAddition
	# Exception Handling #
	try:
		writeLog(getTime('unique') + ' [+] Preparing email with given credentials...\n')
		smtpobj = smtplib.SMTP(config.get('email', 'smtp'), config.get('email', 'port'))
		writeLog(getTime('unique') + ' [+] Start TLS...\n')
		smtpobj.starttls()
		writeLog(getTime('unique') + ' [+] Authenticating email account...\n')
		smtpobj.login(sender_id, sender_pass)
		writeLog(getTime('unique') + ' [+] Sending email...\n')
		smtpobj.sendmail(sender_id,receiver_id, message)
		smtpobj.quit()
		
	except:
		print('\n[!] And error occured, please check', configurationFile)
		writeLog(getTime('unique') + ' [!] Error sending email. Check most recent log message to understand why. Nothing was sent.\n')
		logError('[!] Error sending email. Nothing was sent. Check specific log for more information')
		smtpobj.quit()
		quit()
	
	print('[+] Email Sent!')
	writeLog(getTime('unique') + ' [+] Email sent to: ' + sender_id)
	
## Create Log ##

def writeLog(logMessage):
	# globalTime = global script time
	# currentTime = time right now
	with open(dumpDir + getTime('global') + ' - USBscan.log', 'a+') as logUSB:
		logUSB.write(logMessage)
		

## Log errors ##

def logError(errorMessage):
	currentTime = getTime('unique')
	with open(dumpDir + 'error.log', 'a+') as logError:
		logError.write('\n' + currentTime + ' - ' + errorMessage)

## Get Current Time

def getTime(format):
	if format == 'global': # Format for filenames
		currentTime = globalTime
	elif format == 'unique': # Format for inside logs
		currentTime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	return currentTime

## Main Function ##

def main():
	logTime = getTime('global')
	dumpXml = convert(logDir + evtxLog) # Convert and get xml file
	USBinstaces = sanitise(dumpXml) # Find all events
	
	print()
	
	lessUSBinstaces = showEvents(USBinstaces)
	
	unauthList = checkAuthorised(lessUSBinstaces)
	
	
	if unauthList and is_notify():
		notifyEmail(unauthList)
	
	writeLog('\n{} [+] All done. Stopping script...'.format(getTime('unique')))

if __name__ == "__main__":
	import_settings()
	if is_admin():
		if is_run(): # If script is enabled in config
			main()
		else:
			logError('[!] Running script is disabled in ' + configurationFile)
	else:
		logError('[!] Error starting script as Admin')
		
