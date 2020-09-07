import os
import re
from datetime import datetime
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import ctypes, sys # for admin stuff
import smtplib, ssl # for email
import configparser # for importing settings

# Fix All getTime things. I'm getting confused with the variables and the function.
# You will need to go through and change them ALL
# 

dumpFilename = 'evtxDump.xml'

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
	print(config)
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
	config.read('usb.conf')
	
	logDir = config.get('general', 'logDir')
	evtxLog = config.get('general', 'evtxLog')
	dumpDir = config.get('general', 'dumpDir')

## Convert evtx to xml ##

def evtxDumpFunc(evtxPath,xmlPath):
		
		# Function to convert an input .evtx file into an xml file
		
		with open(xmlPath,'w') as xmlFile:
			with evtx.Evtx(evtxPath) as log:
				xmlFile.write(e_views.XML_HEADER)
				xmlFile.write("<Events>")
				for record in log.records():
					xmlFile.write(record.xml())
					xmlFile.write("</Events>")


def convert(directory):
	if os.path.exists(dumpDir) == False:
		print('\n[-] {} not detected, creating directory...'.format(dumpDir))
		writeLog(getTime('unique') + ' [!] {} not detected, creating directory...'.format(dumpDir))
		os.mkdir(dumpDir)
		print('[+] Done. Commencing...')
		writeLog(getTime('unique') + ' [+] Done. Commencing...')
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
	
	print()
	
	print('[!] Converting: ' + evtxLog )
	writeLog('{} [!] Converting to xml: {}'.format(getTime('unique'), evtxLog))
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
			for line in inputXmlFile: # Scan through lines of log file
				if '<Event xmlns=' in line: # Identify start of event
					try:
						guid = re.search('Guid="(.+?)"></Provider>', line)
						guid = guid.group(1)
					except:
						writeLog(getTime('unique') + ' [-] GUID ERROR: ' + line) # suk ya mum
						logError('GUID ERROR: ' + line)
						
				elif 'TimeCreated' in line:
					try:
						timeCreated = re.search('<TimeCreated SystemTime="(.+?)"></TimeCreated>',line)
						timeCreated = timeCreated.group(1)
					except:
						writeLog(getTime('unique') + ' [-] USER DATA ERROR:' + line) # suk ya mum
						logError('USER DATA ERROR:' + line)
				
				elif '<EventID Qualifiers="">' in line:
					

					eventID = re.search('Qualifiers=\"\">(.+)</EventID>', line)
					eventID = eventID.group(1)

					eventType = 'Null' # Default

					if eventID == '1003': # the Driver Manager service is starting a host process
						eventType = 'USB in'
						
					if eventID == '1006':
						eventType = 'USB out'
								   
				elif '<UserData>' in line:
					try:
						userData = re.search('<LifetimeId>(.+?)</LifetimeId>',line)
						userData = userData.group(1)

					except:
						writeLog(getTime('unique') + ' [-] USER DATA ERROR:' + line) # suk ya mum
						logError('USER DATA ERROR:' + line)
						
				elif 'HostGuid' in line:
					try:
						hostGuid = re.search('<HostGuid>(.+?)</HostGuid>',line)
						hostGuid = hostGuid.group(1)
					except:
						writeLog(getTime('unique') + ' [-] HOST GUID ERROR:' + line) # suk ya mum
						logError('HOST GUID ERROR:' + line)
						
				elif '<DeviceInstanceId>' in line:
					try:
						deviceMake = re.search('{(.+?)}',line)
						deviceMake = '{' + deviceMake.group(1) + '}'
						deviceName = re.search('#DISK&amp;(.+?)&amp;', line)
						deviceName = deviceName.group(1)
					except:
						writeLog(getTime('unique') + ' [-] DEVICE MAKE ERROR:' + line)
						deviceName = "Null" # If there isn't device name in event?
						logError('DEVICE MAKE ERROR:' + line)
				
				
				elif '</Event>' in line:
					
					# Save as much data as possible
					tmpDict = {
						"Device Name" : deviceName,
						"Time" : timeCreated, 
						"Event ID" : eventID,
						"Status" : eventType,
						"USB Serial Number" : userData, 
						"Host GuID" : hostGuid, 
						"Device Make" : deviceMake, 
						"GuID" : guid, 
						
						 }
					#rawOutputFile.write(("Device Name: {}\nTime: {}\nEvent ID: {}\nStatus: {}\nUSB Serial Number: {}\nHost GuID: {}\nMake: {}\nGuID: {}\n\n").format(guid, timeCreated, userData, hostGuid, deviceMake, deviceName, eventID, eventType))
					
					writeLog(getTime('unique') + " [+] Found Event:\n Device Name: {}\n Time: {}\n Event ID: {}\n Status: {}\n USB  Serial Number: {}\n Host GuID: {}\n Make: {}\n GuID: {}\n".format(guid, timeCreated, userData, hostGuid, deviceMake, deviceName, eventID, eventType))

					USBinstances.append(tmpDict)
	
	print("[+] Done! Saved to:", logDir + xml)
	writeLog('{} [+] Done! Saved to: {}{}\n'.format(getTime('unique'), logDir, xml))
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
	readableFilename = 'usb_view.log'
	
	writeLog('{} [+] Displaying and writing for all events found. Writing files to: {}\n'.format(getTime('unique'), readableFilename))
	
	instaces = [] # Initiate empty array for single instances
	
	with open(dumpDir + readableFilename, 'w+') as readableLogFile:
			
			count = 1 # Event Counter
			
			for event in events: 
				
				if event['Status'] == "USB in" or event['Status'] == "USB out": # Only display in and out instances

					print('\n## EVENT {} ##\n'.format(count))
					writeLog('{} [+] Found single deduped event: {} '.format(getTime('unique'), count))
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
	
	smtpobj = smtplib.SMTP(config.get('email', 'smtp'), config.get('email', 'port'))
	
	smtpobj.starttls()
	
	smtpobj.login(sender_id, sender_pass)
	
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
	try:
		smtpobj.sendmail(sender_id,receiver_id, message)
		smtpobj.quit()
		print('[+] Email Sent.')
		writeLog(logTime('unique') + ' [+] Email sent to: ' + sender_id)
	except:
		print('Error sending email. Check configuration and internet connection.')
		writeLog(getTime('unique') + ' [!] Error sending email. Check configuration and internet connection.')
		logError('Error sending email. Check configuration and internet connection.')

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
		currentTime = datetime.now().strftime("%Y%m%d %H%M%S")
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
		notifyEmail(logTime, unauthList)


if __name__ == "__main__":
	import_settings()
	if is_admin():
		if is_run(): # If script is enabled in config
			main()
		else:
			logError('running script is disabled in usb.conf')
	else:
		logError('error starting script as Admin')
		
