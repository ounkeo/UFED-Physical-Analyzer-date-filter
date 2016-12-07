# -*- coding: utf-8 -*-

# Cellebrite Physical Analyzer (PA) date and time filter script
# Wansin Ounkeo 2016-5-22
# Tested: PA 5.02, internal IronPython 2.6 shell, Win7x64 4GB RAM

# This script filters for all data (including deleted data) that 
# fall within a user-specified date range.

# By default, the script does NOT apply your date filter to deleted 
# items thereby giving you more data including ones with bad timestamps.
# You may optionally apply your date filter to deleted items which
# will give you less data.
# A log is saved to 'Logs' folder in Physical Analyzer install folder.

# This script was made in response to SB178 (California Senate Bill 178)
# "California Electronic Communication Privacy Act" to address
# lack of automatic date filtering in UFED Physical Analyzer 5.02. 
# California's SB178 in 2016 requires all search warrants to
# specify a time period to search for electronically stored communications.
# Any data not in the warrant time frame should be excluded.
# Forensic examiners in California currently have to manually filter that 
# data and the process is relatively slow and is error-prone. 
# This script eases that.

# PA by default, auto checks all items after processing which is found in
# ds.TaggedFiles. This script relies on the checked files to work correctly.

# TODO: the top level categories of data are updated in the GUI but the 
# secondary categories are not updated. 

# In the Python shell, ds.Models shows unique data only. 
# The UFED PA GUI shows duplicate counts (in parenthesis).

# changelog 2016-11-21  PA 5.4 changed internal data structures. It uses ds.DataFiles instead of ds.TaggedFiles
#						Update script for the change.

# changelog 2016-06-26	Add DeviceInfo timestamp checks with UTC-0 default.
# changelog 2016-06-23  Remove 'ActiveTime' timestamp. It is like 'Duration' - not a timestamp.
# changelog 2016-06-23	ApplicationUsage has LastLaunch timestamps with mix of values showing 
# 						UTC offset and no UTC offset. Treat the no UTC offset timestamps as UTC time.

# Include below for PA script. But don't include it in the 
# python shell or it will hide 'ds' - the DataStore 
# This needs to be first or else namespace collisions will occur with
# clr library (e.g. Label)
from physical import *

from datetime import datetime
import re
import clr
clr.AddReference ('System.Windows.Forms')
from System.Windows.Forms import MessageBox, Application, Button, Form, \
									Label, TextBox, CheckBox
from System.Drawing import Point


# GLOBAL VARIABLES 
# Python 101: Locally-scoped variables (in fuctions, etc) with these 
# names must use the 'global' keyword for you to be able to assign values
# to them in the global context.

# Should we filter deleted data by the user-specified date range?
# Deleted data can show bad date/time values so times cannot be relied upon.
# By default, this script will not filter deleted data by date range. 
# If you filter deleted items by daterange, it will exclude deleted data with bad dates.
doNotDateFilterDeleted = True

# Should we filter Contacts by LastContacted date?
# Default is to not filter by LastContacted
doNotFilterContact_by_LastContacted = True

# date ranges using tz offset -7 or -8 for PST or PDT
date_start = "2015-02-20 00:00:00-8"
date_end = "2015-02-20 23:59:59-8"

dt_start = TimeStamp(System.Convert.ToDateTime(date_start), True)
dt_end = TimeStamp(System.Convert.ToDateTime(date_end), True)
# output will be in format 12/25/2014 11:59:59 PM (UTC-8)

# These globals are toggled depending on the time stamps
global_all_timestamps_None = True
global_inside_timeframe  = False
keep = False
nRemoved = 0
log = ''

# used to track current file for debugging purposes
currentFile = ''

def debug(string, errtype):
	try:
		log.write(string.encode('utf8')+"\n")
	except Exception as e:
		print "exception in debug"
		print (errtype, e)


# function that does actual date comparison
def withinRange(timestamp):
	global global_all_timestamps_None
	global global_inside_timeframe
	
	# since we are testing a timeframe, at least 1 timestamp is not None 
	global_all_timestamps_None = False

	if timestamp >= dt_start and timestamp <= dt_end :
		global_inside_timeframe = True
		return True
	else:
		return False

		
# Parses Data Files	
# ds.TaggedFiles only contains Data Files. Not any Analyzed Data items.
# ds.TaggedFiles[cateogry.Name] includes deduplicated items 
def containsTimeStamp_DataFiles(f) :
	''' Parse PA Data Files only
	'''
	global global_all_timestamps_None
	global global_inside_timeframe
	global keep
	global log
	
	global_all_timestamps_None = True
	global_inside_timeframe  = False
	keep = False
	msg = ''
	
	try:
		# Node / file  Properties
		if f.Deleted is not None:
			if doNotDateFilterDeleted is True and (str(f.Deleted) == "Deleted"):
				keep = True
				msg = "\t\tKeeping deleted Data File "+str(f.Name)
				return True
				
		if f.CreationTime is not None:
			if withinRange(f.CreationTime):
				msg += "\t\tCreationTime: "+str(f.CreationTime)+" - within range\n"
				pass
			else:
				msg += "\t\tCreationTime: "+str(f.CreationTime)+" outside range\n"
				
		if f.ModifyTime is not None:
			if withinRange(f.ModifyTime):	
				msg += "\t\tModifyTime: "+str(f.ModifyTime)+" within range\n"
				pass
			else:
				msg += "\t\tModifyTime: "+str(f.ModifyTime)+" outside range\n"

		if f.AccessTime is not None:
			if withinRange(f.AccessTime):	
				msg += "\t\tAccessTime: "+str(f.AccessTime)+" within range\n"
				pass
			else:
				msg += "\t\tAccessTime: "+str(f.AccessTime)+" outside range\n"
				
		if f.DeletedTime is not None:
			if withinRange(f.DeletedTime):
				msg += "\t\tDeletedTime: "+str(f.DeletedTime)+" within range\n"
				pass
			else:
				msg += "\t\tDeletedTime: "+str(f.DeletedTime)+" outside range\n"

		
		try:
			if f.MetaData is not None:
				for mdf in f.MetaData:
					if mdf.Name == 'EXIFCaptureTime' and mdf.Value is not None:	
						capturetime = mdf.Value.strip()
						capturetime = capturetime.replace("T", " ")
						date, time, meridiem = capturetime.split(' ')
						mm, dd, yyyy = date.split('/')
						hr, mn, sec = time.split(':')
						
						old_hr = hr
						if meridiem == 'PM' and int(hr) != 12:
							hr = int(hr)+12
							
						if meridiem == 'AM' and int(hr) == 12:
							hr = '00'
						t_str = yyyy+'-'+mm+'-'+dd+' '+str(hr)+':'+mn+':'+sec
						
						ts = TimeStamp(System.Convert.ToDateTime(t_str))
						
						if withinRange(ts):
							
							msg += "\t\tEXIFCaptureTime: "+str(ts)+" within range\n"
						else:
							msg += "\t\tEXIFCaptureTime: "+str(ts)+" outside range\n"
						
					
					if mdf.Name == 'DateTime' and mdf.Value is not None:
						date_time = mdf.Value.strip()
						date_time = date_time.replace("T", " ")
						date, time = date_time.split(' ')
						
						if date[4] == ':':
							yyyy, mm, dd = date.split(':')
						elif date[4] == '-':
							yyyy, mm, dd = date.split('-')
							
						utc_offset = time[8:]
						time = time[:8]
						hr, mn, sec = time.split(':')
						# Some times will be '24:44:06' but should be 0:44:26 (localtime)
						# or 7:44:36 AM(UTC+0) (EXIF DateTime are usually stored as local time)
						hr = hr.replace("24", "0")
						t_str = yyyy+'-'+mm+'-'+dd+' '+str(hr)+':'+mn+':'+sec+utc_offset
						ts = TimeStamp(System.Convert.ToDateTime(t_str))
						if withinRange(ts):
							msg += "\t\tCaptureTime: "+str(ts)+" within range\n"
						else:
							msg += "\t\tCaptureTime: "+str(ts)+" outside range\n"
		except Exception as e:
			msg = "Error EXIFCaptureTime "+str(e)
			print (currentFile.encode('utf8')+":"+msg)
			debug(msg, 'EXIFCaptureTime error')
		
		if global_inside_timeframe is True:
			keep = True
		if global_all_timestamps_None is True:
			keep = True
		debug(msg, 'DataFiles Processing error writing log')
	except Exception as e:
		msg = "containsTimeStamp_DataFiles() Processing Error: "+str(e)
		print(msg)
		debug(msg, 'containsTimeStamp_DataFiles() Processing error writing log')
	return keep	
	

	
# Filters Data Files by dates and clears non-matches
def filter_DataFiles():
	global nRemoved
	global currentFile
	tagslisttoClear = []
	msg = ''
	
	msg2 = "Date range start="+str(dt_start)+" end="+str(dt_end)
	print (msg2)
	for category in ds.TaggedFiles:
		msg1 = "\n***********************************\n"
		msg1 += "Processing "+category.Name
		print(msg1)

		debug(msg1+"\n", "error writing data files log")
		filenum = 1
		cn = str(category.Name)
		cnlist = cn.split('.')
		name = cnlist[-1]
		for f in list(ds.TaggedFiles[category.Name]):
			msg = "\n"+name+" "+str(filenum)+": "
			
			# fixed runtime error with malformed names

			
			if f.Name is not None:
				try:
					if f.Name.isunicode:
						ustr = f.Name.encode('utf-8', 'ignore')
						msg += ustr
						currentFile = ustr
					else:
						msg += str(f.Name)
						currentFile = str(f.Name)
				except UnicodeEncodeError as e:
					msg += "UnicodeEncodeError: bad filename"
			
			debug(msg, "Data Files processing error writing log")

				
			if (containsTimeStamp_DataFiles(f)):
				msg = "\t\tKeeping"
				pass
			else:
				tagslisttoClear.append(f)
				msg = "\t\tRemoving"
			#print(msg)
			debug(msg, "Error writing log data files")
			filenum += 1
			currentFile = ''
		msg = str(name)+'(s) Processed: '+str(filenum-1)
		print(msg)
		debug(msg, 'Data Files finish category error writing log')
	
	# Remove data files from PA list
	nRemoved = len(tagslisttoClear)
	for f in tagslisttoClear:
		f.Tags.Clear()
		
	print "\n***********************************"
	msg = "Data Files removed = "+str(nRemoved)
	print (msg)
	debug(msg, 'Error writing log Data Files removed')
	return nRemoved

def filter_DataFiles_v5_4():
	global nRemoved
	global currentFile
	tagslisttoClear = []
	msg = ''
	
	msg2 = "Date range start="+str(dt_start)+" end="+str(dt_end)
	print (msg2)
	for category in ds.DataFiles:
		msg1 = "\n***********************************\n"
		msg1 += "Processing "+category.Key
		print(msg1)

		debug(msg1+"\n", "error writing data files log")
		filenum = 1
		cn = str(category.Key)
		cnlist = cn.split('.')
		name = cnlist[-1]
		for f in list(ds.DataFiles[category.Key]):
			msg = "\n"+name+" "+str(filenum)+": "
			
			# fixed runtime error with malformed names

			
			if f.Name is not None:
				try:
					if f.Name.isunicode:
						ustr = f.Name.encode('utf-8', 'ignore')
						msg += ustr
						currentFile = ustr
					else:
						msg += str(f.Name)
						currentFile = str(f.Name)
				except UnicodeEncodeError as e:
					msg += "UnicodeEncodeError: bad filename"
			
			debug(msg, "Data Files processing error writing log")

				
			if (containsTimeStamp_DataFiles(f)):
				msg = "\t\tKeeping"
				pass
			else:
				tagslisttoClear.append(f)
				msg = "\t\tRemoving"
			#print(msg)
			debug(msg, "Error writing log data files")
			filenum += 1
			currentFile = ''
		msg = str(name)+'(s) Processed: '+str(filenum-1)
		print(msg)
		debug(msg, 'Data Files finish category error writing log')
	
	# Remove data files from PA list
	nRemoved = len(tagslisttoClear)
	for f in tagslisttoClear:
		f.Tags.Clear()
		
	print "\n***********************************"
	msg = "Data Files removed = "+str(nRemoved)
	print (msg)
	debug(msg, 'Error writing log Data Files removed')
	return nRemoved
	
def reset_globals():
	global global_all_timestamps_None
	global global_inside_timeframe
	global keep
	global nRemoved
	global_all_timestamps_None = True
	global_inside_timeframe  = False
	keep = False
	nRemoved = 0

def filter_AnalyzedData2():
	"""
	Parse Analyzed Data v2. Shorter version. 
	
	This version will handle Data.Models that are not explicitly 
	named but that have recognized timestamps.
	
	Some subcategories will not be updated in GUI.
	But the reports should show updated data.
	"""
	listtoClear = []
	chats_Messages_listtoClear = []
	global keep
	global log
	msg = ''

	# 35 TimeStamps. Duration removed. AllTimeStamps may need review.
	timefields = [
				'TimeContacted', 
				'TimeCreated', 
				'TimeModified',
				'TimeLastLoggedIn',
				'DateDelivered',
				'DateRead',
				'DatePlayed',
				'TimeStamp',
				'AllTimeStamps',
				'StartTime',
				'LastActivity',
				'Creation',
				'Modification',
				'StartDate',
				'EndDate',
				'Reminder',
				'RepeatUntil',
				'EndTime',
				'Expiry',
				'CreationTime',
				'LastAccessTime',
				'LastVisited',
				'LastConnected',
				'LastConnection',
				'LastAutoConnection',
				'PurchaseDate',
				'DeletedDate',
				'Date',
				'LastLaunch',
				'PurchaseTime',
				'ModifyTime',
				'ActivationTime',
				'ExpirationTime',
				]
	
	if doNotFilterContact_by_LastContacted is True:
		# Assumption: TimeContacted timestamp is only used by Contacts.
		# Currently this is true. If other categories use the TimeContacted timestamp,
		# this will prevent those categories from being date filtered properly. 
		timefields.remove('TimeContacted')
		
	
	# For all models
	for m in list(ds.Models):
		msg1 = "\n***********************************\n"
		msg1 += "Processing "+str(m.ModelType)
		msg2 = "\tdaterange start: "+str(dt_start)+" end: "+str(dt_end)
		msg2 += "\n***********************************\n"
		msg = msg1+"\n"+msg2
		debug(msg, "Data Models Error writing log")
		reset_globals()

		filenum = 1
		cn = str(m.ModelType)
		cnlist = cn.split('.')
		mtype = cnlist[-1]
		
		# For all data of a model type
		for f in ds.Models[m.ModelType]:
			msg = "\t"+str(mtype)+" File "+str(filenum)
			debug(msg, "Processing Models - error writing log")
			#if f == Data.Models.Chat:
			if f.FieldExists('Messages'):
				im_num = 1
				for im in f.Messages:
					msg = "\t\tChat IM "+str(im_num)+"\n"
					try:
						if im.FieldExists('TimeStamp') and withinRange(im.TimeStamp.Value):
							msg += "\t\t\t"+str(im.TimeStamp)+" within"
							pass
						if im.FieldExists('StartTime') and withinRange(im.StartTime.Value):
							msg += "\t\t\t"+str(im.StartTime)+" within"
							pass
						if im.FieldExists('DateDelivered') and withinRange(im.DateDelivered.Value):
							msg += "\t\t\t"+str(im.DateDelivered)+" within"
							pass
						if im.FieldExists('DateRead') and withinRange(im.DateRead.Value):
							msg += "\t\t\t"+str(im.DateRead)+" within"
							pass
						if im.FieldExists('DatePlayed') and withinRange(im.DatePlayed.Value):
							msg += "\t\t\t"+str(im.DatePlayed)+" within"
							pass
						if im.FieldExists('Date') and withinRange(im.Date.Value):
							msg += "\t\t\t"+str(im.Date)+" within"
							pass
					except Exception as e:
						msg += "\tChat "+str(filenum)+" Instant Message "+str(im_num)+" Error: "+str(e)
						print(msg)
						debug(msg, "Chat IM error writing log")
												
					if f.Deleted is not None:
						if doNotDateFilterDeleted is True and str(im.Deleted) == "Deleted":
							msg += "\t\t\tKeeping Deleted: Chat IM "+str(im_num)
							print(msg)
							debug(msg, "Keeping Deleted Chat IM error writing log")
							keep = True
							break
					if global_inside_timeframe is True:
						keep = True
					if global_all_timestamps_None is True:
						# This means there were no timestamps or all timestamps were blank so we keep the item
						keep = True
					if keep is True:
						msg += "\t\t\tKeeping"
					else:
						chats_Messages_listtoClear.append(im)
						msg += "\t\t\tRemoving"
					debug(msg,"error writing log IM")
					reset_globals()
					im_num+=1

			# FieldExists('Deleted') does not work as expected
			# maybe because all Models are known to have a Deleted field?
			# if f.FieldExists('Deleted'):
			if f.Deleted is not None:
				if doNotDateFilterDeleted is True and (str(f.Deleted) == 'Deleted'):
					msg = "\t\tKeeping Deleted File "+str(filenum)
					#print msg
					debug(msg, 'Deleted analyzed data - error in writing log')
					keep = True
			
			msg = ''
			# scan through all possible timefield timestamps
			for tf in timefields:
				# AllTimeStamps gets special handling... Value.Value to get right type
				if tf is "AllTimeStamps" and f.FieldExists(tf):
					for ts in getattr(f, tf):
						if withinRange(ts.Value.Value):
							msg += "\t\tAllTimeStamp="+str(ts.Value.Value)+" within\n"
						else:
							msg += '\t\tAllTimeStamp='+str(ts.Value.Value)+" outside\n"
						debug(msg, "SMS AllTimeStamp error writing log")
			
				elif f.FieldExists(tf):
					try:
						ts_val = getattr(f, tf).Value
						if ts_val is not None:
							if withinRange(ts_val):
								msg += "\t\t"+str(tf)+":"+str(ts_val)+" within\n"
								pass
							else:
								msg += "\t\t"+str(tf)+":"+str(ts_val)+" outside\n"
					except Exception as e:
						msg = "File "+str(filenum)+" Timefield: "+str(tf)+" Error: "+str(e)
						print(msg)
						debug(msg, 'Analyzed Data Error writing log')

			if global_inside_timeframe is True:
				keep = True
			if global_all_timestamps_None is True:
				# There were no timestamps or all timestamps were blank
				keep = True
			if keep is True:
				msg += "\t\tKeeping\n"
			else:
				msg += "\t\tRemoving\n"
				listtoClear.append(f)
				
			#print(msg)
			debug(msg, "Keeping data error writing log")
			
			filenum += 1
			reset_globals()	

	
	global nRemoved
	nRemoved = len(listtoClear)+len(chats_Messages_listtoClear)
	
	msg1 = "Analyzed Data items removed = "+str(nRemoved)
	msg2 = "(Chats Instant Messages "+str(len(chats_Messages_listtoClear))+")"
	msg = msg1+" "+msg2
	print(msg)
	debug(msg, "Error writing log, total Analyzed Data removed")

	
	# Remove items from PA GUI
	for f in listtoClear:
			f.ModelCollection.Remove(f)
	for f in chats_Messages_listtoClear:
		f.ModelCollection.Remove(f)
	return nRemoved
		
		
# Filters all Analyzed Data. It will update the PA GUI.
# Old version of filter logic. This def is not called currently.
# It is still useful to see what timestamps are looked for in each category.
def filter_AnalyzedData():
	"""
	Parse Analyzed Data.
	
	Some subcategories will not be updated in GUI.
	But the HTML report will show updated data.
	UFDR report does not display the Call Logs.
	"""
	listtoClear = []
	chats_Messages_listtoClear = []
	global keep
	global log

	#print("filter_AnalyzedData() Timeframes:\t"+str(dt_start)+" through "+str(dt_end))	
	
	for m in list(ds.Models):
		l =  "Processing "+str(m.ModelType)
		debug(l, "Cannot write log to starting Analyzed Data")
		reset_globals()
		
		#Contact time data: Data.Models.ContactModels.Contact
		if m.ModelType == Data.Models.ContactModels.Contact:
			for f in ds.Models[m.ModelType]:
				#print("\tprocessing Contact "+str(f.Name))
				if f.TimeContacted.Value is not None:
					if withinRange(f.TimeContacted.Value):
						pass
				if f.TimeCreated.Value is not None:
					if withinRange(f.TimeCreated.Value):
						pass
				if f.TimeModified.Value is not None:
					if withinRange(f.TimeModified.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Contact "+str(f.Name))
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
				reset_globals()	
		
		# UserAccount time data: Data.Models.User
		if m.ModelType == Data.Models.User:
			for f in ds.Models[m.ModelType]:
				if f.TimeCreated.Value is not None:
					if withinRange(f.TimeCreated.Value):
						pass
				# extra timestamp not mentioned in the "Using the Python Shell.pdf".
				if f.TimeLastLoggedIn.Value is not None:
					if withinRange(f.TimeLastLoggedIn.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted:  UserAccount")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()			
	
		# Party time data: Data.Models.Party
		if m.ModelType == Data.Models.Party:
			for f in ds.Models[m.ModelType]:
				if f.DateDelivered.Value is not None:
					if withinRange(f.DateDelivered.Value):
						pass
				if f.DateRead.Value is not None:
					if withinRange(f.DateRead.Value):
						pass
				if f.DatePlayed.Value is not None:
					if withinRange(f.DatePlayed.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Party ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
	
		# SMS time data: Data.Models.SMS
		if m.ModelType == Data.Models.SMS:
			for f in ds.Models[m.ModelType]:
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				# errors with f.AllTimeStamps.Value
				if f.AllTimeStamps is not None or f.AllTimeStamps is not '':
					MessageBox.Show('Detected SMS AllTimeStamps field. Please reopen phone dump and check manually.')
					for i in list(f.AllTimeStamps):
						msg = "\tSMS.AllTimeStamps found. Manual check needed..."
						print(msg)
						debug(msg, "SMS.AllTimeStamps log write error")
					sms_timestamp = True
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: SMS ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
					
		# Call data: Data.Models.TelephonyModels.Call 
		if m.ModelType == Data.Models.TelephonyModels.Call:
			for f in ds.Models[m.ModelType]:
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Call ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
		# Attachment metadata?
	
		# MailMessage, Email, MMS also has TimeStamp (like SMS)
		if (m.ModelType == Data.Models.Email) or (m.ModelType == Data.Models.MMS) \
		or (m.ModelType == Data.Models.MailMessage):
			for f in ds.Models[m.ModelType]:
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Email, MMS or MailMessage ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")		
				reset_globals()	
			
		
		# InstantMessage like sms. Data.Models.InstantMessage
		if m.ModelType == Data.Models.InstantMessage:
			for f in ds.Models[m.ModelType]:
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.DateRead.Value is not None:
					if withinRange(f.DateRead.Value):
						pass
				if f.DateDelivered.Value is not None:
					if withinRange(f.DateDelivered.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: InstantMessage ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
	
			
		if m.ModelType == Data.Models.Chat:
			for f in ds.Models[m.ModelType]:
				# process IMs in Chats
				if f.Messages is not None:
					num = 0
					for im in f.Messages:
						try:
							if withinRange(im.TimeStamp.Value):
								pass
							if withinRange(im.StartTime.Value):
								pass
							if withinRange(im.DateDelivered.Value):
								pass
							if withinRange(im.DateRead.Value):
								pass
							if im.FieldExists('DatePlayed'):
								print("im="+str(num)+"im.TimeStamp="+str(im.TimeStamp)+" DateDelivered="+str(im.DateDelivered)+" im.DateRead="+str(im.DateRead))
								print("im.DatePlayed="+str(im.DatePlayed)) 
								if withinRange(im.DatePlayed.Value):
									pass
							if im.FieldExists('Date'):
								print("im.Date="+str(im.Date))
								if withinRange(im.Date.Value):
									pass
						except Exception as e:
							print "Error: "+str(e)
							
						if im.Deleted is not None:
							if doNotDateFilterDeleted is True and str(im.Deleted) == "Deleted":
								print("\tKeeping Deleted: IM "+str(num))
								keep = True 
						if global_inside_timeframe is True:
							keep = True
						if global_all_timestamps_None is True:
							# This means there were no timestamps or all timestamps were blank so we keep the item
							keep = True
						if keep is True:
							pass
						else:
							chats_Messages_listtoClear.append(im)
							# print("\t"+f.AbsolutePath+" outside timeframe.")
						reset_globals()
						num+=1
						
				if f.StartTime.Value is not None:
					if withinRange(f.StartTime.Value):
						pass
				if f.LastActivity.Value is not None:
					if withinRange(f.LastActivity.Value):
						pass								
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Chats ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()			

		# update 20160602: No handling of category "Notification" for PA 5.1. 
		# This is why newer filter def is better than this def. It can handle new categories
		# without explicit handling (as long as timestamps names are currently handled.)
		# TimeStamp, DateRead
				
		# Note: Data.Models.Note
		if m.ModelType == Data.Models.Note:
			for f in ds.Models[m.ModelType]:
				if f.Creation.Value is not None:
					if withinRange(f.Creation.Value):
						pass
				if f.Modification.Value is not None:
					if withinRange(f.Modification.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Note ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
		# CalendarEntry: Data.Models.CalendarEntry
		if m.ModelType == Data.Models.CalendarEntry:
			for f in ds.Models[m.ModelType]:
				if f.StartDate.Value is not None:
					if withinRange(f.StartDate.Value):
						pass
				if f.EndDate.Value is not None:
					if withinRange(f.EndDate.Value):
						pass
				if f.Reminder.Value is not None:
					if withinRange(f.Reminder.Value):
						pass
				if f.RepeatUntil.Value is not None:
					if withinRange(f.RepeatUntil.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: CalendarEntry ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
		# Location same as sms: Data.Models.LocationModels.Location
		if m.ModelType == Data.Models.LocationModels.Location:
			for f in ds.Models[m.ModelType]:		
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Location")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
	
		# Journey: Data.Models.LocationModels.Journey
		if m.ModelType == Data.Models.LocationModels.Journey:
			for f in ds.Models[m.ModelType]:
				if f.StartTime.Value is not None:
					if withinRange(f.StartTime.Value):
						pass
				if f.EndTime.Value is not None:
					if withinRange(f.EndTime.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Journey ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
		# Cookie: Data.Models.Cookie
		if m.ModelType == Data.Models.Cookie:
			for f in ds.Models[m.ModelType]:		
				if f.Expiry.Value is not None:
					if withinRange(f.Expiry.Value):
						pass
				if f.CreationTime.Value is not None:
					if withinRange(f.CreationTime.Value):
						pass
				if f.LastAccessTime.Value is not None:
					if withinRange(f.LastAccessTime.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Cookie")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
		# VisitedPage: Data.Models.VisitedPage
		if m.ModelType == Data.Models.VisitedPage:
			for f in ds.Models[m.ModelType]:	
				if f.LastVisited.Value is not None:
					if withinRange(f.LastVisited.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: VisitedPage")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
	
		# WebBookmark: Data.Models.WebBookmark
		if m.ModelType == Data.Models.WebBookmark:
			#print "WebBookmark"
			for f in ds.Models[m.ModelType]:	
				if f.LastVisited.Value is not None:
					if withinRange(f.LastVisited.Value):
						pass
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass			
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: WebBookmark")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					#print "WebBookmark list to clear: "+str(listtoClear)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
				
		# BluetoothDevice: Data.Models.BluetoothDevice
		if m.ModelType == Data.Models.BluetoothDevice:
			for f in ds.Models[m.ModelType]:		
				if f.LastConnected.Value is not None:
					if withinRange(f.LastConnected.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: BluetoothDevice ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
				
		# WirelessNetwork: Data.Models.WirelessNetwork
		if m.ModelType == Data.Models.WirelessNetwork:
			for f in ds.Models[m.ModelType]:		
				if f.LastConnection.Value is not None:
					if withinRange(f.LastConnection.Value):
						pass
				if f.LastAutoConnection.Value is not None:
					if withinRange(f.LastAutoConnection.Value):
						pass		
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: WirelessNetwork")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
				
		# VoiceMail: Data.Models.TelephonyModels.Voicemail
		if m.ModelType == Data.Models.TelephonyModels.Voicemail:
			for f in ds.Models[m.ModelType]:
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				# may be wrong info in UFED Python help file. TimeStamp not Duration
				if f.Duration.Value is not None:
					if withinRange(f.Duration.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: Voicemail ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
		# Passsword no timestamps
	
		# InstalledApplication: Data.Models.ApplicationModels.InstalledApplication
		if m.ModelType == Data.Models.ApplicationModels.InstalledApplication:
			for f in ds.Models[m.ModelType]:
				if f.PurchaseDate.Value is not None:
					if withinRange(f.PurchaseDate.Value):
						pass
				if f.DeletedDate.Value is not None:
					if withinRange(f.DeletedDate.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: InstalledApplication ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
			
		# ApplicationUsage: Data.Models.ApplicationModels.ApplicationUsage
		if m.ModelType == Data.Models.ApplicationModels.ApplicationUsage:
			for f in ds.Models[m.ModelType]:
				if f.ActiveTime.Value is not None:
					if withinRange(f.ActiveTime.Value):
						pass
				if f.Date.Value is not None:
					if withinRange(f.Date.Value):
						pass
				if f.LastLaunch.Value is not None:
					if withinRange(f.LastLaunch.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: ApplicationUsage ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")	
				reset_globals()	
			
		# DictionaryWord has no timestamps: Data.Models.DictionaryWord
	
		# SharedFile: Data.Models.SharedFile
		if m.ModelType == Data.Models.SharedFile:
			for f in ds.Models[m.ModelType]:
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass			
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: SharedFile")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	

		# Map has no timestamps
		
		# SearchedItem: Data.Models.SearchedItem
		if m.ModelType == Data.Models.SearchedItem:
			for f in ds.Models[m.ModelType]:
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: SearchedItem")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")		
				reset_globals()	
		
		# CarvedString has no timestamps: Data.Models.CarvedString

		# PoweringEvent: Data.Models.PoweringEvent
		if m.ModelType == Data.Models.PoweringEvent:
			for f in ds.Models[m.ModelType]:		
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: PoweringEvent ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
		
		# MobileCard: Data.Models.MobileCard
		if m.ModelType == Data.Models.MobileCard:
			for f in ds.Models[m.ModelType]:		
				if f.PurchaseTime.Value is not None:
					if withinRange(f.PurchaseTime.Value):
						pass
				if f.ModifyTime.Value is not None:
					if withinRange(f.ModifyTime.Value):
						pass
				if f.ActivationTime.Value is not None:
					if withinRange(f.ActivationTime.Value):
						pass
				if f.ExpirationTime.Value is not None:
					if withinRange(f.ExpirationTime.Value):
						pass	
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: MobileCard ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	
		
		# IPConnection: Data.Models.IPConnection
		# extra category with timestamp not mentioned in the "Using the Python Shell.pdf".
		if m.ModelType == Data.Models.IPConnection:
			for f in ds.Models[m.ModelType]:		
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: IPConnection ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					# This means there were no timestamps or all timestamps were blank so we keep the item
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
					# print("\t"+f.AbsolutePath+" outside timeframe.")
				reset_globals()	

		# LogEntry: Data.Models.LogEntry
		# extra category with timestamp not mentioned in the "Using the Python Shell.pdf".
		if m.ModelType == Data.Models.LogEntry:
			for f in ds.Models[m.ModelType]:		
				if f.TimeStamp.Value is not None:
					if withinRange(f.TimeStamp.Value):
						pass
				if f.Deleted is not None:
					if doNotDateFilterDeleted is True and str(f.Deleted) == "Deleted":
						print("\tKeeping Deleted: LogEntry ")
						keep = True 
				if global_inside_timeframe is True:
					keep = True
				if global_all_timestamps_None is True:
					keep = True
				if keep is True:
					pass
				else:
					listtoClear.append(f)
				reset_globals()
				
		# Grandchild classes of Data.Models:
		# Data.Models.ContactModels.Contact, Data.Models.TelephonyModels.Call
		# Data.Models.LocationModels.Location, Data.Models.LocationModels.Journey
		# Data.Models.TelephonyModels.Voicemail,
		# Data.Models.ApplicationModels.InstalledApplication
		# Data.Models.ApplicationModels.ApplicationUsage,
	
	print("Analyzed Data items - Chat messages removed ="+str(len(chats_Messages_listtoClear)))
	print("Analyzed Data items - others - removed ="+str(len(listtoClear)))
	global nRemoved
	nRemoved = len(listtoClear)+len(chats_Messages_listtoClear)
	
	# Remove items from PA GUI
	for f in listtoClear:
			f.ModelCollection.Remove(f)
	for f in chats_Messages_listtoClear:
		f.ModelCollection.Remove(f)
	return nRemoved	


# Filters Data Files by dates and clears non-matches
def filter_DeviceInfo():
	global nRemoved
	listtoClear = []
	msg = ''
	ts_count = 1
	
	msg1 = "\n***********************************\n"
	msg1 += "Processing DeviceInfo data"
	print(msg1)
	debug(msg1+"\n", "error writing DeviceInfo log")
	
	msg2 = "Date range start="+str(dt_start)+" end="+str(dt_end)
	print (msg2)
	debug(msg2+"\n", "error writing DeviceInfo log")
	
	for i in ds.DeviceInfo:
		
		if i.Name == 'DeviceInfoLocalNetworkIP' or i.Name == 'DeviceInfoInternetNetworkIP':
			dt_val = None
			m = re.match(".* at (....-..-.. ..:..:..).*", i.Value)
			if m:
				msg = "DeviceInfo item ("+str(ts_count)+"): "+str( m.group(0) )
				utc = re.search("UTC", m.group(0))
				if utc:
					msg += "\n\t\tTimestamp: "+str( m.group(1) )
					dt_val = TimeStamp(System.Convert.ToDateTime( m.group(1) ), True)
				else:
					msg += "\n\t\tTimestamp: "+str( m.group(1) )
					msg += " 'UTC' offset not found. Treating as UTC time."
					ts_w_utc = str(m.group(1))+"-0"
					dt_val = TimeStamp(System.Convert.ToDateTime( ts_w_utc ), True)	
			if withinRange(dt_val):
				msg += " within range.\n\t\tKeeping"
			else:
				listtoClear.append(i)
				msg += " outside range.\n\t\tRemoving"
			#print(msg)
			debug(msg, "Error writing log data files")
		ts_count += 1

	msg = 'DeviceInfo: Processed '+str(ts_count-1)+' items'
	print(msg)
	debug(msg, 'DeviceInfo finish. error writing log')
	
	# Remove data entries from DeviceInfo list
	nRemoved = len(listtoClear)
	for i in listtoClear:
		# This seems to remove it from DeviceInfo, but doesn't update GUI.
		# But the report seems to work correctly. 
		ds.DeviceInfo.Remove(i)
		
	print "\n***********************************"
	msg = "DeviceInfo items removed = "+str(nRemoved)
	print (msg)
	debug(msg, 'Error writing log DeviceInfo items removed')
	return nRemoved

	

class filterForm(Form):
	def __init__(self):
		self.Text = "Find Data In Date Ranges"

		self.Width = 475
		self.Height = 400

		self.check = CheckBox()
		self.check.Text = "Do NOT apply date filter to Deleted items."
		self.check.AutoSize = True
		self.check.Location = Point(25, 10)
		self.check.Width = 90
		self.check.Checked = True
		self.check.CheckedChanged += self.handleDeletedCheckBox

		self.check2 = CheckBox()
		self.check2.Text = "Do NOT apply date filter to Contact's LastContacted"
		self.check2.AutoSize = True
		self.check2.Location = Point(25, 50)
		self.check2.Width = 90
		self.check2.Checked = True
		self.check2.CheckedChanged += self.handleContactsCheckBox
		
		self.exampleLabel = Label()
		self.exampleLabel.Text = "Example: yyyy-mm-dd hh:mm:ss tz"
		self.exampleLabel.Location = Point(25, 120)
		self.exampleLabel.Height = 25
		self.exampleLabel.Width = 172
		self.exampleLabel.AutoSize = True
		
		self.fromLabel = Label()
		self.fromLabel.Text = "From date: "
		self.fromLabel.Location = Point(25, 155)
		self.fromLabel.Height = 25
		self.fromLabel.Width = 172
		self.fromLabel.AutoSize = True

		self.fromTextBox = TextBox()
		self.fromTextBox.Text = "2015-02-20 00:00:00-8"
		self.fromTextBox.Location = Point(25, 195)
		self.fromTextBox.Width = 172

		self.toLabel = Label()
		self.toLabel.Text = "To date: "
		self.toLabel.Location = Point(225, 155)
		self.toLabel.Height = 25
		self.toLabel.Width = 172

		self.toTextBox = TextBox()
		self.toTextBox.Text = "2015-02-20 23:59:59-8"
		self.toTextBox.Location = Point(225, 195)
		self.toTextBox.Width = 172
		
		
		self.button0 = Button()
		self.button0.Text = 'Check date/time'
		self.button0.Location = Point(25, 225)
		self.button0.Click += self.validateDates
		
		self.button1 = Button()
		self.button1.Text = 'Filter Data'
		self.button1.Location = Point(125, 225)
		self.button1.Click += self.filterByDates

		self.button2 = Button()
		self.button2.Text = 'Close'
		self.button2.Location = Point(225, 225)
		self.button2.Click += self.closeThis

		self.statusLabel = Label()
		self.statusLabel.Text = ""
		self.statusLabel.Location = Point(105, 265)
		self.statusLabel.Height = 25
		self.statusLabel.Width = 172
		self.statusLabel.AutoSize = True
		
		self.AcceptButton = self.button1
		self.CancelButton = self.button2

		self.Controls.Add(self.check)
		self.Controls.Add(self.check2)
		self.Controls.Add(self.exampleLabel)
		self.Controls.Add(self.fromLabel)
		self.Controls.Add(self.fromTextBox)
		self.Controls.Add(self.toLabel)
		self.Controls.Add(self.toTextBox)
		self.Controls.Add(self.button0)
		self.Controls.Add(self.button1)
		self.Controls.Add(self.button2)
		self.Controls.Add(self.statusLabel)
		
		self.CenterToParent()
		self.ShowDialog()

	def handleDeletedCheckBox(self, sender, args):
		global doNotDateFilterDeleted
		
		if sender.Checked:
			# Do not filter deleted by date range
			# Deleted sqlite db may have bad dates
			# and we want to display them
			doNotDateFilterDeleted = True
		else:
			doNotDateFilterDeleted = False
	
	def handleContactsCheckBox(self, sender, args):
		global doNotFilterContact_by_LastContacted
		
		if sender.Checked:
			# Filter by Contact's LastContacted timestamp
			doNotFilterContact_by_LastContacted = True
		else:
			doNotFilterContact_by_LastContacted = False
		
	def validateDates(self, sender, event):
		global dt_start
		global dt_end
		fromDate = self.fromTextBox.Text
		toDate = self.toTextBox.Text
		# MessageBox.Show('fromDate='+str(fromDate)+"\ntoDate="+str(toDate))

		try:
			dt_start = TimeStamp(System.Convert.ToDateTime(fromDate), True)
			dt_end = TimeStamp(System.Convert.ToDateTime(toDate), True)
		except Exception as e:
			MessageBox.Show('Error: Unable to set start date as '+str(fromDate)+"\n and end date as "+str(toDate))
			return False
		if dt_start > dt_end:
			MessageBox.Show("End time must be greater than start time.")
			return False
		
		MessageBox.Show('Please Verify Times\n\nStart: '+str(dt_start)+"\nEnd: "+str(dt_end))
		
	def filterByDates(self, sender, event):
		global dt_start
		global dt_end
		global log

		fromDate = self.fromTextBox.Text
		toDate = self.toTextBox.Text

		try:
			dt_start = TimeStamp(System.Convert.ToDateTime(fromDate), True)
			dt_end = TimeStamp(System.Convert.ToDateTime(toDate), True)
		except Exception as e:
			MessageBox.Show('Error: Unable to set start date '+str(fromDate)+"\n and end date "+str(toDate))
			return False
		
		if dt_start > dt_end:
			MessageBox.Show("End time must be greater than start time.")
			return False
			
		self.check.Enabled = False
		self.check2.Enabled = False
		self.button0.Enabled = False
		self.button1.Enabled = False
		self.button2.Enabled = False
		
		self.statusLabel.Text = 'Processing data... please wait.'
		MessageBox.Show('Finding all data between\n\nStart: '+str(dt_start)+'\nEnd: '+str(dt_end)+'\n\nclick OK to start')
		proc_start = datetime.now()
	
		# We want to use device's Display Name as the log filename.
		# Fix errors with Unicode characters in displayName for the log filename.
		displayName = ds.DeviceInfo['Display Name']
		filename = 'default_log_filename.txt'+"-"+str(proc_start)[:-7]+".txt"
		if displayName is not None:
			try:
				if displayName.isunicode:
					ustr = displayName.encode('utf-8', 'ignore')
					msg += ustr
					#remove last 7 characters from string, add .txt
					filename = "PA_date_filter_log-"+str(ustr)+"-"+str(proc_start)[:-7]+".txt"
				else:
					msg += str(displayName)
					filename = str(displayName)
			except UnicodeEncodeError as e:
				msg += "UnicodeEncodeError: bad displayName"

		filename = filename.replace(":","")
		filename = filename.replace(" ","_")
		try:
			# writes to default Cellebrite PA installation folder
			log = open("./Logs/"+filename, 'w')
			msg = "PA_date_filter.py script started: "+str(proc_start)+"\n"
			msg_dates = "Daterange from: "+str(fromDate)+" - "+str(toDate)+"\n"
			if doNotDateFilterDeleted is True:
				msg += "Not applying date filter to deleted data\n"
			else:
				msg += "Applying date filter to deleted data\n"
			if doNotFilterContact_by_LastContacted is True:
				msg += "Not applying date filter to Contact's LastContacted timestamp\n"
			else:
				msg += "Applying date filter to Contact's LastContacted timestamp\n"
				
			print(msg)
			print(msg_dates)
			log.write(msg)
			log.write(msg_dates)
		except Exception as e:
			MessageBox.Show('Error: Unable to write to Log folder in default PA installation location!')
			self.Close()
		
		num_df_removed = 0
		processPA_5_3 = False
		processPA_5_4 = False
		# check for version PA 5.3 which has access to ds.TaggedFiles
		# or version of PA 5.4 which uses ds.DataFiles instead
		try:
			if ds.TaggedFiles is not None:
				processPA_5_3 = True
		except Exception as e:
			if ds.DataFiles is not None:
				processPA_5_4 = True
		
		if processPA_5_3 is True:
			msg = "PA 5.3 processing"
			print(msg)
			log.write(msg)
			num_df_removed = filter_DataFiles()
		elif processPA_5_4 is True:
			msg = "PA 5.4 processing"
			print(msg)
			log.write(msg)
			num_df_removed = filter_DataFiles_v5_4()
		else:
			print "Unknown PA version"
			log.write("Unknown PA version")
				
		num_ad_removed = filter_AnalyzedData2()
		num_di_removed = filter_DeviceInfo()
		total_removed = num_df_removed+num_ad_removed+num_di_removed
		
		proc_end = datetime.now()
		duration = (proc_end - proc_start)
		
		MessageBox.Show('Finished filtering Data Files and Analyzed Data\n\nFiltered out: '+str(total_removed)+"\nDuration: "+str(duration))
		try:
			log.write("\nRemoved: "+str(num_df_removed)+" Data Files." )
			log.write("\nRemoved: "+str(num_ad_removed)+" Analyzed Data items.")
			log.write("\nRemoved: "+str(num_di_removed)+" DeviceInfo items.")
			log.write("\nRemoved: "+str(total_removed)+" Total items.")
			t = proc_end
			endtime = str(t.year)+"-"+str(t.month)+" "+str(t.day)+" "+str(t.hour)+":"+str(t.minute)+":"+str(t.second)
			log.write("\nScript ended "+str(endtime)+"\n")
			log.write("Daterange from: "+str(proc_start)+" - "+str(proc_end)+"\n")
			log.write("Duration: "+str(duration)+"\n")
		except Exception as e:
			errmsg = "Error at Processing ended. "+str(e)
			print(errmsg)
			debug(errmsg, "error closing log")
		
		self.check.Enabled = True
		self.check2.Enabled = True
		self.button0.Enabled = True
		self.button1.Enabled = True
		self.button2.Enabled = True
		self.statusLabel.Text = 'Done processing.\nRemoved: '+str(total_removed)+"\nDuration: "+str(duration)
		
		log.close()
		#self.Close()
		
	def closeThis(self, sender, event):
		self.fromTextBox.Text = ''
		self.toTextBox.Text = ''
		self.Close()

date_filter_form = filterForm()




