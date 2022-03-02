#!/usr/bin/env python3

#
# Copyright IBM Corp. 2016 All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
 
##########################################################
#													     #
#                   Disclaimer 						     #
#													     #
#   The script is provided here is only a sample.        #
#													     #
#   There is no official support on the script by me     #
#													     #
#   or IBM. 										     #
#													     #
#   Do NOT use the script in the production environment. #
#													     #
#   You may use the script as guideline to create the    #
#													     #
#   custom action response best suited to your needs.    #
#													     #
##########################################################

import re
import sys
import datetime
import subprocess

## ** Jump to main() function **

def main():

	lstAction = []

	lstRules = loadData('ipfilter --show')

	lstAction = checkRules( lstRules )

	if len(lstAction) > 0:
		updatePolicy( lstAction )


def updatePolicy( lstAction ):
	"""
		IN: list( default_ipv4,ipv4,active,1,any,tcp,22,permit,#rules_in_policy )

	"""

	global offence_ip, offence_port, max_rules, dry_run

	epoch = datetime.datetime.now().strftime('%s')

	# Add epoch timestamp to policy name.
	qradar_policy_name = 'qr_{0}' . format(epoch)

	policy_name,policy_type,p_active,\
	rule_id,rule_ip,rule_proto,\
	rule_port,rule_action,policy_rule_count = lstAction

	CLONERULE = 'ipfilter --clone {0} -from {1}' . \
		format(qradar_policy_name, policy_name )

	DELRULE = 'ipfilter --delrule {0} -rule {1}' . \
		format(qradar_policy_name, rule_id )

	ADDRULE_DENY = 'ipfilter --addrule {0} -rule {1} -sip {2} -dp {3} -proto {4} -act {5}'. \
	format(
		qradar_policy_name,
		rule_id,
		offence_ip,
		offence_port,
		rule_proto,
		'deny'
	)

	new_rule_id = int(max_rules) + 1
	ADDRULE_PERMIT = 'ipfilter --addrule {0} -rule {1} -sip {2} -dp {3} -proto {4} -act {5}'. \
	format(
		qradar_policy_name,
		new_rule_id,
		'any',
		offence_port,
		rule_proto,
		'permit'
	)

	SAVERULE  = 'ipfilter --save {0}' . \
	 	format(qradar_policy_name )

	ACTIVATE  = 'ipfilter --activate {0}' . \
		format(qradar_policy_name )

	print('{0}\n{1}\n{2}\n{3}\n{4}\n{5}'. 
		format( CLONERULE, DELRULE, ADDRULE_DENY, ADDRULE_PERMIT, SAVERULE, ACTIVATE )
	)

	print('Blocking further connections from {0} on port {1}'.
		format( offence_ip, offence_port )
	)

	# Add ACTIVATE to following tuple

	SEQ = ( CLONERULE, DELRULE, ADDRULE_DENY, ADDRULE_PERMIT, SAVERULE, ACTIVATE )

	switch_cmds = ' ; ' . join( SEQ )

	runCli( switch_cmds )


def loadData( switch_cmd ):
	"""
		This function is written to get the currently active rules
		from the switch configuration.

		Once the active rules are retrieved, they are flattened
		in a list. 

		Parameters
		 - IN : Switch command to execute
		 - OUT: list in following format for all rules found
                for all policies
                default_ipv4,ipv4,active,1,any,tcp,22,permit
	"""

	global active_policies

	active_policies.clear()

	spaces = re.compile('\s+')
	commas = re.compile(',')

	lst_rules = []

	# the user has specified a
	# output file with switch output
	# load it (simulation mode)

	#f = open('switch-output', 'r')
	#data = f.read()
	#f.close()

	data = runCli( switch_cmd )

	# Process the output received from
	# (ipfilter --show) switch command
	# or loaded from output file

	for line in data.split('\n'):

		# Skip empty lines & header line
		if re.search(r'^$|^Rule', line):
			continue

		# Extract policy_name, type and state
		# from line beginning with Name
		if re.search(r'^Name',line):

			line2 = commas.sub('',line)	

			p_name  = line2.split(':')[1].split(' ')[1].strip()
			p_type  = line2.split(':')[2].split(' ')[1].strip()
			p_state = line2.split(':')[3].split(' ')[1].strip()

			continue

		# Consider only the active policy
		if p_state == 'active' and \
			p_type == ip_type : 

			# creating a set of policies
			active_policies.add( p_name )

			# convert space to commas
			csv_line = spaces.sub(',',line.strip())
			# create a tuple
			rec      = ( p_name, p_type, p_state, csv_line )
			# create a comma separated values record
			csv_rec  = ',' . join( rec )
			# store the value in a list
			lst_rules.append(csv_rec)

	return lst_rules

def getRuleCount( lstRules, policy_name ):
	"""
		This function return the rule count for a given policy
		indicated by policy_name

		Parameters: 

		- IN : 	1. List containing all the rules
				2. Name of the policy

		- Out: # of rules in the policy.
	"""

	count = 0

	for x in lstRules:
		if x.split(',')[0] == policy_name:
			count +=1

	return count


def checkRules( lstRules ):
	"""

		IN: list ( default_ipv4,ipv4,active,1,any,tcp,22,permit )
		OUT: list( default_ipv4,ipv4,active,1,any,tcp,22,permit,#rules_in_policy)

	"""

	global active_policies, offence_port, ip_type, max_rules
	
	lstAction = []
	ipAlreadyBlocked = False

	# Iterate through the set with
	# active policy name
	for active_policy in active_policies:
		
		rule_count = 0
		take_action= False

		# Iterate through all rules (ipv4 & ipv6)
		# stored in the list
		for rule in lstRules:

			p_name     = rule.split(',')[0]
			p_type     = rule.split(',')[1]
			p_state    = rule.split(',')[2]
			rule_id    = rule.split(',')[3]
			rule_ip    = rule.split(',')[4]
			rule_proto = rule.split(',')[5]
			
			# account for port range here
			if rule.split(',')[7] == '-' :

				p_begin = rule.split(',')[6]
				p_end   = rule.split(',')[8]

				rule_port  = p_begin + '-' + p_end
				rule_action= rule.split(',')[9]

			else:

				rule_port  = rule.split(',')[6]
				rule_action= rule.split(',')[7]

			# ip_type can be ipv4 or ipv6
			# determined globally
			if p_type == ip_type and \
				p_name == active_policy:

				# get total rules count for this policy
				if rule_count == 0:
					rule_count = getRuleCount( lstRules, p_name )
					max_rules  = rule_count

				port_matched = getPortMatch( rule_port )

				# check if the offensive ip is alrady blocked 
				# abort the further execution 
				if port_matched and \
					rule_ip == offence_ip and \
					rule_action == 'deny':	

					print('No policy change required')
					print('IP {0} is alredy blocked for port {1}'.\
						format(offence_ip,rule_port)
					)
			
					break

				if port_matched and \
					rule_action == 'permit' and \
					rule_ip == 'any':

					tup = ( rule, str(rule_count) )
					action_rec = ',' . join( tup )
							
					lstAction = list(action_rec.split(',')) 
		
					# abort iner loop
					take_action = True
					break

		# abort outer loop
		if take_action:
			break
					
	return lstAction	
			
def getPortMatch( rule_port ):

	global offence_port

	if re.search(r'-',rule_port):

		port_begin = rule_port.split('-')[0]
		port_end   = rule_port.split('-')[1]

		if offence_port >= int(port_begin) and \
			offence_port <= int(port_end):
		
			return True

	else:

		if int(rule_port) == offence_port:

			return True

	return False

def runCli( cli_cmd ):
	"""
		Purpose: Run any external command and return the output

		Parameters:
			- IN
				1. cli command to run
			- OUT
				1. output of cli command
	"""

	global system, remote_user

	lst_cmd = []
	lst_cmd.append( 'ssh' )
	lst_cmd.append( '-o StrictHostKeyChecking=no' )
	lst_cmd.append( remote_user + "@" + system )
	lst_cmd.append( cli_cmd )

	print(cli_cmd)

	try:
		# Command execution using subprocess
		stdout = subprocess.check_output( \
				lst_cmd, 
				universal_newlines = True,
				shell = False 
		)

		if stdout != None:
			return stdout
		
	except KeyboardInterrupt:
		print( "User abort ..\n" )
		sys.exit( 1 )

	except subprocess.CalledProcessError:
		print( "Error connecting to remote host !! aborting !!! \n")
		sys.exit( 1 )


def Usage():

	global system,ip_address,command

	msg = """

	Usage: {0} <system_ip|FQDN> <offense ip> <cmd(ssh|telnet|http|https)>

	"""

	print( msg . format(system,ip_address,command))
	sys.exit()

if __name__ == '__main__':

	argc = len(sys.argv) - 1

	if argc == 0 or argc > 3 :

		Usage()

	system,ip_address,command = sys.argv[1:]
	
	remote_user = 'qradaradmin'

	active_policies = {'index_ignore'}

	cmd_to_port_dict = { 'ssh' : 22, 'https' : 443, 'telnet' : 23, 'http' : 80 }

	max_rules    = 0
	offence_port = cmd_to_port_dict[command]
	offence_ip   = ip_address

	dry_run = False

	if offence_ip.find('.') > 0:
		ip_type = 'ipv4'
	else:
		ip_type = 'ipv6'

	if dry_run:
		print('*** Simulation only ***' )
		print('Switch IP: {0}\nOffence IP:{1}\nOffence Port:{2}\n'.
			format(system,ip_address,offence_port)
		)

	MSG = """ NOTE: 

	The current syslog configuration does not write protocol in
	the event. The switch on the other hand has rules for 
	both tcp and udp protocols.

	As no protocol information is sent along with the event
	1st rule matching the ip / port will be chosen irrespective
	of the protocol.

	This may lead to unintended blocking rule.

	Needs to be fixed in rsyslog event.
	"""

	print(MSG)

	main()
	
