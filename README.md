# ibm-qradar-brocade
GitHub repository to showcase Cyber Resiliency with IBM QRadar and Brocade SAN FOS

This script is used as custom action triggered from IBM QRadar rule to block an Offending IP address post multiple failed logins
 
The script execution is unattended, so several parameters are passed.

 - parameter 1 : switch IP address
 - parameter 2 : offending ip address
 - parameter 3 : offending command

The parameters are extracted from the syslog event sent from Broadcomm switch to IBM QRadar

With above parameters received, the script logs onto switch using ssh and a pre-defined user on switch.

The default user used for passwordless login is _qradaradmin_

In order to permiit the passwordless login perform following actions. 

- Actions on the IBM QRadar host
 - Generated publich/private key pair on QRadar host using ssh-keygen
 - Copy the private key to ```/opt/ibm/qadar/bin/ca_jail/customactionuser/home/.ssh``` folder
 - Optionally create the config file under ```/opt/ibm/qadar/bin/ca_jail/customactionuser/home/.ssh``` to accept the key fingerprint during first login to switch.
 
- Actions on the Broadcomm switch  
 - Log on to the switch with admin user
 - Add the public key of QRadar root user to _qradaradmin_ user

During execution of the script from QRadar following flow is taken into account.

_ipfilter --show_ command is executed and the ouput is returned. The sample switch output is shown below

```
Name: default_ipv4, Type: ipv4, State: active
Rule    Source IP                               Protocol   Dest Port   Action
1     any                                            tcp       22     permit
2     any                                            tcp       23     permit
3     any                                            tcp       80     permit
4     any                                            tcp      443     permit
5     any                                            udp      161     permit
6     any                                            udp      123     permit
7     any                                            tcp      600 - 1023     permit
8     any                                            udp      600 - 1023     permit

Name: default_ipv6, Type: ipv6, State: active
Rule    Source IP                               Protocol   Dest Port   Action
1     any                                            tcp       22     permit
2     any                                            tcp       23     permit
3     any                                            tcp       80     permit
4     any                                            tcp      443     permit
5     any                                            udp      161     permit
6     any                                            udp      123     permit
7     any                                            tcp      600 - 1023     permit
8     any                                            udp      600 - 1023     permit
```

The multi line output here consists of all the policies defined on the switch in active / defined state

The output of ipfilter command is flattened to store in a list in following format
```
policy_name, policy_type, state, rule, ip address, protocol, port, action
default_ipv4,ipv4,active,1,any,tcp,22,permit
```

The list now contians output for every rule per every ACTIVE policy.

Next, the list is searched on the basis of ipv4 or ipv6 type and the  of rules (rule count) for the policy are determined

While traversing the list, the execution is aborted when **ALL** the following condition is met
 - the rule's port is matched with offending port
 - the rule's action is permit
 - the rule's ip address contains any

Once all above conditions are matched, an action list is created with rule entry example shown above and  of rules are added to the rule entry.
``` 
policy_name, policy_type, state, rule, ip address, protocol, port, action, total_number_of_rules_in_the_policy
default_ipv4,ipv4,active,1,any,tcp,22,permit,9
```

With this, at any given time the Action list will contain only one record for the matched rule entry.

Finally, the list elements are parsed to generate respective, clone, addrule, delete rule, save and activate switch commands

The generated switch commands are executed in single ssh session

## Known Limitations ##
  
1. It's not possible to determine the port of the incoming event as only command name (ssh/telnet) is sent as part of the event
   
2. Like the port, its also not possible to determine the protocol using which the command may run

3. The script does not take into account any CIDR notations, so its not possible to block an entire subnet as part of Cyber Resiliency reponse. 

Currently, a dictionary is maintained to reverse map the command to port eg. ssh:22, telnet:23

As we only receive command as a parameter, the dictionary needs to be kept updated with command:port mapping
