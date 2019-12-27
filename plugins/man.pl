#    zapfort alpha v0.01
#    Copyright (C) 2006 Olle Hällman
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

print <<EOF;

Syntax: perl zapfort.pl [target/destination] [-h] [-p port range] [-o output]
	     [-u output] [-g] [-s] [-v] [-m] [-sw]
	     [-c community string] [-ps SNMP port] [-pf FTP port]

Options:
	-p	Specifies port range on <host> to be scanned.
	-o	Exports a report in plain text.
	-u	Exports a report as a web document.
	-g	Grabs the banner on specified ports (-p).
	-s	Scans <host> in stealth mode (light scan).
	-v	Enables a verbose mode.
	-m	Scans <host> for well-known malware (trojans, worms etc)
	-sw	Initiates a ping sweep on specified subnet.
	-c	Specifies the SNMP community string
	-ps	Specifies SNMP port to connect to
	-pf	Specifies FTP port to connect to
        
EOF
exit;