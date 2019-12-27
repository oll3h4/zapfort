# Zapfort Network Tool

## How to run it

The first time your run the script you will be asked to run a compatiblity check. This is because it uses a few non-standard CPAN libraries for extended functionality. These are the modules that need to be installed:

- Net::SNMP
- Net::Telnet
- Net::NBName

Assuming you have CPAN installed, run "cpan" from the terminal/command prompt. Then run: install PACKAGE.
Quit CPAN and run the script again. If everything installed correctly it should say so. If you don't need the functionality associated with the above libraries, you can just skip the entire compatibility check.

## Todo

- Automatic ping sweeps for detection of new network computers with alert capability (rudimentary IDS)
-- Should allow user to view information about computer and ability to block it

- Detection of ARP cache poisoning
- Simple GUI
