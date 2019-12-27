#!/usr/bin/perl

#    zapfort alpha v0.01
#    Copyright (C) 2006 Olle Hällman
#
#    This program is free softptware: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Softptware Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Predeclare global variables
use vars qw(
$host
$PRV
$proto
$size
$verbose
$synscan
$help
$webdoc
$sweepex
$sweep
$outputfile
$ftpp
$banner
$malmode
$community
$plugins
$sp
$ep
$databases
$FirstTime);

# Store information globally
$version = "alpha v0.01";
$config = "./default.conf";

# Time format
my ($sec,$min,$hour,$mday,$mon,$year,$wday,
    $yday,$isdst)=localtime(time);

# Print current version and time
printf "\nRunning zapfort $version @ %4d-%02d-%02d %02d:%02d:%02d\n",
$year+1900,$mon+1,$mday,$hour,$min,$sec;

# Load configuration
do $config;

# If run for the first time, do a
# compatibility check if requested
if ($FirstTime == 1) {
    &CompatibilityCheck;
    open (CONFIGURATION, ">>$config");
    print CONFIGURATION "\$FirstTime = 0; # DELETE THIS LINE TO RUN COMPATIBILITY CHECK AGAIN";
    close (CONFIGURATION);
}

# Compatibility/module check
sub CompatibilityCheck {
    
    use ExtUtils::Installed;
    my $instmod = ExtUtils::Installed->new();
    print "[i] This is your first time running zapfort $version\n";
    print "[?] Initiate first-time compatibility check? (recommended) [y/N]: ";
    my $answer = <STDIN>;
    my @ModuleList;

    if ($answer =~ "y") {
        print "[i] Confirming all essential modules are installed...\n";
        foreach $module ($instmod->modules()) {
            my $version = $instmod->version($module) || "???";
            
            # Module list
            if ($module =~ /Net::SNMP/) {
                print "\tSUCCESS: Net::SNMP ($version) is installed\n";
                $ModuleList[0] = "Net::SNMP";
                }
            if ($module =~ /Net::Telnet/) {
                print "\tSUCCESS: Net::Telnet ($version) is installed\n";
                $ModuleList[1] = "Net::Telnet";
                }
            if ($module =~ /Net::NBName/) {
                print "\tSUCCESS: Net::NBName ($version) is installed\n";
                $ModuleList[2] = "Net::NBName";
                }
        }
        
        if ($ModuleList[0] !~ "Net::SNMP") {
            print "\tFAIL: Net::SNMP is not installed or can't be found\n";
            }
        if ($ModuleList[1] !~ "Net::Telnet") {
            print "\tFAIL: Net::Telnet is not installed or can't be found\n";
            }
        if ($ModuleList[2] !~ "Net::NBName") {
            print "\tFAIL: Net::NBName is not installed or can't be found\n";
            }
        
        if (($ModuleList[0] =~ "Net::SNMP") && ($ModuleList[1] =~ "Net::Telnet") &&
            ($ModuleList[2] =~ "Net::NBName")) {
            print "[i] All good: you are set to go\n";
            }
        else {
            print "[!] Module(s) missing\n";
            print "[i] Install the missing module(s) and try again\n\n";
            print "[!] Cannot continue: quitting...\n";
            exit;
            }
        }
    else {
        
print <<EOF;

[i] SKIPPING COMPATIBILITY CHECK
    THIS _MAY_ RESULT IN ERROR AND APPLICATION FAILURE
    SEE README FOR INTRUCTIONS
EOF

    }
}

# Standard perl libraries
use strict;

use Time::HiRes qw(time);
use Getopt::Long;
use IO::Socket;
use Net::FTP;
use Net::Ping;

# None-standard perl libraries
use Net::NBName;
use Net::SNMP;

# Command line options
my $PARAM = GetOptions(
"p=s"         => \$PRV, # Port range
"r:i"         => \$proto, # Ping packet protocol
"s:i"         => \$size, # Ping packet size
"v"           => \$verbose, # Verbose mode
"s"           => \$synscan, # TCP SYN (stealth) mode (light scan)
"h"           => \$help, # Print manual
"u:s"         => \$webdoc, # Web document report
"e"           => \$sweepex, # Extended ping sweep with NetBIOS features
"sw"          => \$sweep, # Ping sweep
"o:s"         => \$outputfile, # Plain text report
"pf:i"        => \$ftpp, # FTP port
"g"           => \$banner, # Banner grab
"m"           => \$malmode, # Malware mode (database exchange)
"c:s"         => \$community); # SNMP community string

# Print manual if requested
do "./$plugins/man.pl" if $help;

$_ = $ARGV[0]; $host = $_;

# Check target/destination input value
if (($host !~ /^.+\..+$/) && ($host !~ /^.+\..+\..+$/) && ($host !~ /^.+\..+\..+\..+$/)
    && ($host !~ /^.+\..+\..+\..+\-.+$/)) {
    print "[!] Host not (properly) specified; quitting...\n";
    print "[i] Apply -h parameter for help\n\n";
    exit;
    }

# If ping sweep is requested,
# format target/destination input value
if ($sweep) {
    /(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3}$)/;
    ($host, $sp, $ep)=($1, $2, $3);
    }

# Format -p parameter input value
my @temp;
my @ptValue;

$ptValue[0] = $PRV;
$ptValue[1] = $ptValue[0];

$temp[0] = ($ptValue[0] =~ s/\-.+//);
$temp[1] = ($ptValue[1] =~ s/.+\-//);

    $sp = $ptValue[0] if $PRV;
    $ep = $ptValue[1] if $PRV;

# Prevent common mistakes
if ($sp > $ep) {
    print "[!] INPUT WARNING: the minimum port is higher then the maximum\n";
    print "[i] Adjusting port range to \"$ep-$sp\"\n";
    my $temp;
    $temp = $sp;
    $sp = $ep; $ep = $temp;
    }
if ($ep > 65535) {
        print "[!] INPUT WARNING: maximum port cannot exceed \"65535\"\n";
        print "[i] Scan will stop at port \"65535\"\n";
        $ep = 65535;
    }
if ($ep-$sp >= 10000) {
        print "[i] Due to huge port range this scan may take several minutes/hours\n";
        print "    depending on hardware and OS\n";
    }

# Load local databases
do "./$databases/vendors";
do "./$databases/ports";
do "./$databases/malports";

# Finally load the core
do "./$plugins/core.pl";

exit; # Quit zapfort