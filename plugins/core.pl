
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


# Predeclare global variable names
use vars qw ( $dev $ping_before_scan $proto $first_community $community
$os_guess $print_ftptp $ftps $timeout $udpscan $PortCount $cock $SNMP_STAT
$second_community $timeout $size $sp $ep $snmp $malmode $tast $sweepex $ping
$btimeout $oids $snmp_timeout $snmp_port $malware $msg $uproto $telnet @line
$print_telnet $telnet_socket $src $daddr $sport $dport $Count $fuck $vendors
$offset $packet $synscan $syn_scan $ftpp $ftpt $verbose $sweep $pv $services @common $ovr $PRV);
	
$pv[0]=$sp;
$pv[1]=$ep;
	
print "[i] Please read the documentation before using this function," if $malmode;
print "\n    so there is no misunderstanding\n" if $malmode;

# Time format
my ($sec,$min,$hour,$mday,$mon,$year,$wday,
    $yday,$isdst)=localtime(time);

# Trigger subnet discovery and exit
if ($sweep) {
	if ($sweepex) {
			printf "Starting NetBIOS subnet discovery @ %4d-%02d-%02d %02d:%02d:%02d\n",
			$year+1900,$mon+1,$mday,$hour,$min,$sec;
		}
		else {
			printf "Starting subnet discovery @ %4d-%02d-%02d %02d:%02d:%02d\n",
			$year+1900,$mon+1,$mday,$hour,$min,$sec;
		}
	
	my @hosts;
	my $HostCount = 0;
	$hosts[0] = $sp;
	$hosts[1] = $ep;
	
	if ($sweepex) {
		printf("%-15s %-18s %-10s %-13s\n", 'IP ADDRESS', 'MAC ADDRESS', 'DOMAIN', 'NETBIOS NAME');
	}
	else { 
		printf("%-15s %-8s\n", 'IP ADDRESS', 'PACKET RETURN TIME');
    }
	
	for ($sp; $sp <= $ep; $sp++) {
		$ip = "$host$sp";
		$p = Net::Ping->new($proto, $timeout, $size);
		
		$p->hires();
		($ret, $duration, $ip) = $p->ping($ip, 1);

		if ($ret) {
			if ($sweepex) {
				$HostCount++;
				my $nb = Net::NBName->new;
				my $ns = $nb->node_status($ip);
				
				if ($ns) {
					for my $rr ($ns->names) {
						if ($rr->suffix == 0 && $rr->G eq "GROUP") {
							$domain = $rr->name;
							}
						if ($rr->suffix == 0 && $rr->G eq "UNIQUE") {
							$machine = $rr->name unless $rr->name =~ /^IS~/;
							}
						}
					$mac_address = $ns->mac_address; }
				
					printf("%-15s %-18s %-10s %-13s\n", $ip,$mac_address,$domain,$machine);
				}
			else {
				$HostCount++; printf("%-15s %.8f ms\n", $ip, 1000 * $duration);
				}
			} 
		}
	
	my $scanned = $hosts[1]-$hosts[0]+1;
	print "$HostCount/$scanned scanned machines up & running on subnet\n";
	
	if ($scanned <= '1') {
		print "\nScan completed: [$scanned] host scanned in ";
		}
	else {
		print "\nScan completed: [$scanned] hosts scanned in ";
		}

	$etime = time();
	$elapsed_time = $etime-$^T;
	printf("%.2f seconds\n", $elapsed_time);
	exit;
}

print "[i] Verbose mode activated\n" if $verbose;

# Check if host(s) is alive
if ($ping =~ "TRUE") {
	printf "Starting ping sequence @ %02d:%02d:%02d\n",
	$hour,$min,$sec if $verbose;
	
	$ip = $host;
    $p = Net::Ping->new();
    $p->hires();
    ($ret, $duration, $ip) = $p->ping($ip, 5.5);
    printf("$host [ip: $ip] is alive (packet return time: %.2f ms)\n", 1000 * $duration) if $ret;
    $p->close();

	if (!$ret) {
		my $HTTP = new IO::Socket::INET (
					Timeout  => 1,
					PeerAddr => $host,
					PeerPort => 80,
					Proto    => "tcp");
		
		my $FTP = new IO::Socket::INET (
					Timeout  => 1,
					PeerAddr => $host,
					PeerPort => 21,
					Proto    => "tcp") unless $HTTP;
				
		my $SMTP = new IO::Socket::INET (
					Timeout  => 1,
					PeerAddr => $host,
					PeerPort => 25,
					Proto    => "tcp") unless $HTTP && $FTP;
		close $HTTP;
		close $FTP;
		close $SMTP;
		
		if ($HTTP || $FTP || $SMTP) {
			print "NOTE: [ip: $ip] is currently blocking ($proto) ping probes\n";
			}
		else {
			print "[!] [host: $host] is not responding\n";
			print "[i] If it is blocking ping probes, ";
			print "(TCP 21/25/80 closed) try forced mode [-f]\n";
			print "\nScan completed: [1] host scanned in ";
			
			$etime = time();
			$elapsed_time = $etime-$^T;
			printf("%.2f seconds\n", $elapsed_time);
			exit;
		}
	}
	printf "Ping sequence ended @ %02d:%02d:%02d\n",
	$hour,$min,$sec if $verbose;
}

# Display scan type
my $type;

if ($synscan == 0 && $malmode == 0 && $PRV) {
	$type = "chronological connect()";
	}
elsif ($synscan == 0 && $malmode == 0) {
	$type = "common connect()";
	}
elsif ($synscan == 0 && $malmode) {
	$type = "(common) malware connect()";
	}
elsif ($synscan && $malmode == 0) {
	$type = "chronological stealth";
	}

	printf "Starting $type scan @ %02d:%02d:%02d\n",
	$hour,$min,$sec if $verbose;

# Initiate TCP SYN scan if requested



# Common ports connect() scan (PRV: Port Range Value)
if ($synscan == 0 && $PRV == 0 && $host =~ /^.+\..+\..+$/) {
	print "Interesting ports on $host:\n";
	printf("%-8s %-6s %-8s\n", 'PORT NR','STATE','SERVICE');
	
	foreach $sp (@common) {
			my $COMMON = new IO::Socket::INET (
					Timeout  => 1,
					PeerAddr => $host,
					PeerPort => $sp,
					Proto    => "tcp");
			
			if ($COMMON) {
				if ($malmode) {
					printf("%-8s %-7s %-8s\n", $sp, 'active', $malware{$sp}) if $malware{$sp};
					}
				else {
					printf ("%-8s %-6s %-8s\n", $sp, 'open', $services{$sp}); 
					}
				}
			}
}

# Threaded full connect scan in port range
elsif ($synscan == 0) {
if ($malmode) {
	print "Possible threats found on $host:\n";
	printf("%-8s %-7s %-8s\n", 'PORT NR', 'STATE', 'THREAT');
	}
else {
	print "Interesting ports on $host:\n";
	printf("%-8s %-6s %-8s\n", 'PORT NR', 'STATE', 'SERVICE');
	}
	
$| = 1;
my $parent = 0;
my @children = ();

FORK: for ($sp; $sp <= $ep; $sp++) {
	my $oldpid = $$;
	my $pid = fork;
	
	if (not defined $pid) {
		if ($! =~ /Resource temporarily unavailable/) {
			&DoReap;
			$sp --;

		}
		else {
			die "[ERR]: Can't fork: $!\n";
		}

	}
	elsif ($pid == 0) {
		$parent = $oldpid;
		@children = ();

		last FORK;
	}
	else {
		push @children, $pid;
	}
}

if ($parent) {
	my $socket;
	my $success = eval {
		$socket = IO::Socket::INET->new(
			PeerAddr 	=> $host, 
			PeerPort 	=> $sp,
            Timeout     => $timeout,
			Proto 	    => 'tcp'
		) 
	};
			
# If port is open: perform database lookup
# and display port nr
if ($success) {
	if ($malmode) {
		printf("%-8s %-7s %-8s\n", $sp, 'active', $malware{$sp}) if $malware{$sp};
		}
	else {
		# open (TEMP, ">>temp.zapfort");
		# printf TEMP ("%-8s %-6s %-8s\n", $sp, 'open', $services{$sp});
		# close (TEMP);
		printf ("%-8s %-6s %-8s\n", $sp, 'open', $services{$sp});
		}

	shutdown($socket, 2);
    exit;
	}
	exit 0;

} else {
	#If we're not the kid, we're the parent. Do a reap.
	&DoReap;
}

#This sub is the reaper.
sub DoReap {
	while (my $child = shift @children) {
		waitpid $child, 0;
	} 
}

}
 
# If not in stealth mode
unless ($synscan == 0 && ($PRV == 0) && $host =~ /^.+\..+\..+$/) {
    
# Check for anonymous FTP access
if (($ftps = Net::FTP->new($host, Port => $ftpp, Timeout => $ftpt, Debug => 0)) &&
    ($ftps->login("anonymous",'none@none'))) {
	print "[!/02]: Anonymous FTP access found on port \"$ftpp\"\n";

	if ($ftps->dir()) {
		print "\tSuccessfully performed directory listing\n"; }
	if ($ftps->mkdir("719967600")) {
		print "\tSuccessfully created directory\n"; }
	if ($ftps->rmdir("719967600")) {
		print "\tSuccessfully removed directory\n"; }
	if ($ftps->cdup()) {
		print "\tSuccessfully moved up 1 directory\n\tPWD output: "; }
	if ($ftps->pwd()) {
		print $ftps->message; }
	 }

# Perform NetBIOS lookup
  my $nb = Net::NBName->new;
  # a unicast node status request
  my $ns = $nb->node_status($host);
  if ($ns) {
	for my $rr ($ns->names) {
		if ($rr->suffix == 0 && $rr->G eq "GROUP") {
                    $domain = $rr->name;
                }
                if ($rr->suffix == 3 && $rr->G eq "UNIQUE") {
                    $user = $rr->name;
                }
                if ($rr->suffix == 0 && $rr->G eq "UNIQUE") {
                    $machine = $rr->name unless $rr->name =~ /^IS~/;
                }
            }
	print "[!/01]: NetBIOS may be leaking (sensitive) system information:\n";
        print "\tSystem [DOMAIN\\NAME USER]: $domain\\$machine $user\n";
  }

# SNMP OID:s for:
# System name, system description & system uptime
@oids=("1.3.6.1.2.1.1.5.0","1.3.6.1.2.1.1.1.0",
       "1.3.6.1.2.1.1.3.0");

# Open SNMP(v1) socket for first community string
my ($session, $error) = Net::SNMP->session(
   -hostname  => shift || $host,
   -community => shift || $community,
   -version   => shift || 1,
   -timeout   => shift || $snmp_timeout,
   -port      => shift || $snmp_port
);

if ($session) {
	$oids = $session->var_bind_list;
	my $rfc_version = $session->version;
	my $SNMPv;
	
	if ($rfc_version == "0") { $SNMPv = "v1"; }
	elsif ($rfc_version == "1") { $SNMPv = "v2c";}
	else { $SNMPv = "v3"; }

my $result = $session->get_request(
   -varbindlist => \@oids
);

if ($result) {
    print "[!/03]: Vulnerable SNMP($SNMPv) service found\n\tcommunity string is \"$community\"\n";
    printf("\tObtained system name: %s\n",
   $result->{$oids[0]});
    
        printf("\tObtained system description/OS: %s\n",
       $result->{$oids[1]});

            printf("\tObtained system uptime: %s\n",
           $result->{$oids[2]});
	    
        $session->close;
     }
}

# Attempt to receive MAC address through NetBIOS,
# convert format for vendor database lookup
my $nb_mac = Net::NBName->new;
my $ns_mac = $nb_mac->node_status($host);

if ($ns_mac) {
	my $mac = $ns->mac_address;
	my $amount = ($mac =~ s/-/:/g);
	my $mac_address = $mac;
	
		$mac =~ (s/[-:]//g);
		if (length $mac > 6) { $mac = substr($mac,0,6); }
		my $vendor = $vendors{uc $mac};
		print "MAC Address: $mac_address ($vendor)\n";
		}
}

my $calc = (($pv[1]-$pv[0])/65535)*100;
if (($malmode) && ($calc <= 50)) {
	printf("NOTE: only about %.2f percent of the host was scanned\n", $calc);
	print "[i] To perform a full scan, set the port range to 1-65535\n";
	}

# Finally display success and elapsed scan time
print "\nScan completed: [1] host scanned in ";

	$etime = time();
        $elapsed_time = $etime-$^T;
	printf("%.2f seconds\n", $elapsed_time);