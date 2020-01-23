#!/usr/bin/perl

##################################################################################
##################################################################################
#######################  Made by Juan Jose Lizano 2020 ####################
##################################################################################
##################################################################################
####      This is a Nagios Plugin destined to check the status of IPsec       ####
####              site-to-site VPN tunnels on Cisco ASA devices.              ####
##################################################################################
##################################################################################

use strict;
use vars qw($community $IP $primaryPeerIP $peerName $secondaryPeerIP);

use Getopt::Long;
use Pod::Usage;

# Subroutines execution

getParameters ();
checkVPNStatus ();
checkVPNTunnel ();

# Subroutines definition

sub checkVPNStatus ()	# Checks IPsec site-to-site tunnel status via SNMP
{
	my $OID = '1.3.6.1.4.1.9.9.392.1.3.21.1.2';
	my $version = '2c';

	my $command = "/usr/bin/snmpwalk -v $version -c $community $IP $OID 2>&1";
	my $result = `$command`;

	if ($result =~ m/^Timeout.*$/)
	{
		my $output = "UNKNOWN! No SNMP response from $IP.";
		my $code = 3;
		exitScript ($output, $code);
	}

	if ($secondaryPeerIP eq '')
	{
		my $result = checkVPNTunnel ($version, $OID, $primaryPeerIP);

		my $peer;

        	if ($peerName ne '')
        	{
                	$peer = "$primaryPeerIP ($peerName)";
        	}

        	else
        	{
                	$peer = $primaryPeerIP;
        	}

		if ($result == 0)
		{
			my $output = "CRITICAL! VPN peer $peer unavailable.";
			my $code = 2;
			exitScript ($output, $code);
		}

		else
		{
			my $output = "OK! VPN peer $peer available.";
			my $code = 0;
			exitScript ($output, $code);
		}
		
	}

	else
	{
		my $result1 = checkVPNTunnel ($version, $OID, $primaryPeerIP);
		my $result2 = checkVPNTunnel ($version, $OID, $secondaryPeerIP);

		my $peers;

        	if ($peerName ne '')
        	{
                	$peers = "$primaryPeerIP, $secondaryPeerIP ($peerName)";
        	}

        	else
        	{
                	$peers = "$primaryPeerIP, $secondaryPeerIP";
        	}


		if (($result1 == 0) and ($result2 == 0))
		{
			my $output = "CRITICAL! Both VPN peers: $peers unavailable.";
			my $code = 2;
			exitScript ($output, $code);
		}

		else
		{
			my $used;

			if ($result1 == 0)
			{
				$used = "$secondaryPeerIP used.";
			}

			if ($result2 == 0)
			{
				$used = "$primaryPeerIP used.";
			}

			my $output = "OK! VPN peers: $peers available. $used";
			my $code = 0;
			exitScript ($output, $code);
		}
	}
}

sub checkVPNTunnel ()
{
	my $command = "/usr/bin/snmpwalk -v $_[0] -c $community $IP $_[1] | grep $_[2] | wc -l";
	my $result = `$command`;
	return $result;
}

sub exitScript ()	# Exits the script with an appropriate message and code
{
	print "$_[0]\n";
	exit $_[1];
}

sub getParameters ()	# Obtains script parameters and prints help if needed
{
	my $help = '';

	GetOptions ('help|?' => \$help,
		    'C=s' => \$community,
		    'H=s' => \$IP,
		    'P=s' => \$primaryPeerIP,
		    'N:s' => \$peerName,
		    'S:s' => \$secondaryPeerIP)

	or pod2usage (1);
	pod2usage (1) if $help;
	pod2usage (1) if (($community eq '') || ($IP eq '') || ($primaryPeerIP eq ''));
	pod2usage (1) if (($IP !~ m/^\d+\.\d+\.\d+\.\d+$/) || ($primaryPeerIP !~ m/^\d+\.\d+\.\d+\.\d+$/));
	if ($secondaryPeerIP ne '')
	{
		pod2usage (1) if ($secondaryPeerIP !~ m/^\d+\.\d+\.\d+\.\d+$/);
	}

=head1 SYNOPSIS

check_asa_vpn.pl [options] (-help || -?)

=head1 OPTIONS

Mandatory:

-H	IP address of monitored Cisco ASA device

-C	SNMP community

-P	IP address of primary VPN peer

Optional:

-N	Name of VPN peer

-S	IP address of secondary VPN peer

=cut
}
