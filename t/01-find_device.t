#!/usr/bin/perl -w
use strict;
use Test::More tests => 11;

use_ok 'Net::Pcap::FindDevice';

my $name = find_device();

isn't $name, undef, "Found a device";
is find_device($name), $name, "find_device returns the same device if one is given";

my $name2;

$name2 = eval { find_device(undef); };
isn't $name2, undef, "Found a device";
is $name2, $name, "Found the same device as before";

$name2 = eval { find_device("");};
isn't $name2, undef, "Found a device";
is $name2, $name, "Found the same device as before";

ok( Net::Pcap::lookupnet($name, \(my $address), \(my $netmask), \(my $err)) == 0, "Can look up IP address of '$name'");
my $ip = join ".", unpack "C4", pack "N", $address;
diag "$name has IP address $ip";

($name) = Net::Pcap::FindDevice::interfaces_from_ip($ip);
isn't $name, undef, "Found a device for localhost";
is find_device($name), $name, "find_device is idempotent for localhost device";

$name2 = find_device('127.0.0.1');
is $name2, $name, "Found the same device as before";
