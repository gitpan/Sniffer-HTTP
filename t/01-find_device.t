#!/usr/bin/perl -w
use strict;
use Test::More tests => 11;

use_ok 'Net::Pcap::FindDevice';

diag "Pcap lib_version is " . Net::Pcap::lib_version();

if (&Net::Pcap::lib_version() eq 'libpcap version unknown (pre 0.8)') {
  SKIP: {
  skip "libpcap version too low", 10;
  };
  exit;
};

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

SKIP: {
  if ($^O eq 'MSWin32') {
    skip "Win32 has no interface for localhost", 3
  } else {
    ($name) = Net::Pcap::FindDevice::interfaces_from_ip('127.0.0.1');
    isn't $name, undef, "Found a device for localhost"
      and diag "Interface is '$name'";
    is find_device($name), $name, "find_device is idempotent for localhost device";
    $name2 = find_device('127.0.0.1');
    is $name2, $name, "Found the same device as before";
  };
};
