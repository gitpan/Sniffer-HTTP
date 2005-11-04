#!/usr/bin/perl -w
use strict;
use Test::More tests => 8;

use_ok 'Sniffer::HTTP';

my $s = Sniffer::HTTP->new();

can_ok($s, 'find_device');

my $name = $s->find_device();

isn't $name, undef, "Found a device";

is $s->find_device($name), $name, "find_device returns the same device if one is given";

my $name2;
#my $name2 = eval { $s->find_device(qr//);};
#isn't $name2, undef, "Found a device";
#is $name2, $name, "Found the same device as before";

$name2 = eval { $s->find_device(undef);};
isn't $name2, undef, "Found a device";
is $name2, $name, "Found the same device as before";

$name2 = eval { $s->find_device("");};
isn't $name2, undef, "Found a device";
is $name2, $name, "Found the same device as before";

