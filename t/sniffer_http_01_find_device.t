#!/usr/bin/perl -w
use strict;
use Test::More tests => 4;

use_ok 'Sniffer::HTTP';

my $s = Sniffer::HTTP->new();

can_ok($s, 'find_device');

my $name = $s->find_device();

isn't $name, undef, "Found a device";

is $s->find_device($name), $name, "find_device returns the same device if one is given";