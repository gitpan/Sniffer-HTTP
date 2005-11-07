#!/usr/bin/perl -w
use strict;
use Test::More tests => 4;
use Data::Dumper;

use Net::Pcap;
use LWP::Simple;

use_ok 'Sniffer::HTTP';

my $s = Sniffer::HTTP->new(
  callbacks => {
    log      => sub { diag "HTTP: $_[0]" },
    tcp_log  => sub { diag "TCP : $_[0]" },
    request  => \&collect_request,
    response => \&collect_response,
  },
);

my (@responses,@requests);
sub collect_response {
  my ($res,$req,$conn) = @_;
  push @responses, [$res,$req];
  Net::Pcap::breakloop($s->pcap_device);
};
sub collect_request {
  my ($req,$conn) = @_;
  push @requests, $req;
};


my $url = 'http://www.cpan.org/';
diag "*** Doing live capture of an LWP request to $url";
diag "*** If that is blocked or you live behind a proxy, this test will fail.";
diag "*** The dump-to-file feature is untested then.";

my $dumpfile = 't/05-capture_to_file.dump';
if (-f $dumpfile) {
  diag "Removing old dumpfile '$dumpfile'";
  unlink $dumpfile
    or diag "Couldn't remove '$dumpfile': $!";
};

SKIP: {
  if ($ENV{HTTP_PROXY}) {
    skip 4, "Proxy settings detected - sniffing will not work";
  };
  if ($Net::Pcap::VERSION < 0.07) {
    skip 4, "Net::Pcap version too low for breakloop()";
  };

# This version of fork() works even on Win32:
if (fork()) {
  alarm 60; # Emergency breakout
  $s->run(undef,"((dst www.cpan.org || src www.cpan.org)) && (tcp port 80)", capture_file => $dumpfile);
} else {
  diag "Launching request to '$url'";
  sleep 1;
  alarm 55; # Emergency breakout
  get $url;
  exit;
};

ok -f $dumpfile, "A dump was created in '$dumpfile'";

my @stale = $s->stale_connections();
is_deeply(\@stale,[],"No stale connections");

my @live = $s->live_connections();
# Well, not actually, but close enough. The live connection
# gets closed one TCP packet later, but we trigger the break
# out of the loop too early for that.
is scalar(@live), 1, "One live connection";

if (-f $dumpfile) {
  diag "Removing dumpfile '$dumpfile'";
  unlink $dumpfile
    or diag "Couldn't remove '$dumpfile': $!";
};
};