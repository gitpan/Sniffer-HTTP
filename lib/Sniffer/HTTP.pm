package Sniffer::HTTP;
use strict;
use Sniffer::Connection::HTTP;
use base 'Class::Accessor';
use Data::Dumper;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Net::Pcap; # just for the convenience function below
use Carp qw(croak);

use vars qw($VERSION);

$VERSION = '0.07';

=head1 NAME

Sniffer::HTTP - multi-connection sniffer driver

=head1 SYNOPSIS

  use Sniffer::HTTP;
  my $VERBOSE = 0;

  my $sniffer = Sniffer::HTTP->new(
    callbacks => {
      request  => sub { my ($req,$conn) = @_; print $req->uri,"\n" if $req },
      response => sub { my ($res,$req,$conn) = @_; print $res->code,"\n" },
      log      => sub { print $_[0] if $VERBOSE },
      tcp_log  => sub { print $_[0] if $VERBOSE > 1 },
    }
  );

  $sniffer->run('eth0'); # loops forever

  # Or, if you want to feed it the packets yourself:

  while (1) {

    # retrieve TCP packet into $tcp, for example via Net::Pcap
    my $eth = sniff_ethernet_packet;

    # And handle the packet. Callbacks will be invoked as soon
    # as complete data is available
    $sniffer->handle_eth_packet($eth);
  };

This driver gives you callbacks with the completely accumulated
L<HTTP::Request>s or L<HTTP::Response>s as sniffed from the
TCP traffic. You need to feed it the Ethernet, IP or TCP packets
either from a dump file or from L<Net::Pcap> by unpacking them via
L<NetPacket>.

As the whole response data is accumulated in memory you should
be aware of memory issues. If you want to write stuff
directly to disk, you will need to submit patches to L<Sniffer::Connection::HTTP>.

A good example to start from is the C<live-http-headers.pl>
script that comes with the distribution.

=head1 METHODS

=head2 C<< new %ARGS >>

Creates a new object for handling many HTTP requests.
You can pass in the following arguments:

  connections - preexisting connections (optional)
  callbacks   - callbacks for the new connections (hash reference)

Usually, you will want to create a new object like this:

  my $sniffer = Sniffer::HTTP->new( callbacks => {
    request  => sub { my ($req, $conn) = @_; print $req->uri,"\n"; },
    response => sub { my ($res,$req,$conn) = @_; print $res->code,"\n"; },
  });

except that you will likely do more work than this example.

=cut

__PACKAGE__->mk_accessors(qw(connections callbacks));

sub new {
  my ($class,%args) = @_;

  $args{connections} ||= {};
  $args{callbacks}   ||= {};
  $args{callbacks}->{log} ||= sub {};

  my $user_closed = delete $args{callbacks}->{closed};
  $args{callbacks}->{closed} = sub {
    my $key = $_[0]->flow;
    if (! exists $args{connections}->{$key}) {
      warn "Error: flow() ne connection-key!";
      $key = join ":", reverse split /:/, $key;
    };
    $_[0]->{log}->("Removing $key");
    delete $args{connections}->{$key};
    goto &$user_closed
      if $user_closed;
  };

  my $self = $class->SUPER::new(\%args);
  $self;
};

=head2 C<< $sniffer->find_or_create_connection TCP, %ARGS >>

This parses a TCP packet and creates the TCP connection
to keep track of the packet order and resent packets.

=cut

sub find_or_create_connection {
  my ($self,$tcp) = @_;

  my $connections = $self->connections;

  # Implement find_or_create() for connections in
  # the base class ...
  my $key = $tcp->{src_port} . ":" . $tcp->{dest_port};
  if (! exists $connections->{$key}) {
    my $key2 = $tcp->{dest_port} . ":" . $tcp->{src_port};
    if (! exists $connections->{$key2}) {
      $self->callbacks->{log}->("Creating connection $key");
      my $c = $self->callbacks;
      #warn Dumper $c;
      my $o = Sniffer::Connection::HTTP->new(
        %$c,
        tcp           => $tcp,
      );
      $connections->{$key} = $o;
    } else {
      $key = $key2
    };
  };

  return $connections->{$key};
};

=head2 C<< $sniffer->handle_eth_packet ETH >>

Processes a raw ethernet packet. L<Net::PCap> will return
this kind of packet for most Ethernet network cards.

You need to call this method (or one of the other protocol
methods) for every packet you wish to handle.

=cut

sub handle_eth_packet {
  my ($self,$eth) = @_;
  $self->handle_ip_packet(NetPacket::Ethernet->decode($eth)->{data});
};

=head2 C<< $sniffer->handle_ip_packet TCP >>

Processes a raw ip packet.

=cut

sub handle_ip_packet {
  my ($self,$ip) = @_;
  $self->handle_tcp_packet(NetPacket::IP->decode($ip)->{data});
};

=head2 C<< $sniffer->handle_tcp_packet TCP >>

Processes a raw tcp packet. This processes the packet
by handing it off to the L<Sniffer::Connection> which handles
the reordering of TCP packets.

=cut

sub handle_tcp_packet {
  my ($self,$tcp) = @_;
  if (! ref $tcp) {
    $tcp = NetPacket::TCP->decode($tcp);
  };
  $self->find_or_create_connection($tcp)->handle_packet($tcp);
};

=head2 C<< run DEVICE, PCAP_FILTER >>

Listens on the given device for all TCP
traffic from and to port 80 and invokes the callbacks
as necessary. If you want finer control
over what C<Net::Pcap> does, you need to set up
Net::Pcap yourself.

On Linux, you can give the device name 'any' and it
will listen on all interfaces.

On Windows, you can give a regular expression and it
will listen on the device whose name matches that
regular expression.

=cut

sub run {
  my ($self,$device_name, $pcap_filter) = @_;

  my $device = $self->find_device($device_name);
  $pcap_filter ||= "port 80";

  # Set up Net::Pcap
  my ($err);
  my %devinfo;
  my @devs;
  if ($Net::Pcap::VERSION < 0.07) {
    @devs = Net::Pcap::findalldevs(\$err, \%devinfo);
  } else {
    @devs = Net::Pcap::findalldevs(\%devinfo, \$err);
  };

  my ($address, $netmask);
  if (Net::Pcap::lookupnet($device, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $device, ' - ', $err;
  }
  warn $err if $err;

  #   Create packet capture object on device
  my $pcap = Net::Pcap::open_live($device, 128000, -1, 500, \$err);
  unless (defined $pcap) {
    die "Unable to create packet capture on device '$device' - $err";
  };

  my $filter;
  Net::Pcap::compile(
    $pcap,
    \$filter,
    $pcap_filter,
    0,
    $netmask
  ) && die 'Unable to compile packet capture filter';
  Net::Pcap::setfilter($pcap,$filter);

  Net::Pcap::loop($pcap, -1, sub { $self->handle_eth_packet($_[2]) }, '') ||
      die 'Unable to perform packet capture';
};

=head2 C<< $sniffer->find_device DEVICE >>

Finds a L<Net::Pcap> device based on some criteria:

If the parameter given is a regular expression, and
the operating system is C<MSWin32>, it
is used to scan the descriptions of the Net::Pcap 
device list. The name of the first matching element
is returned.

If a L<Net::Pcap> device matching the
stringified parameter exists, it is returned.
If there exists no matching device for the scalar, 
C<undef> is returned.

If the parameter is not given, and there is a device
called C<any>, that one is returned.

If there is only one network device, the name of
that device is returned.

If there is only one device left after removing all 
network devices with IP address 127.0.0.1, the name
of that device is returned.

The name of the device with the default gateway
(if any) is returned.

Otherwise it gives up and returns C<undef>.

=cut

sub find_device {
  my ($self, $device_name) = @_;
  # Set up Net::Pcap
  my ($err);
  my %devinfo;
  my @devs;
  if ($Net::Pcap::VERSION < 0.07) {
    @devs = Net::Pcap::findalldevs(\$err, \%devinfo);
  } else {
    @devs = Net::Pcap::findalldevs(\%devinfo, \$err);
  };

  my $device = $device_name;
  if ($device_name) {
    if (ref $device_name eq 'Regexp') {
      if ($^O eq 'MSWin32') {
        ($device) = grep {$devinfo{$_} =~ /$device_name/} keys %devinfo;
      } else {
        die "It doesn't make sense to me to scan the devices on $^O.";
      };
    } elsif (exists $devinfo{$device_name}) {
      $device = $device_name;
    } else {
      croak "Don't know how to handle $device_name as a Net::Pcap device";
    };
  } else {
    if (exists $devinfo{any}) {
      $device = 'any';
    } elsif (@devs == 1) {
      $device = $devs[0];
    } else {
      # Now we need to actually look at the devices and select the
      # one with the default gateway:
      
      # First, get the default gateway by using
      # `netstat -rn`
      my $device_ip;
      my $re_if = $^O eq 'MSWin32' 
                  ? qr/^\s*(?:0.0.0.0)\s+(\S+)\s+(\S+)\s+/
                  : qr/^(?:0.0.0.0|default)\s+(\S+)\s+.*?(\S+)\s*$/;
      for (qx{netstat -rn}) {
        if ( /$re_if/ ) {
          #$gateway = $1;
          $device_ip = $2;
          last;
        };
      };
      
      if (! $device_ip) {
        croak "Couldn't find IP address/interface of the default gateway interface. Maybe 'netstat' is unavailable?";
      };
      
      if (exists $devinfo{$device_ip}) {
        return $device_ip
      };

      # Looks like we got an IP and not an interface name.
      # So scan all interfaces if they have that our IP address.
      
      my $good_address = unpack "N", pack "C4", (split /\./, $device_ip);
      
      my @good_devices;
      for my $device (@devs) {
        my ($address, $netmask);
        (Net::Pcap::lookupnet($device, \$address, \$netmask, \$err) == 0) or next;
        $address != 0 or next;
        for ($address,$netmask) {
          $_ = unpack "N", pack "N", $_;
        };
        
        if ($address == ($good_address & $netmask)) {
          push @good_devices, $device;
        };
      };
      
      if (@good_devices == 1) {
        $device = $good_devices[0];
      } elsif (@good_devices > 1) {
        croak "Too many device candidates found (@good_devices)";
      }      
    };
  };
  
  return $device
};

1;

=head1 EXAMPLE PCAP FILTERS

Here are some example Net::Pcap filters for common things:

Capture all HTTP traffic between your machine and C<www.example.com>:

  (dest www.example.com && (port 80)) || (src www.example.com && (port 80))

Capture all HTTP traffic between your machine and C<www1.example.com> or C<www2.example.com>:
    (dest www1.example.com && (port 80)) || (src www1.example.com && (port 80))
  ||(dest www2.example.com && (port 80)) || (src www2.example.com && (port 80))

Note that Net::Pcap resolves these addresses before using them, so you might
actually get more data than you asked for.

=head1 BUGS

The whole module suite has almost no tests.

If you experience problems, I<please> supply me with a complete,
relevant packet dump as the included C<dump-raw.pl> creates. Even
better, supply me with (failing) tests.

=head1 AUTHOR

Max Maischein (corion@cpan.org)

=head1 COPYRIGHT

Copyright (C) 2005 Max Maischein.  All Rights Reserved.

This code is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SEE ALSO

L<HTTP::Proxy>, ethereal, L<Sniffer::Connnection>

=cut