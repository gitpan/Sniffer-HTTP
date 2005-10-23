package Sniffer::HTTP;
use strict;
use Sniffer::Connection::HTTP;
use base 'Class::Accessor';
use Data::Dumper;

use vars qw($VERSION);

$VERSION = '0.04';

=head1 NAME

Sniffer::HTTP - multi-connection sniffer driver

=head1 SYNOPSIS

  my $VERBOSE = 0;

  my $sniffer = Sniffer::HTTP->new(
    callbacks => {
      request  => sub { my ($req,$conn) = @_; print $req->uri,"\n" if $req },
      response => sub { my ($res,$req,$conn) = @_; print $res->code,"\n" },
      log      => sub { print $_[0] if $VERBOSE },
      tcp_log  => sub { print $_[0] if $VERBOSE > 1 },
    }
  );

  # retrieve TCP packet in $tcp, for example via Net::Pcap
  my $tcp = sniff_tcp_packet;

  $sniffer->handle_packet($tcp);

This driver gives you callbacks with the completely accumulated
L<HTTP::Request>s or L<HTTP::Response>s as sniffed from the
TCP traffic. You need to feed it the TCP packets either from
a dump file or from L<Net::Pcap> by unpacking them via
L<NetPacket>.

As the whole response data is accumulated in memory you should
be aware of memory issues. If you want to write stuff
directly to disk, you will need to submit patches to L<Sniffer::Connection::HTTP>

=head1 METHODS

=head2 C<< new %ARGS >>

  connections - preexisting connections (optional)
  callbacks   - callbacks for the new connections

=cut

__PACKAGE__->mk_accessors(qw(connections callbacks));

sub new {
  my ($class,%args) = @_;

  $args{connections} ||= {};
  $args{callbacks}   ||= {};

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

This parses a packet and creates the necessary connection.

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

sub handle_packet {
  my ($self,$tcp) = @_;
  $self->find_or_create_connection($tcp)->handle_packet($tcp);
};

1;

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