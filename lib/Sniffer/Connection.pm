package Sniffer::Connection;
use strict;
use base 'Class::Accessor';
use Carp qw(carp croak);
use NetPacket::TCP;
use Data::Dumper;

=head1 NAME

Sniffer::Connection - contain basic information about a TCP connection

=head1 SYNOPSIS

  my $conn = Sniffer::Connection->new(
    tcp           => $packet,
    sent_data     => sub { $self->sent_data(@_) },
    received_data => sub { $self->received_data(@_) },
    closed        => sub {},
    teardown      => sub { $self->closed->($self) },
    log           => sub { print $_[0] },
  ));

This module will try to give you the ordered
data stream from a TCP connection. You supply
callbacks for the data. The data is returned
as the ACK-packets are seen for it.

As the TCP-reordering is cooked out by me, it
likely has bugs, but I have used this module
for sniffing some out-of-order TCP connection.

=cut

use vars qw($VERSION);

$VERSION = '0.08';

my @callbacks = qw(sent_data received_data closed teardown log);
__PACKAGE__->mk_accessors(qw(src_port dest_port src_host dest_host status last_ack window ), @callbacks);

sub new {
  my($class,%args) = @_;

  my $packet = delete $args{tcp};

  # Set up dummy callbacks as the default
  for (@callbacks) { $args{$_} ||= sub {}; };

  #$args{last_ack} ||= { src => undef, dest => undef };
  $args{window} ||= { src => {}, dest => {} };
  # will contain unacknowledged tcp packets

  my $self = $class->SUPER::new(\%args);

  if ($packet) {
    $self->handle_packet($packet);
  };

  $self;
};

=head2 C<< $conn->init_from_packet TCP >>

Initializes the connection data from a packet.

=cut

sub init_from_packet {
  my ($self, $tcp) = @_;
  $self->src_port($tcp->{src_port});
  $self->dest_port($tcp->{dest_port});
};

=head2 C<< $conn->handle_packet TCP >>

Handles a packet and updates the status
according to the packet.

=cut

sub handle_packet {
  my ($self, $tcp) = @_;

  if ($self->flow eq '-:-') {
    $self->init_from_packet($tcp);
  };

  my $key = $self->flow;
  my @dir = ('src', 'dest');
  #warn $self->signature($tcp) . "/" . $key;
  if ($self->signature($tcp) ne $key) {
    @dir = reverse @dir;
  };

  # Overwrite older sequence numbers
  $self->window->{$dir[0]}->{ $tcp->{seqnum} } = $tcp;

  #warn "Flushing $dir[1] before $tcp->{acknum}";
  $self->flush_window($dir[1], $tcp->{acknum});
  if (scalar keys %{$self->window->{$dir[1]}} > 32) {
    warn sprintf "$key ($dir[1]): %s packets unacknowledged.", scalar keys %{$self->window->{$dir[1]}};
  };
  #if (scalar keys %{$self->window->{$dir[1]}}) {
  #  warn $_ for sort keys %{$self->window->{$dir[1]}};
  #};
};

sub flush_window {
  my ($self,$part,$ack) = @_;
  my $status = $self->status;

  my $window = $self->window->{$part};
  my @seqnums = grep { $_ <= $ack } (sort keys %$window);

  #{
  #  local $" = ",";
  #  print "Handling ",(scalar @seqnums)," packets (@seqnums).\n";
  #};

  my @packets = map { delete $window->{$_} } @seqnums;
  for my $tcp (@packets) {
    die "Didn't find a window for every seqnum ..."
      unless $tcp;

    $self->log->( sprintf "Initial %08b %s", $tcp->{flags}, tcp_flags($tcp->{flags}) );

    if (not defined $status) {
        if ($tcp->{flags} == SYN) {
          $self->init_from_packet($tcp);
          $self->log->("New connection initiated");
          $self->status("SYN");
          return;
        } else {
          $self->log->("Not a SYN packet (ignored)");
          return;
        };

    } elsif ($status eq 'SYN') {
        # We want a SYN_ACK packet now
        if ($tcp->{flags} == SYN+ACK) {
          $self->log->("New connection acknowledged");
          if ($status ne "SYN") {
            print "!!! Connection status is $status, expected SYN\n";
          };
          $self->status("SYN_ACK");
          return
        } else {
          # silently drop the packet for now
          # If we are in SYN state but didn't get a SYN ACK, emit a warning
          # $self->log->("!!! Connection status is SYN, ignoring packet");
          return;
        };
    } elsif ($status eq 'ACK' or $status eq 'SYN_ACK') {
        my $data = $tcp->{data};
        my $key = $self->flow;

        if (length $data) {
          my $flow = 'sent_data';
          $flow = 'received_data'
            if ($self->flow ne $self->signature($tcp));
          $self->$flow->($data,$self,$tcp);
        };
        $self->status('ACK')
          if $status ne 'ACK';
      } elsif ($status eq 'CLOSE') {
        $self->log->("Connection close acknowledged");
        $self->teardown->($self);
        return
      };

      if ($tcp->{flags} & FIN) {
        $self->log->("Connection closed");
        $self->status("CLOSE");
        $self->closed->($self);
    };
  };
};

sub as_string {
  my ($self) = @_;
  sprintf "%s / %s", $self->flow, $self->status;
};

sub flow {
  my ($self) = @_;
  join ":", ($self->src_port||"-"), ($self->dest_port||"-")
};

sub signature {
  my ($class,$packet) = @_;
  join ":", $packet->{src_port}, $packet->{dest_port};
};

sub tcp_flags {
  my ($val) = @_;
  my $idx = 0;
  join " ", map { $val & 2**$idx++ ? uc : lc } (qw(FIN SYN RST PSH ACK URG ECN CWR));
};

1;

=head1 TODO

=over 4

=item *

Implement a (configurable?) timeout (of say 5 minutes) after which connections
get auto-closed to reduce resource usage.

=item *

Data can only be forwarded after there has been
the ACK packet for it!

=back

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

=cut
