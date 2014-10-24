package Sniffer::Connection::HTTP;
use strict;
use Sniffer::Connection;
use HTTP::Request;
use HTTP::Response;

=head1 NAME

Sniffer::Connection::HTTP - Callbacks for a HTTP connection

=head1 SYNOPSIS

You shouldn't use this directly but via L<Sniffer::HTTP>
which encapsulates most of this.

  my $sniffer = Sniffer::Connection::HTTP->new(
    callbacks => {
      request  => sub { my ($req,$conn) = @_; print $req->uri,"\n" if $req },
      response => sub { my ($res,$req,$conn) = @_; print $res->code,"\n" },
    }
  );

  # retrieve TCP packet in $tcp, for example via Net::Pcap
  my $tcp = sniff_tcp_packet;

  $sniffer->handle_packet($tcp);

=cut

use base 'Class::Accessor';

my @callbacks = qw(request response closed log);
__PACKAGE__->mk_accessors(qw(tcp_connection sent_buffer recv_buffer _response _response_chunk_size _response_len _request prev_request),
                          @callbacks);

sub new {
  my ($class,%args) = @_;

  my $packet = delete $args{tcp};

  # Set up dummy callbacks as the default
  for (@callbacks) { $args{$_} ||= sub {}; };

  for (qw(sent_buffer recv_buffer)) {
    $args{$_} ||= \(my $buffer);
  };

  my $tcp_log = delete $args{tcp_log} || sub {};

  my $self = $class->SUPER::new(\%args);
  $self->tcp_connection(Sniffer::Connection->new(
    tcp           => $packet,
    sent_data     => sub { $self->sent_data(@_) },
    received_data => sub { $self->received_data(@_) },
    closed        => sub {},
    teardown      => sub { $self->closed->($self) },
    log           => $tcp_log,
  ));

  $self;
};

sub sent_data {
  my ($self,$data,$conn) = @_;
  $self->flush_received;
  ${$self->{sent_buffer}} .= $data;
  $self->flush_sent;
};

sub received_data {
  my ($self,$data,$conn) = @_;
  $self->flush_sent;
  ${$self->{recv_buffer}} .= $data;
  $self->flush_received;
};

sub flush_received {
  my ($self) = @_;
  my $buffer = $self->recv_buffer;
  while ($$buffer) {
    if (! (my $res = $self->_response)) {
      # We need to find something that looks like a valid HTTP request in our stream
      if (not $$buffer =~ s!.*^(HTTP/\d\..*? [12345]\d\d\b)!$1!m) {
        # Need to discard-and-sync
        $$buffer = "";
        #$self->recv_buffer(undef);
        return;
      };

      if (! ($$buffer =~ s!^(.*?\r?\n\r?\n)!!sm)) {
        # need more data before header is complete
        $self->log->log("Need more header data");
        #$self->recv_buffer($buffer);
        return;
      };
      
      my $h = $1;
      $res = HTTP::Response->parse($h);
      $self->_response($res);

      my $len = $res->header('Content-Length');
      
      $self->_response_len( $len );
    };

    my $res = $self->_response;
    my $len = $self->_response_len;
    my $chunksize = $self->_response_chunk_size;
    
    if ($res->header('Transfer-Encoding') eq 'chunked') {
      if (! defined $chunksize) {
        if (! ($$buffer =~ s!^\s*([a-f0-9]+)[ \t]*\r\n!!si)) {
          $self->log->("Extracting chunked size failed.");
          (my $copy = $$buffer) =~ s!\n!\\n\n!gs;
          $copy =~ s!\r!\\r!gs;
          $self->log->($copy);
        } else {
          $chunksize = hex $1;
          #$self->log->("Chunked size: $chunksize\n");
          $self->_response_chunk_size($chunksize);
        };      
      };
      while (defined $chunksize) {
        $self->log->("Chunked size: $chunksize\n");
        
        if (length $$buffer > $chunksize) {
          $self->log->("Got chunk of size $chunksize");
          $self->_response->add_content(substr($$buffer,0,$chunksize));
          $$buffer = substr($$buffer,$chunksize);
          #$self->log->($$buffer);
          
          #$self->log->("Resetting chunk size");
          $self->_response_chunk_size(undef);
        } else {
          # Need more data
          return
        };
        
        if ($chunksize == 0) {
          $self->report_response($res);
          return
        };
      };
    };

    # Non-chunked handling:
    if (length $$buffer < $len) {
      # need more data before header is complete
      $self->log->(sprintf "Need more response body data (%0.0f%%)\r", 100 * ((length $$buffer) / $len))
        if $len;
      return;
    };

    if ($len == 0) {
      # can only flush at closing of connection
      $self->log->("Would need to collect whole buffer in connection (unimplemented, taking what I've got)" );
      $len = length $$buffer;
    };
    
    $self->report_response_buffer($buffer,$len);
  };
};

sub report_response_buffer {
  my ($self,$buffer,$len) = @_;
  my $res = $self->_response;

  $res->content(substr($$buffer,0,$len));
  $self->log->("Response header and content are ready ($len bytes)");

  $$buffer = substr($$buffer,$len);
  if (length $$buffer) {
    $self->log->("Leftover data: $$buffer");
  };
  $self->report_response($res);
};

sub report_response {
  my ($self,$res) = @_;
  $self->response->($res,$self->prev_request,$self);
  $self->_response(undef);
  $self->_response_len(undef);
};

sub flush_sent {
  my ($self) = @_;
  my $buffer = $self->sent_buffer;
  while ($$buffer) {
    if (! (my $req = $self->_request)) {
      # We need to find something that looks like a valid HTTP request in our stream
      $$buffer =~ s!.*^(GET|POST)!$1!m;

      if (! ($$buffer =~ s!^(.*?\r?\n\r?\n)!!sm)) {
        # need more data before header is complete
        $self->log->("Need more header data");
        #$self->sent_buffer($buffer);
        return;
      };

      # Consider prepending the hostname in front of
      # the URI for nicer equivalence with HTTP::Proxy?

      $self->log->("Got header");
      my $h = $1;
      $req = HTTP::Request->parse($h);
      $self->_request($req);
    };

    my $req = $self->_request;
    my $len = $req->header('Content-Length') || 0; # length $$buffer; # not clean

    if (length $$buffer < $len) {
      # need more data before header is complete
      return;
    };

    $self->_request->content(substr($$buffer,0,$len));
    $self->log->("Request header and content are ready ($len bytes)");

    $self->request->($req,$self);

    $$buffer = substr($$buffer,$len);

    # Tie request and response together in a better way than serial request->response->request ...
    $self->prev_request($req);
    $self->_request(undef);
  };
};

sub handle_packet { my $self = shift;$self->tcp_connection->handle_packet(@_); };
sub flow { my $self = shift; return $self->tcp_connection->flow(@_);};

1;

=head1 TODO

=over 4

=item *

Think about pipelined connections. These are not easily massaged into the
request/response scheme. Well, maybe they are, with a bit of hidden
logic here.

=item *

Every response accumulates all data in memory instead of
giving the user the partial response so it can be written
to disk. This should maybe later be improved.

=cut