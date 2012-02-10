package Farly::Transport::Port;

use 5.008008;
use strict;
use warnings;
use Carp;
use Farly::Transport::Object;

our @ISA = qw(Farly::Transport::Object);
our $VERSION = '0.01';

sub new {
	my ( $class, $port ) = @_;

	die "Port required" unless (defined($port));

	my $self = {
		PORT => undef, 
	};
	bless( $self, $class );

	$self->_init($port);

	return $self;
}

sub _init {
	my ( $self, $port ) = @_;

	$port =~ s/\s+//g;

	die "invalid port $port"
	  unless ( $port =~ /\d+/ );

	die "invalid port $port"
	  unless ( $port >= 0 && $port <= 65535 );

	$self->{PORT} = $port;

	return;
}

sub as_string {
	return $_[0]->{PORT};
}

sub port {
	return $_[0]->{PORT};
}

sub first {
	return $_[0]->{PORT};
}

sub last {
	return $_[0]->{PORT};
}

sub iter {
	my @list = ( $_[0] );
	return @list;
}

1;
__END__

=head1 NAME

Farly::Transport::Port - IPv4 address class

=head1 DESCRIPTION

This class represents a TCP or UDP port number.

Inherits from Farly::Transport::Object.

=head1 METHODS

=head2 new( <string> )

The constructor accepts a decimal port number

 my $port = Farly::Transport::Port->new( 80 );

=head2 port()

Returns the integer port number

  $8_bit_int = $port->port();

=head2 first()

Returns the port number

  $8_bit_int = $port->first();

=head2 last()

Returns the port number

  $8_bit_int = $port->first();

=head2 as_string()

Returns the current Farly::Transport::Port an integer

  print $port->as_string();

=head2 iter()

Returns an array containing the current Port object. For use in
Set calculations.

  my @array = $port->iter();

=head1 COPYRIGHT AND LICENSE

Farly::Transport::Port
Copyright (C) 2012  Trystan Johnson

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
