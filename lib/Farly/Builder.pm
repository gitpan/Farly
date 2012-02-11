package Farly::Builder;

use 5.008008;
use strict;
use warnings;
use Carp;
use Log::Log4perl qw(get_logger);
use Farly::IPv4::Address;
use Farly::IPv4::Network;
use Farly::IPv4::Range;
use Farly::Transport::Port;
use Farly::Transport::PortRange;
use Farly::Transport::Protocol;
use Object::KVC::List;
use Object::KVC::Hash;
use Object::KVC::HashRef;
use Object::KVC::Set;
use Object::KVC::String;

our $VERSION = '0.02';

sub new {
	my $class  = shift;

	my $self   = {
		FILE      => undef,
		CONTAINER => undef,
	};
	bless( $self, $class );

	my $logger = get_logger(__PACKAGE__);
	$logger->info("$self NEW ");

	return $self;
}

sub set_file {
	my ($self, $file) = @_;

	$self->{FILE} = $file;

	my $logger = get_logger(__PACKAGE__);
	$logger->info( "$self SET FILE TO ", $self->{FILE} );
}

sub file {
	return $_[0]->{FILE};
}

1;
__END__

=head1 NAME

Farly::Builder - Builder base class

=head1 DESCRIPTION

Farly::Builder is the Builder base class. Defines the
vendor independent Builder interface.

Farly::Builder is used by vendor specific builders only.

=head1 COPYRIGHT AND LICENCE

Farly::Builder
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
