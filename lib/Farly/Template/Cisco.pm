package Farly::Template::Cisco;

use 5.008008;
use strict;
use warnings;
use Carp;
use File::Spec;
use Template;
use Log::Log4perl qw(get_logger);

our $VERSION = '0.06';
our ( $volume, $dir, $file ) = File::Spec->splitpath( $INC{'Farly/Template/Cisco.pm'} );

sub new {
	my ($class, $file, %args) = @_;

	my $self = {
		FILE     => $file,
		TEMPLATE => undef,
	};

	bless $self, $class;

	$self->_init(%args);

	my $logger = get_logger(__PACKAGE__);
	$logger->info("$self NEW");

	return $self;
}

sub _init {
	my ($self, %args) = @_;

	my $path = "$volume$dir"."Files/";

	$self->{TEMPLATE} = Template->new(
		{
			%args,
			INCLUDE_PATH => $path,
			TRIM         => 1,
		}
	) or die "$Template::ERROR\n";
}

sub _template { return $_[0]->{TEMPLATE}; }
sub _file { return $_[0]->{FILE}; }

sub _value_format {
	my ( $self, $value ) = @_;

	my $string;

	if ( $value->isa('Farly::IPv4::Address') ) {

		$string = "host " . $value->as_string();
	}
	elsif ( $value->isa('Farly::Transport::Port') ) {

		$string = "eq ".$value->as_string();
	}
	elsif ( $value->isa('Farly::Transport::PortRange') ) {

		$string .= "range ".$value->as_string();
	}
	elsif ( $value->isa('Object::KVC::HashRef') ) {

		$string = $value->get("ID")->as_string();
	}
	else {

		$string = $value->as_string();
		$string =~ s/0.0.0.0 0.0.0.0/any/g;
		$string =~ s/^\s+|\s+$//g;
	}

	return $string;
}

sub _format {
	my ( $self, $ce ) = @_;

	my $GROUP_REF = Object::KVC::HashRef->new();
	$GROUP_REF->set( "ENTRY", Object::KVC::String->new("GROUP") );

	my $OBJECT_REF = Object::KVC::HashRef->new();
	$OBJECT_REF->set( "ENTRY", Object::KVC::String->new("OBJECT") );

	my $IF_REF = Object::KVC::HashRef->new();
	$IF_REF->set( "ENTRY", Object::KVC::String->new("INTERFACE") );

	my $INTERFACE = Object::KVC::Hash->new();
	$INTERFACE->set( "ENTRY", Object::KVC::String->new("INTERFACE") );

	my $RULE  = Object::KVC::String->new("RULE");

	my $ALL = Farly::Transport::PortRange->new("1 65535");

	my $hash;

	#interface ip addresses should not be prefixed with "host"
	if ( $ce->matches( $INTERFACE ) ) {
		foreach my $key ( $ce->get_keys() ) {
			$hash->{$key} = $ce->get($key)->as_string();
		}
		return $hash;
	}

	foreach my $key ( $ce->get_keys() ) {

		my $value = $ce->get($key);

		my $prefix;
		my $string;

		if ( $value->equals($ALL) ) {
			next;
		}

		if ( $value->isa('Object::KVC::HashRef') ) {

			if ( $value->matches($GROUP_REF) ) {
				if ( $ce->get("ENTRY")->equals($RULE) ) {
					$prefix = "object-group";
				}
			}
			elsif ( $value->matches($OBJECT_REF) ) {
				$prefix = "object";
			}
			elsif ( $value->matches($IF_REF) ) {
				$prefix = "interface";
			}
		}

		$string = defined($prefix)
		  ? $prefix . " " . $self->_value_format($value)
		  : $self->_value_format($value);

		$hash->{ $key } = $string;
	}

	return $hash;
}


sub as_string {
	my ( $self, $ce ) = @_;

	my $hash = $self->_format($ce);

	$self->_template()->process( $self->_file, $hash )
	  or die $self->_template()->error();
}

1;
__END__

=head1 NAME

Farly::Template::Cisco - Converts the Farly firewall model into 
                         Cisco format

=head1 DESCRIPTION

Farly::Template::Cisco formats and prints the Farly firewall model into 
Cisco configuration formats.

=head1 METHODS

=head2 new()

The constructor. Device type required.

  $template = Farly::Template::Cisco->new('ASA');

Valid device types:

  ASA

=head2 as_string( <Object::KVC::Hash> )

Prints the current Farly object in Cisco format.

  $template->as_string( $object );

=head1 COPYRIGHT AND LICENCE

Farly::Template::Cisco
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
