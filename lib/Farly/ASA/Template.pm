package Farly::ASA::Template;

use 5.008008;
use strict;
use warnings;
use Carp;
use File::Spec;
use Template;
use Log::Log4perl qw(get_logger);
use Farly::ASA::PortFormatter;
use Farly::ASA::ProtocolFormatter;
use Farly::ASA::ICMPFormatter;

our $VERSION = '0.04';
our ( $volume, $dir, $file ) = File::Spec->splitpath( $INC{'Farly/ASA/Template.pm'} );

sub new {
	my ($class) = @_;

	my $self = {
		TEMPLATE           => undef,
		port_formatter     => Farly::ASA::PortFormatter->new(),
		protocol_formatter => Farly::ASA::ProtocolFormatter->new(),
		icmp_formatter     => Farly::ASA::ICMPFormatter->new(),
	};

	bless $self, $class;

	$self->_init();

	my $logger = get_logger(__PACKAGE__);
	$logger->info("$self NEW");

	return $self;
}

sub _init {
	my ($self) = @_;

	my $path = "$volume$dir";

	$self->{TEMPLATE} = Template->new(
		{
			INCLUDE_PATH => $path,
			TRIM         => 1,
		}
	) or die "$Template::ERROR\n";
}

sub template {
	return $_[0]->{TEMPLATE};
}

sub port_formatter {
	return $_[0]->{port_formatter};
}

sub protocol_formatter {
	return $_[0]->{protocol_formatter};
}

sub icmp_formatter {
	return $_[0]->{icmp_formatter};
}

sub value_format {
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
	elsif ( $value->isa('Farly::Transport::Protocol') ) {

		$string = defined( $self->protocol_formatter->as_string( $value->as_string() ) )
		  ? $self->protocol_formatter->as_string( $value->as_string() )
		  : $value->as_string();
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

sub format {
	my ( $self, $ce ) = @_;

	my $GROUP_REF = Object::KVC::HashRef->new();
	$GROUP_REF->set( "ENTRY", Object::KVC::String->new("GROUP") );

	my $OBJECT = Object::KVC::Hash->new();
	$OBJECT->set( "ENTRY", Object::KVC::String->new("OBJECT") );

	my $OBJECT_REF = Object::KVC::HashRef->new();
	$OBJECT_REF->set( "ENTRY", Object::KVC::String->new("OBJECT") );

	my $IF_REF = Object::KVC::HashRef->new();
	$IF_REF->set( "ENTRY", Object::KVC::String->new("INTERFACE") );

	my $RULE  = Object::KVC::String->new("RULE");
	my $GROUP = Object::KVC::String->new("GROUP");

	my $ALL = Farly::Transport::PortRange->new("1 65535");

	my $hash;

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
		  ? $prefix . " " . $self->value_format($value)
		  : $self->value_format($value);

		if ( $key eq "ICMP_TYPE" ) {
			
			$string = defined( $self->icmp_formatter->as_string( $value->as_string() ) )
			  ? $self->icmp_formatter->as_string( $value->as_string() )
			  : $value->as_string();
		}

		$hash->{ $key } = $string;
	}

	return $hash;
}


sub as_string {
	my ( $self, $ce ) = @_;

	my $INTERFACE = Object::KVC::HashRef->new();
	$INTERFACE->set( "ENTRY", Object::KVC::String->new("INTERFACE") );

	my $hash;
	if ( $ce->matches( $INTERFACE ) ) {
		foreach my $key ( $ce->get_keys() ) {
			$hash->{$key} = $ce->get($key)->as_string();
		}
	}
	else {
		$hash = $self->format($ce);		
	}

	$self->template()->process( 'ASA.tt', $hash )
	  or die $self->template()->error();
	
}

1;
__END__

=head1 NAME

Farly::ASA::Template - Converts the Farly firewall model into 
                       Cisco ASA configurations.

=head1 DESCRIPTION

Farly::ASA::Template formats and prints the Farly firewall model into 
Cisco ASA configuration format.

=head1 METHODS

=head2 new()

The constructor. No arguments required.

  $template = Farly::ASA::Template->new();

=head2 as_string( <Object::KVC::Hash> )

Prints the current Farly object in Cisco ASA string format.

  $template->as_string( $object );

=head1 COPYRIGHT AND LICENCE

Farly::ASA::Template
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
