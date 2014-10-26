package Farly::ASA::Annotator;

use 5.008008;
use strict;
use warnings;
use Carp;
use Scalar::Util qw(blessed);
use Log::Log4perl qw(get_logger);
use Farly::ASA::PortFormatter;
use Farly::ASA::ProtocolFormatter;
use Farly::ASA::ICMPFormatter;

our $VERSION = '0.09';
our $AUTOLOAD;

#each token type maps to a class
our $Token_Class_Map = {
	'STRING'      => 'Object::KVC::String',
	'DIGIT'       => 'Object::KVC::Integer',
	'NAME'        => 'Object::KVC::String',            #method replaces name with IP
	'IF_REF'      => 'Object::KVC::HashRef',
	'OBJECT_REF'  => 'Object::KVC::HashRef',
	'GROUP_REF'   => 'Object::KVC::HashRef',
	'RULE_REF'    => 'Object::KVC::HashRef',
	'GROUP_TYPE'  => 'Object::KVC::String',
	'OBJECT_TYPE' => 'Object::KVC::String',
	'ANY'         => 'Farly::IPv4::Network',			#method ANY = '0.0.0.0 0.0.0.0'
	'IPADDRESS'   => 'Farly::IPv4::Address',
	'MASK'        => 'Farly::IPv4::Address',
	'IPNETWORK'   => 'Farly::IPv4::Network',
	'IPRANGE'     => 'Farly::IPv4::Range',
	'NAMED_NET'   => 'Object::KVC::String',             #method replaces name with IP
	'PROTOCOL'    => 'Farly::Transport::Protocol',
	'GROUP_PROTOCOL' => 'Object::KVC::String',          #not ::Protocol because of 'tcp-udp'
	'ICMP_TYPE'      => 'Farly::IPv4::ICMPType',        #method maps string to int
	'PORT_ID'       => 'Farly::Transport::Port',      	#method maps string to int
	'PORT_RANGE'    => 'Farly::Transport::PortRange',   #method maps string to int
	'PORT_GT'       => 'Farly::Transport::PortGT',      #method maps string to int
	'PORT_LT'       => 'Farly::Transport::PortLT',      #method maps string to int
	'ACTIONS'       => 'Object::KVC::String',
	'ACL_TYPES'     => 'Object::KVC::String',
	'REMARKS'       => 'Object::KVC::String',
	'ACL_DIRECTION' => 'Object::KVC::String',
	'ACL_GLOBAL'    => 'Object::KVC::String',
	'STATE'         => 'Object::KVC::String',
	'ACL_STATUS'    => 'Object::KVC::String',
	'LOG_LEVEL'     => 'Object::KVC::String',
	'DEFAULT_ROUTE' => 'Farly::IPv4::Network',			#method DEFAULT_ROUTE = '0.0.0.0 0.0.0.0'
	'TUNNELED'      => 'Object::KVC::String'
};

# 'ENTRY' is like a namespace in which an ID must be unique
# A <type>_REF refers to a Object::KVC::Hash by ENTRY and ID
our $Entry_Map = {
	'IF_REF'     => 'INTERFACE',
	'OBJECT_REF' => 'OBJECT',
	'GROUP_REF'  => 'GROUP',
	'RULE_REF'   => 'RULE',
};

sub new {
	my ( $class ) = @_;

	my $self  = {
		NAMES        => {}, #name to address 'symbol table'
		PORT_FMT     => Farly::ASA::PortFormatter->new(),
		PROTOCOL_FMT => Farly::ASA::ProtocolFormatter->new(),
		ICMP_FMT     => Farly::ASA::ICMPFormatter->new()
	};
	bless $self, $class;

	my $logger = get_logger(__PACKAGE__);
	$logger->info("$self NEW");

	return $self;
}

sub port_formatter {
	return $_[0]->{PORT_FMT};
}

sub protocol_formatter {
	return $_[0]->{PROTOCOL_FMT};
}

sub icmp_formatter {
	return $_[0]->{ICMP_FMT};
}

sub visit {
	my ( $self, $node ) = @_;

	# set s of explored vertices
	my %seen;

	#stack is all neighbors of s
	my @stack;
	push @stack, $node;

	#my $key;

	while (@stack) {

		$node = pop @stack;

		next if ( $seen{$node}++ );

		if ( exists( $node->{'__VALUE__'} ) ) {
			my $method = ref($node);
			$self->$method($node);
		}
		elsif ( $node->isa('names') ) {
			$self->_new_name($node);
		}
		else {

			foreach my $key ( keys %$node ) {

				next if ( $key eq 'EOL' );

				my $next = $node->{$key};

				if ( blessed($next) ) {

					push @stack, $next;
				}
			}
		}
	}
	return 1;
}

sub _new_name {
	my ( $self, $node ) = @_;

	my $logger = get_logger(__PACKAGE__);

	my $name = $node->{NAME}->{__VALUE__}
	  or confess "$self error: name not found for ", ref($node);

	my $ip = $node->{IPADDRESS}->{__VALUE__}
	  or confess "$self error: IP address not found for ", ref($node);

	$logger->debug("name: $name ip: $ip");
	$self->{NAMES}->{$name} = $ip;
}

sub NAME {
	my ( $self, $node ) = @_;

	my $name = $node->{'__VALUE__'}
	  or confess "$self error: __VALUE__ not found for name";

	my $ip = $self->{NAMES}->{$name}
	  or confess "$self error: IP address not found for name $name";

	$node->{'__VALUE__'} = Farly::IPv4::Address->new($ip);
}

sub NAMED_NET {
	my ( $self, $node ) = @_;

	my $named_net = $node->{'__VALUE__'}
	  or confess "$self error: __VALUE__ not found for name";

	my ( $name, $mask ) = split( /\s+/, $named_net );

	my $ip = $self->{NAMES}->{$name}
	  or confess "$self error: IP address not found for name $name";

	$node->{'__VALUE__'} = Farly::IPv4::Network->new("$ip $mask");
}

sub ANY {
	my ( $self, $node ) = @_;
	$node->{'__VALUE__'} = Farly::IPv4::Network->new("0.0.0.0 0.0.0.0");
}

sub DEFAULT_ROUTE {
	my ( $self, $node ) = @_;
	$node->{'__VALUE__'} = Farly::IPv4::Network->new("0.0.0.0 0.0.0.0");
}

sub ICMP_TYPE {
	my ( $self, $node ) = @_;

	my $icmp_type = $node->{'__VALUE__'};

	$node->{'__VALUE__'} = defined( $self->icmp_formatter()->as_integer($icmp_type) )
	  ? Farly::IPv4::ICMPType->new( $self->icmp_formatter()->as_integer($icmp_type) )
	  : Farly::IPv4::ICMPType->new( $icmp_type );
}

sub PROTOCOL {
	my ( $self, $node ) = @_;

	my $protocol = $node->{'__VALUE__'};

	$node->{'__VALUE__'} = defined( $self->protocol_formatter()->as_integer($protocol) )
	  ? Farly::Transport::Protocol->new( $self->protocol_formatter()->as_integer($protocol) )
	  : Farly::Transport::Protocol->new( $protocol );
}

sub PORT_ID {
	my ( $self, $node ) = @_;

	my $port = $node->{'__VALUE__'};

	$node->{'__VALUE__'} = defined( $self->port_formatter()->as_integer($port) )
	  ? Farly::Transport::Port->new( $self->port_formatter()->as_integer($port) )
	  : Farly::Transport::Port->new( $port );
}

sub PORT_RANGE {
	my ( $self, $node ) = @_;

	my $port_range = $node->{'__VALUE__'};

	my ( $low, $high ) = split( /\s+/, $port_range );

	if ( defined $self->port_formatter()->as_integer($low) ) {
		$low = $self->port_formatter()->as_integer($low);
	}
	if ( defined $self->port_formatter()->as_integer($high) ) {
		$high = $self->port_formatter()->as_integer($high);
	}

	$node->{'__VALUE__'} = Farly::Transport::PortRange->new("$low $high");
}

sub PORT_GT {
	my ( $self, $node ) = @_;

	my $port = $node->{'__VALUE__'};

	$node->{'__VALUE__'} = defined( $self->port_formatter()->as_integer($port) )
	  ? Farly::Transport::PortGT->new( $self->port_formatter()->as_integer($port) )
	  : Farly::Transport::PortGT->new( $port );
}

sub PORT_LT {
	my ( $self, $node ) = @_;

	my $port = $node->{'__VALUE__'};

	$node->{'__VALUE__'} = defined( $self->port_formatter()->as_integer($port) )
	  ? Farly::Transport::PortLT->new( $self->port_formatter()->as_integer($port) )
	  : Farly::Transport::PortLT->new( $port );
}

sub _new_ObjectRef {
	my ( $self, $token_type, $value ) = @_;

	my $entry = $Entry_Map->{$token_type}
	  or confess "No token type to ENTRY mapping for token $token_type\n";

	my $ce = Object::KVC::HashRef->new();

	$ce->set( 'ENTRY', Object::KVC::String->new($entry) );
	$ce->set( 'ID',    Object::KVC::String->new($value) );

	return $ce;
}

sub AUTOLOAD {
	my ( $self, $node ) = @_;

	my $type = ref($self) or confess "$self is not an object";

	confess "tree node for $type required"
	  unless defined($node);

	my $token_type = ref($node);

	my $class = $Token_Class_Map->{$token_type}
	  or confess "$self error: class not found for $token_type\n";

	my $value;
	defined( $node->{'__VALUE__'} ) 
	  ? $value = $node->{'__VALUE__'}
	  : confess "$self error: value not found in node $token_type\n";

	my $object;
	if ( $class eq 'Object::KVC::HashRef' ) {

		#need to set 'ENTRY' and 'ID' properties
		$object = $self->_new_ObjectRef( $token_type, $value );
	}
	else {

		#create the object right away
		$object = $class->new($value);
	}

	$node->{'__VALUE__'} = $object;
}

sub DESTROY { }

1;
__END__

=head1 NAME

Farly::ASA::Annotator - Turn Token values into objects

=head1 DESCRIPTION

Farly::ASA::Annotator walks the Parse::RecDescent <autotree> parse tree
searching for Token objects. Token objects are recognized by the presence
of the '__VALUE__' key (see <autotree>). Farly::ASA::Annotator then
converts Token object values into objects of a suitable class based on
the class of the Token object. The value associated with the '__VALUE__'
key is replaced with the new object.

Farly::ASA::Annotator dies on error.

Farly::ASA::Annotator is used by the Farly::ASA::Builder only.

=head1 COPYRIGHT AND LICENCE

Farly::ASA::Annotator
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
