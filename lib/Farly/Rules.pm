package Farly::Rules;

use 5.008008;
use strict;
use warnings;
use Carp;
use Data::Dumper;
use Log::Log4perl qw(get_logger);

our $VERSION = '0.05';

sub new {
	my ( $class, $fw ) = @_;

	confess "configuration container object required"
	  unless ( defined($fw) );

	confess "Object::KVC::List object required"
	  unless ( $fw->isa("Object::KVC::List") );

	my $self = {
		CONFIG => $fw,
		INDEX  => undef,
	};

	bless $self, $class;

	my $logger = get_logger(__PACKAGE__);
	$logger->info("$self NEW");
	$logger->info( "$self CONFIG ", $self->{CONFIG} );

	$self->_make_index();

	return $self;
}

sub config {
	return $_[0]->{CONFIG};
}

sub _make_index {
	my ($self) = @_;

	my $logger = get_logger(__PACKAGE__);

	foreach my $object ( $self->config()->iter() ) {
		if (   $object->has_defined("ENTRY")
			&& $object->has_defined("ID") )
		{
			if ( !$object->get("ID")->isa('Object::KVC::Hash') ) {
				my $entry = $object->get("ENTRY")->as_string();
				my $id    = $object->get("ID")->as_string();
				if ( !defined $self->{INDEX}->{$entry}->{$id} ) {
					$self->{INDEX}->{$entry}->{$id} = Object::KVC::Set->new();
				}
				my $set = $self->{INDEX}->{$entry}->{$id};
				$set->add($object);
			}
		}
		else {
			# 'ENTRY' and 'ID' properties are required
			$logger->error( "invalid object found ", Dumper($object) );
		}
	}

	#print Dumper( $self->{INDEX} );
}

sub _set_default_ports {
	my ( $self, $ce ) = @_;

	my $logger = get_logger(__PACKAGE__);

	my $RULE = Object::KVC::Hash->new();
	$RULE->set( "ENTRY", Object::KVC::String->new("RULE") );

	my $IP  = Farly::Transport::Protocol->new("0");
	my $TCP = Farly::Transport::Protocol->new("6");
	my $UDP = Farly::Transport::Protocol->new("17");

	#Check if the config entry is an access-list
	if ( $ce->matches($RULE) ) {

		return if ( $ce->has_defined("COMMENT") );

		#Check if the access-list protocol is ip, tcp or udp
		if (   $ce->get("PROTOCOL")->equals($IP)
			|| $ce->get("PROTOCOL")->equals($TCP)
			|| $ce->get("PROTOCOL")->equals($UDP) )
		{

			$logger->debug("defaulting ports for $ce");

			#if a srcport is not defined, define all ports
			if ( !$ce->has_defined("SRC_PORT") ) {

				$ce->set( "SRC_PORT", Farly::Transport::PortRange->new( 1, 65535 ) );
				$logger->debug( "SET SOURCE PORT ", $ce->get("SRC_PORT") );
			}

			#if a dst port is not defined, define all ports
			if ( !$ce->has_defined("DST_PORT") ) {

				$ce->set( "DST_PORT", Farly::Transport::PortRange->new( 1, 65535 ) );
				$logger->debug( "SET DST PORT ", $ce->get("DST_PORT") );
			}
		}
	}
	else {
		confess "_set_default_ports is for RULE objects only, not for ", Dumper($ce);
	}
}

# Given an ::ObjectRef, return the set of actual objects.
# The actual objects may contain references.
sub _get_actual {
	my ( $self, $ce ) = @_;

	my $logger = get_logger(__PACKAGE__);
	$logger->debug( "get_actual for : ", $ce->dump() );

	if ( defined $self->{INDEX} ) {

		my $entry = $ce->get("ENTRY")->as_string()
		  or confess "'ENTRY' not found for ", $ce->dump();

		my $id = $ce->get("ID")->as_string()
		  or confess "'ID' not found for ", $ce->dump();

		my $result = $self->{INDEX}->{$entry}->{$id};

		$logger->debug( "actual set : $result : ", $result->as_string() );

		return $result;
	}
	else {
		my $result = Object::KVC::Set->new();

		$self->config()->matches( $ce, $result );

		if ( $result->size() == 0 ) {
			$logger->error( "$self Error failed to find 
			  actual configuration entry for\n", $ce->dump() );
			return undef;
		}

		$logger->debug( "actual set : $result : ", $result->as_string() );

		return $result;    #->first();
	}
}

sub expand_all {
	my ($self) = @_;
	my $logger = get_logger(__PACKAGE__);

	my $expanded = Object::KVC::List->new();

	my $RULE = Object::KVC::String->new("RULE");

	my $RULE_SEARCH = Object::KVC::Hash->new();
	$RULE_SEARCH->set( "ENTRY", $RULE );

	my $rules = Object::KVC::List->new();

	$self->config()->matches( $RULE_SEARCH, $rules );

	foreach my $ce ( $rules->iter() ) {
		eval {
			#$logger->debug( "expanding ", $ce->get("ID")->as_string() );
			my $clone = $ce->clone();
			$self->_expand( $clone, $expanded );
		};
		if ($@) {
			confess "$@ \n expand failed for ", $ce->dump(), "\n";
		}
	}

	return $expanded;
}

# { 'key' => ::HashRef } refers to one or more actual Objects
#   Replace the ::HashRef with a ::Set of the actual objects
#   the actual objects might hold a ::HashRef
# { 'key' => ::Set } is a list of config ::Hash or ::HashRef's.
#   For every object in the Set clone the RULE object
#   and replace the RULE value with the object from the ::Set
# { 'key' => Object::KVC::Hash or Farly::IPv4 or Farly::Transport }
#   use "OBJECT" key/value in the raw RULE object

sub _expand {
	my ( $self, $rule, $result ) = @_;
	my $logger = get_logger(__PACKAGE__);

	my $is_expanded;
	my @stack;
	push @stack, $rule;

	my $COMMENT = Object::KVC::Hash->new();
	$COMMENT->set( "OBJECT_TYPE", Object::KVC::String->new("COMMENT") );

	my $SERVICE = Object::KVC::Hash->new();
	$SERVICE->set( "OBJECT_TYPE", Object::KVC::String->new("SERVICE") );

	my $VIP = Object::KVC::Hash->new();
	$VIP->set( "OBJECT_TYPE", Object::KVC::String->new("VIP") );

	#my $TCPUDP = Object::KVC::Hash->new();
	#$TCPUDP->set( "ENTRY", Object::KVC::String->new("GROUP") );
	#$TCPUDP->set( "GROUP_PROTOCOL", Object::KVC::String->new("tcp-udp") );

	while (@stack) {
		my $ce = pop @stack;

		foreach my $key ( $ce->get_keys() ) {

			my $value = $ce->get($key);

			$logger->debug("entry $ce - key : $key - value : $value");

			$is_expanded = 1;

			if ( $value->isa("Object::KVC::HashRef") ) {
				$is_expanded = 0;

				my $actual = $self->_get_actual($value);

				last if ( !defined($actual) );

				#print "key $key actual $actual\n";
				$ce->set( $key, $actual );

				push @stack, $ce;
				last;
			}
			elsif ( $value->isa("Object::KVC::Set") ) {
				$is_expanded = 0;

				$logger->debug("$ce => $key isa $value");

				foreach my $object ( $value->iter() ) {

					my $clone = $ce->clone();

					$clone->set( $key, $object );

					push @stack, $clone;
				}
				last;
			}
			elsif ( $value->isa("Object::KVC::Hash") ) {

				$is_expanded = 0;

				my $clone = $ce->clone();

				#GROUP_PROTOCOL "tcp-udp"?

				if ( $value->matches($COMMENT) ) {
					$logger->debug( "skipped group comment :\n", $ce->dump(), "\n" );
					last;
				}
				if ( $value->matches($VIP) ) {

					$self->_expand_vip( $key, $clone, $value );
				}
				elsif ( $value->matches($SERVICE) ) {
					$self->_expand_service( $clone, $value );
				}
				elsif ( $value->has_defined("OBJECT") ) {
					$clone->set( $key, $value->get("OBJECT") );
				}
				else {
					$logger->warn( "object $value :\n", $value->dump(), "has no OBJECT\n" );
					$logger->warn( "skipped $ce :\n", $ce->dump(), "\n" );
					last;
				}

				#print $clone->dump(),"\n";
				push @stack, $clone;
				last;
			}
		}

		if ($is_expanded) {
			$self->_set_default_ports($ce);
			$result->add($ce);
		}

		#print "stack ",scalar(@stack)," result ",$result->size(),"\n";
	}

	#print "returning ",$result->size()," expanded rules\n";
	return $result;
}

sub _expand_service {
	my ( $self, $clone, $service_object ) = @_;
	my @keys = qw(PROTOCOL SRC_PORT DST_PORT ICMP_TYPE);
	foreach my $key (@keys) {
		if ( $service_object->has_defined($key) ) {
			$clone->set( $key, $service_object->get($key) );
		}
	}
	return;
}

sub _expand_vip {
	my ( $self, $key, $clone, $vip_object ) = @_;

	my $logger = get_logger(__PACKAGE__);
	$logger->debug("processing VIP, $vip_object - key : $key");

	if ( $key eq "DST_IP" ) {
		$clone->set( $key, $vip_object->get("REAL_IP") );
	}
	elsif ( $key eq "DST_PORT" ) {
		$clone->set( $key, $vip_object->get("REAL_PORT") );
	}
	else {
		confess "invalid key for VIP\n", "key $key \n", $clone->dump(), "\n",
		  $vip_object->dump(), "\n";
	}

	return;
}

1;

__END__

=head1 NAME

Farly::Rules - Convert a firewall rule configuration into a raw rule set

=head1 DESCRIPTION

Farly::Rules converts a firewall rule configuration into a raw rule set.
The raw ruleset is an Object::KVC::List<Object::KVC::Hash> containing
all firewall rules.  

A raw rule set has no references to other firewall objects.  The expanded 
firewall rule is for specific packet to firewall rule matching.

=head1 METHODS

=head2 new()

The constructor. The firewall configuration is provided.

  $rule_expander = Farly::Rules->new( <Object::KVC::List> );

=head2 expand_all()

Returns an Object::KVC::List<Object::KVC::Hash> container of all
raw expanded firewall rules in the current Farly firewall model.

  $expanded_ruleset = $rule_expander->expand_all();

=head1 COPYRIGHT AND LICENCE

Farly::Rules
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