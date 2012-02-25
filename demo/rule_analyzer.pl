=b
LICENSE

Farly/demo/rule_analyzer.pl
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


REFERENCES

Qian, J., Hinrichs, S., Nahrstedt K. ACLA: A Framework for Access
Control List (ACL) Analysis and Optimization, Communications and 
Multimedia Security, 2001

=cut

use strict;
use warnings;
use Carp;
use Farly;
use Farly::Rules;
use Farly::ASA::Template;

my $file = "../t/test.cfg";
my $rule_id = "outside-in";

my $importer  = Farly->new();
my $container = $importer->process( "ASA", $file );

my $rule_expander  = Farly::Rules->new($container);
my $expanded_rules = $rule_expander->expand_all();

my $list_permits = Object::KVC::List->new();
my $list_denys   = Object::KVC::List->new();

do_search( $expanded_rules, $rule_id, $list_permits, $list_denys );

my $n = $list_permits->size() + $list_denys->size();
	
print "Optimizing $n $rule_id ip, tcp, udp rules...\n";
my $start = [ Time::HiRes::gettimeofday() ];

my $fixed_rules = optimize( $list_permits, $list_denys );

my $elapsed = Time::HiRes::tv_interval($start);
print "\nOptimize time: $elapsed seconds\n";

=b
my $template = Farly::ASA::Template->new();
foreach my $rule ( sort ascending_LINE $fixed_rules->iter() ) {
	$template->as_string($rule);
	print "\n";
} 
=cut

# store all 'permt ip' and 'permit tcp/udp' in $permits
# store all 'deny ip' and 'deny tcp/udp' in $denies
sub do_search {
	my ( $rules, $id, $permits, $denies ) = @_;

	my $search = Object::KVC::Hash->new();
	$search->set( "ID",       Object::KVC::String->new($id) );
	$search->set( "ACTION",   Object::KVC::String->new("permit") );
	$search->set( "PROTOCOL", Farly::Transport::Protocol->new(0) );

	$rules->matches( $search, $permits );

	# get permit tcp rules
	$search->set( "PROTOCOL", Farly::Transport::Protocol->new(6) );

	$rules->matches( $search, $permits );

	# get permit udp rules
	$search->set( "PROTOCOL", Farly::Transport::Protocol->new(17) );

	$rules->matches( $search, $permits );

	# get deny ip rules
	$search->set( "ACTION",   Object::KVC::String->new("deny") );
	$search->set( "PROTOCOL", Farly::Transport::Protocol->new(0) );

	$rules->matches( $search, $denies );

	# get deny tcp rules
	$search->set( "PROTOCOL", Farly::Transport::Protocol->new(6) );

	$rules->matches( $search, $denies );

	# get deny udp rules
	$search->set( "PROTOCOL", Farly::Transport::Protocol->new(17) );

	$rules->matches( $search, $denies );
}

# sort rules in ascending order by line number
sub ascending_LINE {
	$a->get("LINE")->number() <=> $b->get("LINE")->number();
}

# sort rules in ascending order so that current can contain next
# but next can't contain current
sub ascending {
	     $a->get("DST_IP")->first() <=> $b->get("DST_IP")->first()
	  || $b->get("DST_IP")->last() <=> $a->get("DST_IP")->last()
	  || $a->get("SRC_IP")->first() <=> $b->get("SRC_IP")->first()
	  || $b->get("SRC_IP")->last() <=> $a->get("SRC_IP")->last()
	  || $a->get("DST_PORT")->first() <=> $b->get("DST_PORT")->first()
	  || $b->get("DST_PORT")->last() <=> $a->get("DST_PORT")->last()
	  || $a->get("SRC_PORT")->first() <=> $b->get("SRC_PORT")->first()
	  || $b->get("SRC_PORT")->last() <=> $a->get("SRC_PORT")->last()
	  || $a->get("PROTOCOL")->protocol() <=> $b->get("PROTOCOL")->protocol();
}

sub five_tuple {
	my ($rule) = @_;

	my $r = Object::KVC::Hash->new();

	my @rule_properties = qw(PROTOCOL SRC_IP SRC_PORT DST_IP DST_PORT);

	foreach my $property (@rule_properties) {
		if ( $rule->has_defined($property) ) {
			$r->set( $property, $rule->get($property) );
		}
		else {
			warn "property $property not defined in ", $rule->dump(), "\n";
		}
	}

	return $r;
}

# Given rule X, Y, where X precedes Y in the ACL
# X and Y are inconsistent if:
# Xp contains Yd
# Xd contains Yp

sub inconsistent {
	my ( $s_a, $s_an ) = @_;

	# $s_a = ARRAY ref of rules of action a
	# $s_an = ARRAY ref of rules of action !a
	# $s_a and $s_an are sorted by line number and must be readonly

	# hash of rule indexes to keep or remove
	my %remove;

	my $rule_x;
	my $rule_y;

	# iterate over rules of action a
	for ( my $x = 0 ; $x != scalar( @{$s_a} ) ; $x++ ) {

		$rule_x = $s_a->[$x];

		# iterate over rules of action !a
		for ( my $y = 0 ; $y != scalar( @{$s_an} ) ; $y++ ) {

			#skip check if rule_y is already removed
			next if $remove{$y};

			$rule_y = $s_an->[$y];

			# if $rule_x comes before $rule_y in the rule set
			# then check if $rule_x contains $rule_y

			if ( $rule_x->get('LINE')->number() <= $rule_y->get('LINE')->number() )
			{

				# $rule_x1 is rule_x with layer 3 and 4 properties only
				my $rule_x1 = five_tuple($rule_x);

				if ( $rule_y->contained_by($rule_x1) ) {
					# note removal of rule_y and the
					# rule_x which caused the inconsistency
					$remove{$y} = $rule_x;
				}
			}
		}
	}

	# list of action !a rules to be removed
	return %remove;
}

# Given rule X, Y, where X precedes Y in the ACL
# if Yp containS Xp and there does not exist rule Zd between
# Xp and Yp such that Zd intersect Xp and Xp !contains Zd

sub can_remove {
	my ( $rule_x, $rule_y, $s_an ) = @_;
	# $rule_x = the rule contained by $rule_y
	# $s_an = rules of action !a sorted by ascending DST_IP

	# $rule_x1 is rule_x with layer 3 and 4 properties only
	my $rule_x1 = five_tuple($rule_x);

	foreach my $rule_z ( @{$s_an} ) {

		if ( !$rule_z->get("DST_IP")->gt( $rule_x1->get("DST_IP") ) ) {

			#is Z between X and Y?
			if ( ( $rule_z->get('LINE')->number() >= $rule_x->get('LINE')->number() )
			  && ( $rule_z->get('LINE')->number() <= $rule_y->get('LINE')->number() ) )
			{

				# Zd intersect Xp?
				if ( $rule_z->intersects($rule_x1) ) {

					# Xp ! contain Zd
					if ( !$rule_z->contained_by($rule_x1) ) {
						return undef;
					}
				}
			}
		}
		else {
			# $rule_z is greater than $rule_x1 therefore rule_x and rule_z are disjoint
			last;
		}
	}

	return 1;
}

# Given rule X, Y, where X precedes Y in the ACL
# a is the action type of the rule
# if X contains Y then Y can be removed
# if Y contains X then X can be removed if there are no rules Z
# in $s_an that intersect X and exist between X and Y in the ACL

sub redundant {
	my ( $s_a, $s_an ) = @_;
	# $s_a = ARRAY ref of rules of action a to be validated
	# $s_an = ARRAY ref of rules of action !a
	# $s_a and $s_an are sorted by ascending and must be readonly

	# hash of rules to keep or remove
	my %remove;

	# iterate over rules of action a
	for ( my $x = 0 ; $x != scalar( @{$s_a} ) ; $x++ ) {

		#skip check if rule_y is already removed
		next if $remove{$x};

		# $rule_x1 is rule_x with layer 3 and 4 properties only
		my $rule_x = $s_a->[$x];

		# remove non layer 3/4 rule properties
		my $rule_x1 = five_tuple( $s_a->[$x] );

		for ( my $y = $x + 1 ; $y != scalar( @{$s_a} ) ; $y++ ) {

			my $rule_y = $s_a->[$y];

			if ( !$rule_y->get("DST_IP")->gt( $rule_x->get("DST_IP") ) ) {

				# $rule_x comes before rule_y in the rule array
				# therefore x might contain y
				
				if ( $rule_y->contained_by($rule_x1) ) {

					# rule_x is before rule_y in the rule set so remove rule_y
					if ( $rule_x->get('LINE')->number() <= $rule_y->get('LINE')->number() )
					{
						$remove{$y} = $rule_x;
					}
					else {
						# rule_y is actually after rule_x in the rule set
						if ( can_remove( $rule_y, $rule_x, $s_an ) ) {
							$remove{$y} = $rule_x;
						}
					}
				}
			}
			else {
				# rule_y DST_IP is greater than rule_x DST_IP then rule_x can't
				# contain rule_y or any rules after rule_y (they are disjoint)
				last;
			}
		}
	}

	return %remove;
}

# copies rules in @{$a_ref} except for the rules
# whose index exists in remove, which are not copied
sub remove_copy_exists {
	my ( $a_ref, $remove ) = @_;

	my $r = Object::KVC::List->new();

	for ( my $i = 0 ; $i != scalar( @{$a_ref} ) ; $i++ ) {
		if ( !exists( $remove->{$i} ) ) {
			$r->add( $a_ref->[$i] );
		}
	}

	return $r;
}

sub print_remove {
	my ( $keep, $remove ) = @_;
	
	my $template = Farly::ASA::Template->new();

	foreach my $i ( sort keys %$remove ) {
		print "\n ! ";
		$template->as_string( $remove->{$i} );
		print "\n";
		print "no ";
		$template->as_string( $keep->[$i] );
		print "\n";
	}
}


sub optimize {
	my ( $permits, $denies ) = @_;
	my @arr_permits;
	my @arr_denys;

	@arr_permits = sort ascending_LINE $permits->iter();
	@arr_denys   = sort ascending_LINE $denies->iter();

	# remove is a hash with the index number of
	# rules which are to be removed. the value is the
	# rule object causing the redundancy
	my %remove;  # <index, Object::KVC::Hash>

	# find permit rules that contain deny rules
	# that are defined further down in the rule set
	print "\nChecking for deny rule inconsistencies...\n";
	%remove = inconsistent( \@arr_permits, \@arr_denys );

	# create a new list of deny rules which are being kept
	$denies = remove_copy_exists( \@arr_denys, \%remove );
	print_remove( \@arr_denys, \%remove );
	
	# the consistent deny list sorted by LINE again
	@arr_denys = sort ascending_LINE $denies->iter();

	# find deny rules which contain permit
	# rules further down in the rule set
	print "\nChecking for permit rule inconsistencies...\n";
	%remove = inconsistent( \@arr_denys, \@arr_permits );

	# create the list of permit rules which are being kept
	$permits = remove_copy_exists( \@arr_permits, \%remove );
	print_remove( \@arr_permits, \%remove );

	# sort the rule in ascedning order
	@arr_permits = sort ascending $permits->iter();
	@arr_denys   = sort ascending $denies->iter();

	print "\nChecking for permit rule redundancies...\n";
	%remove = redundant( \@arr_permits, \@arr_denys );

	$permits = remove_copy_exists( \@arr_permits, \%remove );
	print_remove( \@arr_permits, \%remove );

	# sort the permits again
	@arr_permits = sort ascending $permits->iter();

	print "\nChecking for deny rule redundancies...\n";
	%remove = redundant( \@arr_denys, \@arr_permits );

	$denies = remove_copy_exists( \@arr_denys, \%remove );
	print_remove( \@arr_denys, \%remove );
	
	# combine the permit and deny rules into the optimized rule set
	foreach my $rule ( $denies->iter() ) {
		$permits->add($rule);
	}

	return $permits;
}
