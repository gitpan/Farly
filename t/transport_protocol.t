use strict;
use warnings;

use Test::Simple tests => 8;

use Farly::Transport::Protocol;

my $ip = Farly::Transport::Protocol->new("0");
my $p1 = Farly::Transport::Protocol->new("6");
my $p2 = Farly::Transport::Protocol->new("17");
my $p3 = Farly::Transport::Protocol->new("17");


ok( $ip->contains($p2), "ip contains" );

ok( !$p1->contains($p2), "!contains" );

ok( $p2->contains($p3), "contains" );

ok( !$p1->equals($p2), "!equals" );

ok( $p2->equals($p3), "equals" );

ok( $p2->intersects($ip), "intersects" );

ok( $p2->intersects($p3), "intersects" );

ok( ! $p1->intersects($p2), "!intersects" );