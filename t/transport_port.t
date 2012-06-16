use strict;
use warnings;

use Test::Simple tests => 16;

use Farly::Transport::Port;
use Farly::Transport::PortRange;

my $p1 = Farly::Transport::Port->new("80");
my $p2 = Farly::Transport::Port->new("80");
my $p3 = Farly::Transport::Port->new("443");
my $p4 = Farly::Transport::Port->new("5060");

eval { my $p5 = Farly::Transport::Port->new("www"); };

ok ( $@ =~ /invalid port/, "invalid port www");

eval { my $p5 = Farly::Transport::Port->new(100000); };

ok ( $@ =~ /invalid port/, "invalid port 100000");

my $portRange1 = Farly::Transport::PortRange->new("1-1024");
my $portRange2 = Farly::Transport::PortRange->new("1-1024");
my $portRange3 = Farly::Transport::PortRange->new("1024 65535");
my $portRange4 = Farly::Transport::PortRange->new("16384 32768");
my $portRange5 = Farly::Transport::PortRange->new("10000 20000");

ok ( $portRange4->intersects($portRange3), "intersects 1");
ok ( $portRange4->intersects($portRange3), "intersects 2");
ok ( $portRange2->intersects($portRange3), "intersects 3");

#Ports
ok( $p1->equals($p2), "equals port port" );

ok( !$p1->equals($p3), "!equals port port" );

ok( $p2->contains($p1), "contains port port" );

ok ( $p1->as_string() eq "80", "as_string");

ok ( $portRange1->contains($p1), "range contains port");

ok ( !$portRange3->contains($p1), "! range contains port");

ok ( $portRange1->equals($portRange2), "range equals range");

ok ( $portRange3->contains($portRange4), "range contains range");

ok ( !$portRange4->contains($portRange3), "range not contains range");

ok( $p2->intersects($p1), "intersects" );

ok( ! $p1->intersects($p3), "!intersects" );
