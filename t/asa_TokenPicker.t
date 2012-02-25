use strict;
use warnings;

use Data::Dumper;
use Scalar::Util 'blessed';
use Test::Simple tests => 2;

use Log::Log4perl qw(:easy);
Log::Log4perl->easy_init($ERROR);

use Farly;
use Farly::ASA::Builder;
use Farly::ASA::TokenPicker;

my $picker = Farly::ASA::TokenPicker->new();
ok( $picker->isa('Farly::ASA::TokenPicker'), "constructor" );

my $rule = bless( {
                 '__RULE__' => 'startrule',
                 'access_list' => bless( {
                                           'acl_id' => bless( {
                                                                '__RULE__' => 'acl_id',
                                                                'acl_line' => bless( {
                                                                                       '__RULE__' => 'acl_line',
                                                                                       'DIGIT' => bless( {
                                                                                                           '__VALUE__' => bless( {
                                                                                                                                   'STRING' => '1'
                                                                                                                                 }, 'Object::KVC::String' )
                                                                                                         }, 'DIGIT' ),
                                                                                       '__STRING1__' => 'line',
                                                                                       'acl_type' => bless( {
                                                                                                              'acl_action' => bless( {
                                                                                                                                       '__RULE__' => 'acl_action',
                                                                                                                                       'ACTIONS' => bless( {
                                                                                                                                                             '__VALUE__' => bless( {
                                                                                                                                                                                     'STRING' => 'permit'
                                                                                                                                                                                   }, 'Object::KVC::String' )
                                                                                                                                                           }, 'ACTIONS' ),
                                                                                                                                       'acl_protocol' => bless( {
                                                                                                                                                                  '__RULE__' => 'acl_protocol',
                                                                                                                                                                  'PROTOCOL' => bless( {
                                                                                                                                                                                         '__VALUE__' => bless( {
                                                                                                                                                                                                                 'PROTOCOL' => 6
                                                                                                                                                                                                               }, 'Farly::Transport::Protocol' )
                                                                                                                                                                                       }, 'PROTOCOL' ),
                                                                                                                                                                  'acl_src_ip' => bless( {
                                                                                                                                                                                           '__RULE__' => 'acl_src_ip',
                                                                                                                                                                                           'acl_src_port' => bless( {
                                                                                                                                                                                                                      '__RULE__' => 'acl_src_port',
                                                                                                                                                                                                                      'acl_dst_ip' => bless( {
                                                                                                                                                                                                                                               '__RULE__' => 'acl_dst_ip',
                                                                                                                                                                                                                                               'acl_dst_port' => bless( {
                                                                                                                                                                                                                                                                          '__RULE__' => 'acl_dst_port',
                                                                                                                                                                                                                                                                          'port' => bless( {
                                                                                                                                                                                                                                                                                             '__RULE__' => 'port',
                                                                                                                                                                                                                                                                                             'port_lt' => bless( {
                                                                                                                                                                                                                                                                                                                   '__RULE__' => 'port_lt',
                                                                                                                                                                                                                                                                                                                   'PORT_LT' => bless( {
                                                                                                                                                                                                                                                                                                                                         '__VALUE__' => bless( {
                                                                                                                                                                                                                                                                                                                                                                 'LOW' => bless( {
                                                                                                                                                                                                                                                                                                                                                                                   'PORT' => 1
                                                                                                                                                                                                                                                                                                                                                                                 }, 'Farly::Transport::Port' ),
                                                                                                                                                                                                                                                                                                                                                                 'HIGH' => bless( {
                                                                                                                                                                                                                                                                                                                                                                                    'PORT' => 1024
                                                                                                                                                                                                                                                                                                                                                                                  }, 'Farly::Transport::Port' )
                                                                                                                                                                                                                                                                                                                                                               }, 'Farly::Transport::PortRange' )
                                                                                                                                                                                                                                                                                                                                       }, 'PORT_LT' ),
                                                                                                                                                                                                                                                                                                                   '__STRING1__' => 'lt'
                                                                                                                                                                                                                                                                                                                 }, 'port_lt' )
                                                                                                                                                                                                                                                                                           }, 'port' ),
                                                                                                                                                                                                                                                                          'acl_options' => bless( {
                                                                                                                                                                                                                                                                                                    '__RULE__' => 'acl_options',
                                                                                                                                                                                                                                                                                                    'EOL' => bless( {
                                                                                                                                                                                                                                                                                                                      '__VALUE__' => ''
                                                                                                                                                                                                                                                                                                                    }, 'EOL' )
                                                                                                                                                                                                                                                                                                  }, 'acl_options' )
                                                                                                                                                                                                                                                                        }, 'acl_dst_port' ),
                                                                                                                                                                                                                                               'address_ref' => bless( {
                                                                                                                                                                                                                                                                         '__RULE__' => 'address_ref',
                                                                                                                                                                                                                                                                         '__STRING1__' => 'OG_NETWORK',
                                                                                                                                                                                                                                                                         'GROUP_REF' => bless( {
                                                                                                                                                                                                                                                                                                 '__VALUE__' => bless( {
                                                                                                                                                                                                                                                                                                                         'ID' => bless( {
                                                                                                                                                                                                                                                                                                                                          'STRING' => 'citrix'
                                                                                                                                                                                                                                                                                                                                        }, 'Object::KVC::String' ),
                                                                                                                                                                                                                                                                                                                         'ENTRY' => bless( {
                                                                                                                                                                                                                                                                                                                                             'STRING' => 'GROUP'
                                                                                                                                                                                                                                                                                                                                           }, 'Object::KVC::String' )
                                                                                                                                                                                                                                                                                                                       }, 'Object::KVC::HashRef' )
                                                                                                                                                                                                                                                                                               }, 'GROUP_REF' )
                                                                                                                                                                                                                                                                       }, 'address_ref' )
                                                                                                                                                                                                                                             }, 'acl_dst_ip' ),
                                                                                                                                                                                                                      'port' => bless( {
                                                                                                                                                                                                                                         '__RULE__' => 'port',
                                                                                                                                                                                                                                         'port_gt' => bless( {
                                                                                                                                                                                                                                                               '__RULE__' => 'port_gt',
                                                                                                                                                                                                                                                               '__STRING1__' => 'gt',
                                                                                                                                                                                                                                                               'PORT_GT' => bless( {
                                                                                                                                                                                                                                                                                     '__VALUE__' => bless( {
                                                                                                                                                                                                                                                                                                             'LOW' => bless( {
                                                                                                                                                                                                                                                                                                                               'PORT' => 1024
                                                                                                                                                                                                                                                                                                                             }, 'Farly::Transport::Port' ),
                                                                                                                                                                                                                                                                                                             'HIGH' => bless( {
                                                                                                                                                                                                                                                                                                                                'PORT' => 65535
                                                                                                                                                                                                                                                                                                                              }, 'Farly::Transport::Port' )
                                                                                                                                                                                                                                                                                                           }, 'Farly::Transport::PortRange' )
                                                                                                                                                                                                                                                                                   }, 'PORT_GT' )
                                                                                                                                                                                                                                                             }, 'port_gt' )
                                                                                                                                                                                                                                       }, 'port' )
                                                                                                                                                                                                                    }, 'acl_src_port' ),
                                                                                                                                                                                           'address' => bless( {
                                                                                                                                                                                                                 '__RULE__' => 'address',
                                                                                                                                                                                                                 'ANY' => bless( {
                                                                                                                                                                                                                                   '__VALUE__' => bless( {
                                                                                                                                                                                                                                                           'NETWORK' => bless( {
                                                                                                                                                                                                                                                                                 'ADDRESS' => pack("N",0)
                                                                                                                                                                                                                                                                               }, 'Farly::IPv4::Address' ),
                                                                                                                                                                                                                                                           'MASK' => bless( {
                                                                                                                                                                                                                                                                              'ADDRESS' => pack("N",0)
                                                                                                                                                                                                                                                                            }, 'Farly::IPv4::Address' )
                                                                                                                                                                                                                                                         }, 'Farly::IPv4::Network' )
                                                                                                                                                                                                                                 }, 'ANY' )
                                                                                                                                                                                                               }, 'address' )
                                                                                                                                                                                         }, 'acl_src_ip' )
                                                                                                                                                                }, 'acl_protocol' )
                                                                                                                                     }, 'acl_action' ),
                                                                                                              '__RULE__' => 'acl_type',
                                                                                                              'ACL_TYPES' => bless( {
                                                                                                                                      '__VALUE__' => bless( {
                                                                                                                                                              'STRING' => 'extended'
                                                                                                                                                            }, 'Object::KVC::String' )
                                                                                                                                    }, 'ACL_TYPES' )
                                                                                                            }, 'acl_type' )
                                                                                     }, 'acl_line' ),
                                                                'STRING' => bless( {
                                                                                     '__VALUE__' => bless( {
                                                                                                             'STRING' => 'acl-outside'
                                                                                                           }, 'Object::KVC::String' )
                                                                                   }, 'STRING' )
                                                              }, 'acl_id' ),
                                           '__RULE__' => 'access_list',
                                           '__STRING1__' => 'access-list'
                                         }, 'access_list' ),
                 'EOL' => bless( {
                                   '__VALUE__' => ''
                                 }, 'EOL' )
               }, 'startrule' );
               
$picker->visit($rule);

my $container = $picker->container();

my $DST = Object::KVC::HashRef->new();
$DST->set( "ENTRY", Object::KVC::String->new("GROUP") );
$DST->set( "ID", Object::KVC::String->new("citrix") );

my $expected = Object::KVC::Hash->new();

$expected->set("ID", Object::KVC::String->new("acl-outside") );
$expected->set("DST_IP", $DST );
$expected->set("PROTOCOL", Farly::Transport::Protocol->new("6") );
$expected->set("TYPE", Object::KVC::String->new("extended") );
$expected->set("SRC_PORT", Farly::Transport::PortRange->new("1024 65535") );
$expected->set("DST_PORT", Farly::Transport::PortRange->new("1 1024") );
$expected->set("ACTION", Object::KVC::String->new("permit") );
$expected->set("ENTRY", Object::KVC::String->new("RULE") );
$expected->set("SRC_IP", Farly::IPv4::Network->new("0.0.0.0 0.0.0.0") );
$expected->set("LINE", Object::KVC::String->new("1") );

my @arr = $container->iter();

ok( $arr[0]->equals($expected), "equals");