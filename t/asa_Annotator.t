use strict;
use warnings;

use Data::Dumper;
use Scalar::Util 'blessed';
use Test::Simple tests => 3;

use Log::Log4perl qw(:easy);
Log::Log4perl->easy_init($ERROR);

use Farly::ASA::Builder;
use Farly::ASA::Annotator;

my $annotator = Farly::ASA::Annotator->new();

ok( $annotator->isa('Farly::ASA::Annotator'), "constructor" );

#this is the Data::Dumper dump of the parse tree for
#an access-list
my $named_net = bless(
	{
		'__RULE__' => 'startrule',
		'names'    => bless(
			{
				'NAME'        => bless( { '__VALUE__' => 'intranet' }, 'NAME' ),
				'__RULE__'    => 'names',
				'__STRING1__' => 'name',
				'IPADDRESS'   =>
				  bless( { '__VALUE__' => '10.0.0.0' }, 'IPADDRESS' )
			},
			'names'
		),
		'EOL' => bless( { '__VALUE__' => '' }, 'EOL' )
	},
	'startrule'
);

my $named_host = bless(
	{
		'__RULE__' => 'startrule',
		'names'    => bless(
			{
				'NAME'        => bless( { '__VALUE__' => 'server1' }, 'NAME' ),
				'__RULE__'    => 'names',
				'__STRING1__' => 'name',
				'IPADDRESS'   =>
				  bless( { '__VALUE__' => '192.168.10.1' }, 'IPADDRESS' )
			},
			'names'
		),
		'EOL' => bless( { '__VALUE__' => '' }, 'EOL' )
	},
	'startrule'
);

$annotator->visit($named_net);
$annotator->visit($named_host);

my $named_rule = bless(
	{
		'__RULE__'    => 'startrule',
		'access_list' => bless(
			{
				'acl_id' => bless(
					{
						'acl_action' => bless(
							{
								'__RULE__'     => 'acl_action',
								'acl_protocol' => bless(
									{
										'__RULE__' => 'acl_protocol',
										'PROTOCOL' => bless(
											{ '__VALUE__' => 'ip' }, 'PROTOCOL'
										),
										'acl_src_ip' => bless(
											{
												'__RULE__'   => 'acl_src_ip',
												'acl_dst_ip' => bless(
													{
														'acl_dst_port' => bless(
															{
																'__RULE__' =>
'acl_dst_port',
																'port' => bless(
																	{
'__RULE__'
																		  => 'port',
'port_gt'
																		  => bless
																		  (
																			{
'__RULE__'
																				  =>
'port_gt',
'__STRING1__'
																				  =>
'gt',
'PORT_GT'
																				  =>
																				  bless
																				  (
																					{
'__VALUE__'
																						  =>
'www 65535'
																					}
																					,
'PORT_GT'
																				  )
																			},
'port_gt'
																		  )
																	},
																	'port'
																),
																'acl_options' =>
																  bless(
																	{
'__RULE__'
																		  => 'acl_options',
																		'EOL' =>
																		  bless(
																			{
'__VALUE__'
																				  =>
''
																			},
'EOL'
																		  )
																	},
'acl_options'
																  )
															},
															'acl_dst_port'
														),
														'__RULE__' =>
														  'acl_dst_ip',
														'address' => bless(
															{
																'NAME' => bless(
																	{
'__VALUE__'
																		  => 'server1'
																	},
																	'NAME'
																),
																'__RULE__' =>
																  'address',
																'__STRING1__' =>
																  'host'
															},
															'address'
														)
													},
													'acl_dst_ip'
												),
												'address' => bless(
													{
														'NAMED_NET' => bless(
															{
																'__VALUE__' =>
'intranet 255.0.0.0'
															},
															'NAMED_NET'
														),
														'__RULE__' => 'address'
													},
													'address'
												)
											},
											'acl_src_ip'
										)
									},
									'acl_protocol'
								),
								'ACTIONS' => bless(
									{ '__VALUE__' => 'permit' }, 'ACTIONS'
								)
							},
							'acl_action'
						),
						'__RULE__' => 'acl_id',
						'STRING'   =>
						  bless( { '__VALUE__' => 'acl-outside' }, 'STRING' )
					},
					'acl_id'
				),
				'__RULE__'    => 'access_list',
				'__STRING1__' => 'access-list'
			},
			'access_list'
		),
		'EOL' => bless( { '__VALUE__' => '' }, 'EOL' )
	},
	'startrule'
);

$annotator->visit($named_rule);

my $actual   = visit($named_rule);
my $expected = {
	'acl_action'   => Object::KVC::String->new('permit'),
	'acl_id'       => Object::KVC::String->new('acl-outside'),
	'acl_dst_port' => Farly::Transport::PortRange->new('80 65535'),
	'acl_dst_ip'   => Farly::IPv4::Address->new('192.168.10.1'),
	'acl_protocol' => Farly::Transport::Protocol->new('0'),
	'acl_src_ip'   => Farly::IPv4::Network->new('10.0.0.0 255.0.0.0')
	,
};

ok( equals( $actual, $expected ), "names coverage" );

=b
foreach my $key ( keys %$actual ) {
	print "'$key' => ", ref( $actual->{$key} ), "->new('",
	  $actual->{$key}->as_string(), "');\n";
}

exit;
=cut

my $in = bless(
	{
		'__RULE__'    => 'startrule',
		'access_list' => bless(
			{
				'acl_id' => bless(
					{
						'__RULE__' => 'acl_id',
						'acl_line' => bless(
							{
								'DIGIT' =>
								  bless( { '__VALUE__' => '1' }, 'DIGIT' ),
								'__RULE__'    => 'acl_line',
								'__STRING1__' => 'line',
								'acl_type'    => bless(
									{
										'acl_action' => bless(
											{
												'__RULE__'     => 'acl_action',
												'acl_protocol' => bless(
													{
														'__RULE__' =>
														  'acl_protocol',
														'PROTOCOL' => bless(
															{
																'__VALUE__' =>
																  'tcp'
															},
															'PROTOCOL'
														),
														'acl_src_ip' => bless(
															{
																'acl_src_port'
																  => bless(
																	{
'__RULE__'
																		  => 'acl_src_port',
'acl_dst_ip'
																		  => bless
																		  (
																			{
'acl_dst_port'
																				  =>
																				  bless
																				  (
																					{
'__RULE__'
																						  =>
'acl_dst_port',
'port'
																						  =>
																						  bless
																						  (
																							{
'__RULE__'
																								  =>
'port',
'port_lt'
																								  =>
																								  bless
																								  (
																									{
'__RULE__'
																										  =>
'port_lt',
'PORT_LT'
																										  =>
																										  bless
																										  (
																											{
'__VALUE__'
																												  =>
'1 1024'
																											}
																											,
'PORT_LT'
																										  )
																										,
'__STRING1__'
																										  =>
'lt'
																									}
																									,
'port_lt'
																								  )
																							}
																							,
'port'
																						  )
																						,
'acl_options'
																						  =>
																						  bless
																						  (
																							{
'__RULE__'
																								  =>
'acl_options',
'EOL'
																								  =>
																								  bless
																								  (
																									{
'__VALUE__'
																										  =>
''
																									}
																									,
'EOL'
																								  )
																							}
																							,
'acl_options'
																						  )
																					}
																					,
'acl_dst_port'
																				  )
																				,
'__RULE__'
																				  =>
'acl_dst_ip',
'address_ref'
																				  =>
																				  bless
																				  (
																					{
'__RULE__'
																						  =>
'address_ref',
'__STRING1__'
																						  =>
'OG_NETWORK',
'GROUP_REF'
																						  =>
																						  bless
																						  (
																							{
'__VALUE__'
																								  =>
'citrix'
																							}
																							,
'GROUP_REF'
																						  )
																					}
																					,
'address_ref'
																				  )
																			},
'acl_dst_ip'
																		  ),
																		'port'
																		  => bless
																		  (
																			{
'__RULE__'
																				  =>
'port',
'port_gt'
																				  =>
																				  bless
																				  (
																					{
'__RULE__'
																						  =>
'port_gt',
'__STRING1__'
																						  =>
'gt',
'PORT_GT'
																						  =>
																						  bless
																						  (
																							{
'__VALUE__'
																								  =>
'1024 65535'
																							}
																							,
'PORT_GT'
																						  )
																					}
																					,
'port_gt'
																				  )
																			},
'port'
																		  )
																	},
'acl_src_port'
																  ),
																'__RULE__' =>
																  'acl_src_ip',
																'address' =>
																  bless(
																	{
'__RULE__'
																		  => 'address',
																		'ANY' =>
																		  bless(
																			{
'__VALUE__'
																				  =>
'any'
																			},
'ANY'
																		  )
																	},
																	'address'
																  )
															},
															'acl_src_ip'
														)
													},
													'acl_protocol'
												),
												'ACTIONS' => bless(
													{ '__VALUE__' => 'permit' },
													'ACTIONS'
												)
											},
											'acl_action'
										),
										'__RULE__'  => 'acl_type',
										'ACL_TYPES' => bless(
											{ '__VALUE__' => 'extended' },
											'ACL_TYPES'
										)
									},
									'acl_type'
								)
							},
							'acl_line'
						),
						'STRING' =>
						  bless( { '__VALUE__' => 'acl-outside' }, 'STRING' )
					},
					'acl_id'
				),
				'__RULE__'    => 'access_list',
				'__STRING1__' => 'access-list'
			},
			'access_list'
		),
		'EOL' => bless( { '__VALUE__' => '' }, 'EOL' )
	},
	'startrule'
);

$annotator->visit($in);

$actual = visit($in);

my $GROUP = Object::KVC::HashRef->new();
$GROUP->set( 'ENTRY', Object::KVC::String->new('GROUP') );
$GROUP->set( 'ID',    Object::KVC::String->new('citrix') );

$expected = {
	'acl_dst_ip'   => $GROUP,
	'acl_id'       => Object::KVC::String->new('acl-outside'),
	'acl_action'   => Object::KVC::String->new('permit'),
	'acl_dst_port' => Farly::Transport::PortRange->new('1 1024'),
	'acl_src_port' => Farly::Transport::PortRange->new('1024 65535'),
	'acl_line'     => Object::KVC::String->new('1'),
	'acl_protocol' => Farly::Transport::Protocol->new('6'),
	'acl_src_ip'   => Farly::IPv4::Network->new('0.0.0.0 0.0.0.0'),
	'acl_type'     => Object::KVC::String->new('extended'),
};

ok( equals( $actual, $expected ), "ref and port coverage" );

sub visit {
	my ($node) = @_;

	my $Rule_To_Key_Map = {
		"hostname"                => 1,
		"names"                   => 1,
		"NAME"                    => 1,
		"interface"               => 1,
		"if_name"                 => 1,
		"sec_level"               => 1,
		"if_ip"                   => 1,
		"if_mask"                 => 1,
		"if_standby"              => 1,
		"object"                  => 1,
		"object_id"               => 1,
		"object_network"          => 1,
		"object_service_protocol" => 1,
		"object_service_src"      => 1,
		"object_service_dst"      => 1,
		"object_icmp"             => 1,
		"object_group"            => 1,
		"og_id"                   => 1,
		"og_protocol"             => 1,
		"og_object"               => 1,
		"og_so_protocol"          => 1,
		"og_so_src_port"          => 1,
		"og_so_dst_port"          => 1,
		"acl_action"              => 1,
		"acl_id"                  => 1,
		"acl_line"                => 1,
		"acl_type"                => 1,
		"acl_protocol"            => 1,
		"acl_protocol_group"      => 1,
		"acl_service_group"       => 1,
		"acl_service_object"      => 1,
		"acl_src_ip"              => 1,
		"acl_src_port"            => 1,
		"acl_dst_ip"              => 1,
		"acl_dst_port"            => 1,
		"acl_icmp_type"           => 1,
		"acl_remark"              => 1,
		"ag_id"                   => 1,
		"ag_direction"            => 1,
		"ag_interface"            => 1,
	};

	my $parent_key;
	my $result;

	# set s of explored vertices
	my %seen;

	#stack is all neighbors of s
	my @stack;
	push @stack, [ $node, $parent_key ];

	my $key;

	while (@stack) {

		my $rec = pop @stack;

		$node       = $rec->[0];
		$parent_key = $rec->[1];    #undef for root

		next if ( $seen{$node}++ );

		my $rule_id = ref($node);

		if ( exists( $Rule_To_Key_Map->{$rule_id} ) ) {
			$parent_key = $rule_id;
		}

		foreach my $key ( keys %$node ) {

			next if ( $key eq "EOL" );

			my $next = $node->{$key};

			if ( blessed($next) ) {

				if ( exists( $next->{__VALUE__} ) ) {

			   #print ref($node), " ", ref($next), " ", $next->{__VALUE__},"\n";
					my $rule  = ref($node);
					my $token = $next->{__VALUE__};
					$result->{$parent_key} = $token;

					#print $parent_key," ",$result->{$parent_key},"\n";
					#print $rule, " ", $result->{$rule}, "\n";
				}

				push @stack, [ $next, $parent_key ];

				#push @stack, $next;
			}
		}
	}

	return $result;
}

sub equals {
	my ( $hash1, $hash2 ) = @_;

	if ( scalar( keys %$hash1 ) != scalar( keys %$hash2 ) ) {
		return undef;
	}

	foreach my $key ( keys %$hash2 ) {
		if ( !defined( $hash1->{$key} ) ) {
			return undef;
		}
		if ( !$hash1->{$key}->equals( $hash2->{$key} ) ) {
			return undef;
		}
	}
	return 1;
}

