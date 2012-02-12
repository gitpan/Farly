use 5.008008;
use ExtUtils::MakeMaker;

my %prereq = ();
$prereq{'UNIVERSAL::DOES'} = 0.004 if !defined &UNIVERSAL::DOES;

WriteMakefile(
    NAME              => 'Farly',
    VERSION_FROM      => 'lib/Farly.pm',
    PREREQ_PM         => {
		%prereq,
    		'Object::KVC'       => 0.01,
    		'Parse::RecDescent' => 1.965001,
    		'Log::Log4perl'     => 1.35,
    		'Template'          => 2.22,	
    },
    ($] >= 5.005 ?
      (ABSTRACT  => 'Farly - Firewall Analysis and Rewrite LibrarY',
       AUTHOR    => 'Trystan Johnson') : ()),
);
