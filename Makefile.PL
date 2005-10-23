use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'    => 'Sniffer::HTTP',
    'VERSION_FROM'  => 'lib/Sniffer/HTTP.pm', # finds $VERSION
    'PREREQ_PM'    => { 'Class::Accessor' => 0,
                        'Class::Data::Inheritable' => 0,
                        'HTTP::Request'   => 0,
                        'NetPacket::TCP'  => 0,
                      }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'lib/Sniffer/HTTP.pm', # retrieve abstract from module
       AUTHOR     => 'Max Maischein <corion@cpan.org>') : ()),
);

1;
