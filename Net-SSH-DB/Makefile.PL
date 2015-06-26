
# Net::SSH::DB Makefile.PL
# $Id$

use ExtUtils::MakeMaker;

WriteMakefile (
	NAME => 'Net::SSH::DB',
	VERSION_FROM => 'lib/Net/SSH/DB.pm',
	EXE_FILES => [
		"bin/sshdmp",
		"bin/sshdb",
		"bin/sshproc"
	],
	PREREQ_PM => {
		'DBD::SQLite' => 1.3, # tested against 1.35
		'YAML' => 0, # tested against 0.84
		'OpSys' => 1.0
	}
);

