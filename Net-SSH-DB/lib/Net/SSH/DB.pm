
# Net::SSH::DB
# =============
#
# $Id$
#
# Net::SSH::LogParser SQL-Backed login database class.
#

# globals

package Net::SSH::DB;
$VERSION = 1.0;

use warnings;
use strict;

use Carp;

use DBI;
use DBD::SQLite;

use Net::SSH::LogParser;

# sub predecls

sub new;
sub connect;

sub createdb;
sub begintxn;
sub insertrec;
sub updaterec;
sub endtxn;

# todo: smart-insert - e.g. replace existing records with update
#   ... this is good if e.g. still logged in records are lated updated

sub main;

# subs

sub new {
	my $class = shift;
	my $fname = shift;

	my $self = {};
	$self->{dbh} = undef;
	$self->{dburi} = undef;
	$self->{_insth} = undef;

	if($fname) {
		Net::SSH::DB::connect($self,$fname) or return undef;
	}

	bless $self,$class;

	return $self;
}

sub connect {
	my($self,$fname) = @_;

	return undef unless $fname;

	my $dburi = "dbi:SQLite:$fname";
	my $dbh = DBI->connect($dburi);

	if(!$dbh) {
		carp "unable to connect to $dburi: $!\n";
		return undef;
	}

	# connection settings...
	$dbh->do('pragma journal_mode = truncate');

	$self->{dburi} = $dburi;
	$self->{dbh} = $dbh;

	return $dbh;
}

sub createdb {
	my $self = shift;

	my ($dbh,$sth);
	my $schema = join '', <DATA>;

	$dbh = $self->{dbh};

	if(!$dbh) {
		carp "createdb on unconnected object";
		return 1;
	}

	$sth = $dbh->prepare($schema);
	$sth->execute();

	return 0;
}

sub begintxn {
	my $self = shift;
	my ($dbh,$sth);

	$dbh = $self->{dbh};
	
	if(!$dbh) {
		carp "begintxn on unconnected object";
		return 1;
	}

	$dbh->do('begin transaction');
}

sub insertrec {
	my ($self,$rec) = @_;

	my ($dbh,$ststr,$sth);

	return undef unless $rec;

	$dbh = $self->{dbh};
	$sth = $self->{_insth};

	if(!$sth) {
		$sth = $dbh->prepare(
			"insert into sshdata values(?,?,?,?,?,?,?,?,?,?,?)"
		);
		$self->{_insth} = $sth;
	}

	$sth->bind_param(1 ,$rec->{in});
	$sth->bind_param(2 ,$rec->{out});
	$sth->bind_param(3 ,$rec->{host});
	$sth->bind_param(4 ,$rec->{pid});
	$sth->bind_param(5 ,$rec->{user});
	$sth->bind_param(6 ,$rec->{rhost});
	$sth->bind_param(7 ,$rec->{rport});
	$sth->bind_param(8 ,$rec->{state});
	$sth->bind_param(9 ,$rec->{auth});
	$sth->bind_param(10 ,$rec->{method});
	$sth->bind_param(11 ,$rec->{proto});

	$sth->execute();	
}

sub endtxn {
	my $self = shift;
	my $dbh = $self->{dbh};
	
	if(!$dbh) {
		carp "begintxn on unconnected object";
		return 1;
	}

	$dbh->do('commit');
}

1;
__DATA__

--
-- Net::SSH::DB SQL Schema
-- created for sqlite3 databases
--
-- $Id$
--

create table sshdata (
	timein integer not null,
	timeout integer,
	host text not null,
	pid integer not null,
	user text not null,
	rhost text not null,
	rport integer not null,
	state text not null,
	auth text not null,
	method text not null,
	proto text not null,
	primary key (timein,host,pid)
);

