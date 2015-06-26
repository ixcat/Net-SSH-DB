#! /usr/bin/env perl

#
# Net::SSH::LogParser
#
# sftp login record processing.
#
#  misc notes:
#    - el6 login records different than e.g. openbsd (pam vs native)
#      'subsystem request' is syslog .INFO on el6 (ssh portable?) but debug2
#      on openbsd - however, can setup sftp flags..
#    - tests okish el6/OpenBSD 5.6 - need more logic cases for other systems.
#
# Note: proper user process tracking *requires* LogLevel VERBOSE in sshd_config.
#
# internal api basically:
# 
#   - has a 'next log event' generator to retrieve a stream of log events
#   - has a 'next login event' to synthesize login / logout records
# 
# this enables a 'generator like' usage of the gizmo - 
# as nextlogevent() will store file location and interlock with next()
# to create a 'login event stream'.
#
# $Id$
# 

package Net::SSH::LogParser;

use strict;
use warnings;

use YAML; # debug
use Time::Piece qw//;
use Carp;

use OpSys; # will need later - for os specific parsing

# sub predecls

sub new;
sub setdate;
sub open;

sub next;
sub dump;

sub main;

sub _nextlogevt;
sub _dateconv;

sub _guessfork;		# fork child guess heuristics
sub _guesshup;		# hangup child guess heuristics

# globals

my $msgtypes = { # not used, but is 'offical' list of strings
	'accept' => 'accept',
	'sftp' => 'sftp',
	'hup' => 'hup',
	'srvstart' => 'srvstart',
	'srvstop' => 'srvstop'
};

# subs

sub new {
	my $class = shift;
	my $self = {};

	$self->{recs} = []; 		# found records list

	# for '_nextlogevt' logic
	$self->{_logfh} = undef;	# ssh log filehandle

	# for 'next' logic
	$self->{_ins} = {}; 		# current logins by ssh pid
	$self->{_pend} = []; 		# pending found records queue

	$self->{_guesspid} = 0;		# enable child process guess heuristics
	$self->{_lastpid} = 0;		# last found pid (child heuristics)
	$self->{_ppids} = {};		# parent pid table

	# time processing logic

	$self->{_dateconv} = undef;
	$self->{_year} = undef;
	$self->{_tz} = undef;

	bless $self,$class;
	return $self;
}

sub setdate { # setdate year tz
	my $self = shift;
	my $year = shift;
	my $tz = shift;

	$self->{_dateconv} = 1;
	$self->{_year} = $year;
	$self->{_tz} = $tz;
}

sub open {
	my $self = shift;
	my $fn = shift;

	my $fh;

	if(!CORE::open( $fh, '<', $fn )){
		carp "couldn't open file!: $!\n";
		return undef;
	}

	$self->{_logfh} = $fh;
	return $fh;
}

#
# get next login/out record. 
#
# algorithm is roughly:
#
#   - iterate over log events from '_nextlogevt'
#     - track login events
#     - track sftp subssytem request events
#     - when logout, return a record for the associated login/logout,
#       marking that login as an ssh login if there was not an sftp
#       record associated with it, with 'normal' type flag
#     - when eof (or sshd restart? herm - reboot vs daemon restart), 
#       return all records as is, with 'active' type flag
#
# Connection vs protocol vs state:
#
# - proto: ssh1 ssh2, etc - just actual protocol.
#
# - method: { ssh, sftp }:
#
#     - assume ssh unless we have an sftp event during connection lifetime
#
# - state: { normal, active, abrt }:
#
#   Events from _nextlogevt:
#	
#     'accept' => 'accept',
#     'sftp' => 'sftp',
#     'hup' => 'hup',
#     'srvstart' => 'srvstart',
#     'srvstop' => 'srvstop'
#
#   in utmp, we have: active/normal/reboot/shutdown
#     where active is: 'still active' (no termination record)
#     and 'normal' is: 'normal disconnection' (e.g. we track whole session)
#     ... here, reboot/shutdown are not available since server 
#         start/stop doesn't directly correlate with session termination
# 
#     - normal: known good in/out
#     - active: possibly still logged in, possibly dangling
#       depending on completeness of logs processed
#     - abrt: known bad logout (pid collision, unmapped logout/sftp events)
#
# Host Restart / Termination:
# 
# Restart detection cannot be 100% accurate.
# since ssh sessions are kept active across parent restarts,
# and server restart doesn't always follow host restart
# 
# To actually process this properly, need to interpolate system
# reboot records, which shouldn't happen here, but externally.. 
#
# fornow:
#
#   - Just return login/out records, dumping 'activelist'
#     at EOF. An attempt at manual, external reconciliation
#     can happen later according to application specific criteria.
#
 
sub next {
	my $self = shift;

	my $ret = undef;
	my $rec = undef;

	my $ins = $self->{_ins};
	my $pend = $self->{_pend};

	my $lastpid = $self->{_lastpid};
	my $ppids = $self->{_ppids};
	my ($pid,$ppid,$child);

	my $recs = $self->{recs};

	while(1) {

		# handle pending records

		if (scalar @{$pend} > 0) {
			$ret = shift @{$pend};
			push @{$recs}, $ret;
			return $ret;
		}

		# process events

		my $rec = $self->_nextlogevt();

		# no more events

		if (!$rec) {

			# process still 'active' sessions
			my ($pid,$in) = each %{$ins};

			if($pid) {
				$ret = $in;

				$ret->{out} = 0;
				$ret->{state} = 'active';

				delete $ins->{$pid};
				return $ret;
			}

			$self->{_ins} = {};
			$self->{_pend} = {};
			$self->{_ppid} = {};

			return undef; # no records, no active logins
		}

		# other event types

		my $type = '';
		$type = $rec->{type} if $rec->{type};
		next if $type eq '';

		my $pid = $rec->{pid};
		if($ppids->{$pid}) {
			$ppid = $ppids->{$pid};
			$child = $pid;
			$pid = $ppid;
		}

		if($type eq 'accept') {

			# catch dangling logins -
			# make record, queue for return and continue

			if($ins->{$pid}) {
				$ret = $ins->{$pid};

				$ret->{state} = 'abrt';
				$ret->{out} = 0;

				delete $ppids->{$child} if $child;
				delete $ins->{$pid};

				return $ret;
			}

			$ins->{$pid} = {
				'user' => $rec->{user},
				'host' => $rec->{host},
				'pid' => $rec->{pid},
				'in' => $rec->{date},
				'out' => undef,
				'rhost' => $rec->{rhost},
				'rport' => $rec->{rport},
				'auth' => $rec->{auth},
				'proto' => $rec->{proto},
				'method' => 'ssh',
				'state' => 'active'
			};
			$self->{_lastpid} = $lastpid = $pid;
		}

		if($type eq 'child') { # child tracking - 1 level is enough
			my $child = undef;
			$child = $rec->{child};
			$ppids->{$child} = $pid;
			next;
		}

		if($type eq 'sftp') {
			my $tmp = $ins->{$pid};

			if(!$tmp) { 
				# unmapped sftp - 
				# try parent heuristic if ok, drop otherwise

				my $g = $self->_guessfork($rec,$pid,$lastpid);

				if($g eq $pid) {
					$ret = $rec;
					$ret->{state} = 'abrt';
					return $ret;
				}

				$tmp = $ins->{$lastpid};
				$tmp->{method} = 'sftp';
				$ppids->{$pid} = $lastpid;
			}
			else {
				$tmp->{method} = 'sftp';
				$ins->{$pid} = $tmp;
			}
		}

		if($type eq 'hup') {
			$ret = $ins->{$pid};

			if(!$ret) { # umapped hup
				$ret = $rec;
				$ret->{state} = 'abrt';
				return $ret;
			}

			$ret->{out} = $rec->{date};
			$ret->{state} = 'normal';

			delete $ppids->{$child} if $child;
			delete $ins->{$pid};

			return $ret;
		}

		if($type =~ m:srv(start|stop): ){
			next; # restart not handled
		}

	}


}

#
# get next log event.
#
# records of interest:
#
# all prefaced via: 'Apr 23 21:43:09 srv1 sshd[28427]: '
#
# login/session start:
#
# Accepted publickey for root from 192.168.1.21 port 32819 ssh2
# pam_unix(sshd:session): session opened for user root by (uid=0)
# User child is on pid 1234
# subsystem request for sftp
# Starting session: subsystem 'sftp' for chris from 192.168.1.21 port 45492
#
# logout:
# 
# Received disconnect from 192.168.1.21: 11: disconnected by user
# pam_unix(sshd:session): session closed for user root
# Read error from remote host (.*?): Connection timed out
# Connection closed by 10.143.195.18
#
# server stop/start:
#
# Received signal 15; terminating.
# Server listening on 0.0.0.0 port 22.
# Server listening on :: port 22.
#

sub _nextlogevt {

	my $self = shift;
	my $fh = $self->{_logfh};

	my ($sshrx,$acceptrx,$childrx,$sftprx);
	my ($huprx);
	my ($startrx,$stoprx);

	$sshrx = '(\w{3} (?:\s\d|\d{2}) \d{2}:\d{2}:\d{2}) '
		. '(\w+) sshd\[(\d+)\]: '
		. '(.*)$';

	$acceptrx = 'Accepted (\w+) for (\w+) from (.*?) port (\d+) (\w+)';
	$childrx = 'User child is on pid (\d+)';
	$sftprx = '(subsystem request for sftp|subsystem .sftp. for \w)';

	$huprx = '(' .
		'Received disconnect from (.*?): \d+: \w+' .'|'.
		'pam_unix\(sshd:session\): session closed for user \w+' .'|'.
		'Read error from remote host (.*?): Connection timed out' .'|'.
		'Connection closed by \w+' .
	')';

	$startrx = 'Server listening on';
	$stoprx = 'Received signal 15; terminating.';

	while(<$fh>) {

		my $ret = {};

		# only deal with SSH
		next unless m:$sshrx:;

		# $ret->{date} = $1; # fixme: convert to timestamp
		$ret->{date} = $self->_dateconv($1);
		$ret->{host} = $2;
		$ret->{pid} = $3;
		$ret->{msg} = $4;

		$ret->{type} = undef;
		$ret->{auth} = undef;
		$ret->{user} = undef;
		$ret->{rhost} = undef;
		$ret->{rport} = undef;
		$ret->{proto} = undef;
		$ret->{child} = undef;

		# dispatch ssh msg type:
		if(m:$acceptrx:) {
			$ret->{type} = 'accept';
			$ret->{auth} = $1;
			$ret->{user} = $2;
			$ret->{rhost} = $3;
			$ret->{rport} = $4;
			$ret->{proto} = $5;
		}
		if(m:$childrx:) {
			$ret->{type} = 'child';
			$ret->{child} = $1;
		}
		if(m:$sftprx:) {
			$ret->{type} = 'sftp';
		}
		if(m:$huprx:) {
			$ret->{type} = 'hup';
		}
		if(m:$startrx:) {
			$ret->{type} = 'srvstart';
		}
		if(m:$stoprx:) {
			$ret->{type} = 'srvstop';
		}

		return $ret;
	}

	return undef; # EOF

}

sub _dateconv { # XXX: threadsafe: modifies TZ

	my $self = shift;
	my $datestr = shift;

	return $datestr unless $self->{_dateconv};
	my $year = $self->{_year};
	my $tz = $self->{_tz};

	my ($ret, $oldtz, $lt, $dt);

	$oldtz = $ENV{TZ};

	$ENV{TZ} = $tz;

	$datestr .= " $year";

	$lt = Time::Piece::localtime();
	$dt = Time::Piece->strptime($datestr, '%b %d %H:%M:%S %Y');

	$ret = Time::Piece::localtime(
		($dt->epoch() - $lt->tzoffset())->seconds()
	);

	$ENV{TZ} = $oldtz;

	return $ret->epoch();

}

sub _guessfork { # child guess heuristics - returns pid of 'correct' record

	my $self = shift;
	my $rec = shift;
	my $pid = shift;
	my $lastpid = shift;

	# dont guess unless configured to do so
	return $pid unless $self->{_guesspid};

	my $other = $self->{_ins}->{$lastpid};

	return $pid unless $other;

	# can only portably count on timestamps - can potentially cross wires
	return $lastpid if ($rec->{date} - $other->{in} < 5);

	return $pid;

}

sub _guesshup { # disconnection child guess heuristics

my $notes =<<'EONOTE'

mainly to cover case of:

Apr 30 13:35:19 eve sshd[10238]: Accepted password for dd4932 from 173.198.127.6
6 port 42908 ssh2
Apr 30 13:35:21 eve sshd[10240]: Received disconnect from 173.198.127.66: 11: di
sconnected by user

so.. how to catch:

  - track inputs as rhost:pid array
  - fit outputs to closest input pid within threshold - 
    ... but doesn't work for random pid os (openbsd)

EONOTE
;

}

sub main {
	my $class = shift; # called via package usually
	my $args = shift;

	my $lf = $args->{logfile};

	if(!$lf) {
		my $os = OpSys->new();
		my $osname = $os->{osname};

		$lf = '/var/log/secure' if $osname eq 'linux';
		$lf = '/var/log/authlog' if $osname eq 'openbsd';
	}

	my $proc = Net::SSH::LogParser->new();

	$proc->open($lf);

	$proc->{_guesspid} = 1;

	if($args->{dateconv}) {
		$proc->setdate(
			Time::Piece::localtime()->_year(),
			$ENV{TZ} 
		);
	}

	if ($args->{action} eq 'dump') {
		while ( my $evt = $proc->_nextlogevt()) {
			print YAML::Dump $evt;
		}
	}
	if ($args->{action} eq 'procdmp') {
		while ( my $evt = $proc->next()) {
			if($evt->{state} ne 'abrt') {
				print YAML::Dump $evt;
			}
		}
	}
	return 0;
}

1;
__DATA__
Apr 22 04:13:56 srv1 sshd[2633]: Received signal 15; terminating.
Apr 22 04:14:00 srv1 sshd[29236]: Server listening on 0.0.0.0 port 22.
Apr 22 04:14:00 srv1 sshd[29236]: Server listening on :: port 22.
Apr 22 15:12:06 srv1 sshd[31558]: Received disconnect from 192.168.1.21: 11: disconnected by user
Apr 22 15:12:06 srv1 sshd[31558]: pam_unix(sshd:session): session closed for user root
Apr 22 15:13:27 srv1 sshd[31123]: Received disconnect from 192.168.1.21: 11: disconnected by user
Apr 22 15:13:27 srv1 sshd[31123]: pam_unix(sshd:session): session closed for user root
Apr 22 17:36:24 srv1 sshd[25647]: Accepted publickey for root from 192.168.1.21 port 16809 ssh2
Apr 22 17:36:24 srv1 sshd[25647]: pam_unix(sshd:session): session opened for user root by (uid=0)
Apr 22 20:16:35 srv1 sshd[25647]: Received disconnect from 192.168.1.21: 11: disconnected by user
Apr 22 20:16:35 srv1 sshd[25647]: pam_unix(sshd:session): session closed for user root
Apr 23 15:16:20 srv1 sshd[30474]: Accepted publickey for root from 192.168.1.21 port 43924 ssh2
Apr 23 15:16:21 srv1 sshd[30474]: pam_unix(sshd:session): session opened for user root by (uid=0)
Apr 23 21:42:53 srv1 sshd[28407]: Connection closed by 192.168.1.21
Apr 23 21:43:09 srv1 sshd[28427]: Accepted publickey for root from 192.168.1.21 port 32819 ssh2
Apr 23 21:43:09 srv1 sshd[28427]: pam_unix(sshd:session): session opened for user root by (uid=0)
Apr 23 21:43:09 srv1 sshd[28427]: subsystem request for sftp
Apr 23 21:43:14 srv1 sshd[28427]: Received disconnect from 192.168.1.21: 11: disconnected by user
Apr 23 21:43:14 srv1 sshd[28427]: pam_unix(sshd:session): session closed for user root
