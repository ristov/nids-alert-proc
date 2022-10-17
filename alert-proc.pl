#!/usr/bin/perl -w
#
# alert-proc 0.01 - alert-proc.pl
# Copyright (C) 2022 Risto Vaarandi
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#


use strict;

use POSIX qw(:errno_h);
use Cpanel::JSON::XS;
use Net::CIDR::Lite;
use Storable;
use Sys::Syslog;
use Getopt::Long;


use vars qw(
  $USAGE
  %alerts
  $alpha
  %app_proto_func
  %attributes
  $attrkey_init_val
  $blocksize
  %candidates
  $candidate_timeout
  %clusters
  $cluster_timeout
  $default_centroid
  $dumpstate
  $homenets
  $input_buffer
  $last_maintenance
  $max_attrtable_entropy
  $max_attrtable_size
  $max_candidate_age
  $max_candidates
  $max_clusters
  $min_attrkey_val
  $output_fh
  $output_file
  $parser_regexp
  $pid_file
  $reopen_output
  $scantime
  $session_length
  $session_timeout
  %sig_matches
  $sleeptime
  $statefile
  $syslog_facility
  $syslog_level
  $syslog_tag
  $terminate
);


$USAGE = qq!Usage: $0 [options]

Options:

  --max-candidate-age=<max candidate age> 

    If cluster candidate age exceeds <max candidate age> seconds, promote 
    the candidate to cluster. Default value for <max candidate age> is 
    86400 seconds (1 day).

  --candidate-timeout=<candidate timeout>

    If cluster candidate has not seen matches during more than 
    <candidate timeout> seconds, drop the candidate. Default value for 
    <candidate timeout> is 3600 seconds (1 hour).

  --cluster-timeout=<cluster timeout>

    If cluster has not seen matches during more than <cluster timeout> 
    seconds, drop the cluster. Default value for <cluster timeout> is 
    604800 seconds (1 week).

  --alpha=<alpha>

    The value of alpha for EWMA calculations. This option is mandatory.

  --attrkey-init-value=<init value>

    Initialize the value of new attribute hash table key to <init value>.
    Default value for <init value> is (1 / (2/alpha - 1)).

  --min-attrkey-value=<value threshold>

    If the value of attribute hash table key drops below <value threshold>,
    the key is removed from attribute hash table, in order to reduce memory
    consumption of attribute hash tables. Default value for <value threshold> 
    is (0.2 * (1 / (2/alpha - 1))).

  --max-attrtable-size=<size threshold>
  --max-attrtable-entropy=<entropy threshold>

    If the attribute hash table contains <size threshold> or more keys, and
    the normalized information entropy of key values is <entropy threshold>
    or more, similarity score 1 is reported for the given attribute. 
    Default value for <size threshold> is 50, and default value for 
    <entropy threshold> is 0.8.

  --homenet=<homenet> ...

    One or more home networks, where each network is given with a separate
    --homenet option. Providing at least one --homenet option is mandatory.

  --parser=<regular expression>

    Regular expression for matching and parsing input lines, so that
    Suricata EVE messages are extracted. The regular expression must set 
    \$+{json} match variable to JSON data string from the EVE message. 
    For example, the following regular expression parses Suricata EVE 
    messages from syslog log files:
    'suricata(?:\\[\\d+\\])?: \@cee:\\s*(?<json>\\{.+\\})\\s*\$'
    By default, no regular expression is applied for matching and parsing 
    input lines, and it is assumed that each input line is a valid JSON 
    data string representing a valid Suricata EVE message.

  --session-timeout=<session timeout>
  --session-length=<session length>

    Group consecutive IDS alert messages for the same external IP address 
    and the same signature together. If no more IDS alert messages have been
    observed for a given group during <session timeout> seconds, the group
    is regarded as complete. If IDS alert messages have been observed
    during <session length> seconds for a given group, the group is regarded
    as complete. Setting <session length> to 0 means that each group will
    contain only one IDS alert message (i.e., alert messages are not arranged
    into groups). Default value for <session timeout> is 60 seconds, and
    default value for <session length> is 300 seconds.

  --statefile=<state file>

    If this command line option is provided, the program writes its
    internal state to <state file> on termination, and restores its 
    state from <state file> when it starts. The state file <state file> 
    is also produced on the reception of USR2 signal.

  --sleeptime=<sleep time>

    Sleep time in seconds -- if no new messages were read from
    standard input, the program sleeps for <sleep time> seconds.
    Default value for <sleep time> is 1.0 seconds.

  --blocksize=<block size>

    IO block size in bytes. Default value for <block size> is 16384 bytes.

  --scantime=<scan time>

    After each <scan time> seconds, scan all data structures for
    housekeeping purposes. Default value for <scan time> is 10 seconds.

  --output=<output file>

    Write IDS alert groups to file <output file>, creating the file if 
    it does not exist. Each group is in JSON format and is written as 
    a single line to the file. Note that on the reception of HUP signal, 
    the file will be reopened (and recreated if it no longer exists, in 
    order to facilitate log rotation). Specifying - for <output file> 
    denotes standard output.

  --syslog-tag=<tag>

    Log IDS alert groups to syslog with syslog tag <tag>.
    Without this option, groups are not logged to syslog, even if
    --syslog-facility or --syslog-level options are provided.

  --syslog-facility=<facility>

    If IDS alert groups are logged to syslog, use syslog facility <facility>.
    Default value for <facility> is user.

  --syslog-level=<level>

    If IDS alert groups are logged to syslog, use syslog level <level>.
    Default value for <level> is info.

  --pid=<pid file>

    Store process ID to file <pid file>.

  --help, -?

    Print the usage information.

  --version

    Print the version information.

!;


#####################################################################


sub get_options {

  my(@homenets, $regexp, $help, $version);

  if (!scalar(@ARGV)) {
    print $USAGE;
    exit(0);
  }

  $max_candidate_age = 86400;
  $candidate_timeout = 3600;
  $cluster_timeout = 604800;
  $max_attrtable_size = 50;
  $max_attrtable_entropy = 0.8;
  $session_timeout = 60;
  $session_length = 300;
  $sleeptime = 1;
  $blocksize = 16384;
  $scantime = 10;
  $syslog_facility = "user";
  $syslog_level = "info";
  $help = 0;
  $version = 0;

  GetOptions( "max-candidate-age=i" => \$max_candidate_age,
              "candidate-timeout=i" => \$candidate_timeout,
              "cluster-timeout=i" => \$cluster_timeout,
              "alpha=f" => \$alpha,
              "attrkey-init-value=f" => \$attrkey_init_val,
              "min-attrkey-value=f" => \$min_attrkey_val,
              "max-attrtable-size=i" => \$max_attrtable_size,
              "max-attrtable-entropy=f" => \$max_attrtable_entropy,
              "homenet=s" => \@homenets,
              "parser=s" => \$regexp,
              "session-timeout=i" => \$session_timeout,
              "session-length=i" => \$session_length,
              "statefile=s" => \$statefile,
              "sleeptime=f" => \$sleeptime,
              "blocksize=i" => \$blocksize,
              "scantime=i" => \$scantime,
              "output=s" => \$output_file,
              "syslog-tag=s" => \$syslog_tag,
              "syslog-facility=s" => \$syslog_facility,
              "syslog-level=s" => \$syslog_level,
              "pid=s" => \$pid_file,
              "help|?" => \$help,
              "version" => \$version );

  if ($help) {
    print $USAGE;
    exit(0);
  }

  if ($version) {
    print "alert-proc version 0.01, Copyright (C) 2022 Risto Vaarandi\n";
    exit(0);
  }

  if ($max_candidate_age <= 0) {
    print STDERR "Invalid max candidate age $max_candidate_age: must be positive integer\n";
    exit(1);
  }

  if ($candidate_timeout <= 0) {
    print STDERR "Invalid candidate timeout $candidate_timeout: must be positive integer\n";
    exit(1);
  }

  if ($cluster_timeout <= 0) {
    print STDERR "Invalid cluster timeout $cluster_timeout: must be positive integer\n";
    exit(1);
  }

  if (!defined($alpha)) {
    print STDERR "--alpha option is mandatory\n";
    exit(1);
  }

  if ($alpha <= 0 || $alpha > 1) {
    print STDERR "Invalid alpha $alpha: must be positive real number not greater than 1\n";
    exit(1);
  }

  if (!defined($attrkey_init_val)) {
    $attrkey_init_val = 1 / (2/$alpha - 1);
  }

  if ($attrkey_init_val <= 0 || $attrkey_init_val > 1) {
    print STDERR "Invalid attribute key init value $attrkey_init_val: must be positive real number not greater than 1\n";
    exit(1);
  }

  if (!defined($min_attrkey_val)) {
    $min_attrkey_val = 0.2 * (1 / (2/$alpha - 1));
  }

  if ($min_attrkey_val <= 0 || $min_attrkey_val > 1) {
    print STDERR "Invalid min attribute key value $min_attrkey_val: must be positive real number not greater than 1\n";
    exit(1);
  }

  if ($min_attrkey_val > $attrkey_init_val) {
    print STDERR "Invalid min attribute key value $min_attrkey_val: must not be greater than attribute key init value (current setting --attrkey-init-value=$attrkey_init_val)\n";
    exit(1);
  }

  if ($max_attrtable_size <= 0) {
    print STDERR "Invalid max attribute table size $max_attrtable_size: must be positive integer\n";
    exit(1);
  }

  if ($max_attrtable_entropy <= 0 || $max_attrtable_entropy > 1) {
    print STDERR "Invalid max attribute table entropy $max_attrtable_entropy: must be positive real number not greater than 1\n";
    exit(1);
  }

  if (!scalar(@homenets)) {
    print STDERR "--homenet option is mandatory\n";
    exit(1);
  }

  $homenets = eval { Net::CIDR::Lite->new(@homenets) };

  if ($@) {
    print STDERR "Invalid home network(s) ", join(" ", @homenets), ": $@\n";
    exit(1);
  }

  if (defined($regexp)) { 

    $parser_regexp = eval { qr/$regexp/ };

    if ($@) {
      print STDERR "Invalid regular expression $regexp: $@\n";
      exit(1);
    }

  }

  if ($session_timeout <= 0) {
    print STDERR "Invalid session timeout $session_timeout: must be positive integer\n";
    exit(1);
  }

  if ($session_length < 0) {
    print STDERR "Invalid session length $session_length: must be non-negative integer\n";
    exit(1);
  }

  if ($sleeptime <= 0) {
    print STDERR "Invalid sleep time $sleeptime: must be positive real number\n";
    exit(1);
  }

  if ($blocksize <= 0) {
    print STDERR "Invalid IO block size $blocksize: must be positive integer\n";
    exit(1);
  }

  if ($scantime <= 0) {
    print STDERR "Invalid scan time $scantime: must be positive integer\n";
    exit(1);
  }

  if (!defined($output_file) && !defined($syslog_tag)) {
    print STDERR "Defining at least one output with --output or --syslog-tag option is mandatory\n";
    exit(1);
  }
}


sub detect_int_ext {

  my($srcip, $srcport, $dstip, $dstport) = @_;
  my($intip, $intport, $extip, $extport);

  if ($homenets->find($srcip)) {
    $intip = $srcip;
    $intport = $srcport;
    $extip = $dstip;
    $extport = $dstport;
  }
  elsif ($homenets->find($dstip)) {
    $intip = $dstip;
    $intport = $dstport;
    $extip = $srcip;
    $extport = $srcport;
  }
  
  if (!defined($intip)) {
    return (undef, undef, undef, undef);
  }

  if ($homenets->find($extip)) {
    return (undef, undef, undef, undef);
  }

  return ($intip, $intport, $extip, $extport);
}


sub process_tls_alert {

  my($ref, $attref) = @_;

  # if app_proto field of the alert is set to "tls", but tls attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"tls"})) { return; }

  # parse tls specific attributes

  if (!exists($attref->{"TlsFingerprint"})) {
    $attref->{"TlsFingerprint"} = {};
  }

  if (exists($ref->{"tls"}->{"fingerprint"})) {
    $attref->{"TlsFingerprint"}->{$ref->{"tls"}->{"fingerprint"}} = 1;
  }

  if (!exists($attref->{"TlsIssuerDn"})) {
    $attref->{"TlsIssuerDn"} = {};
  }

  if (exists($ref->{"tls"}->{"issuerdn"})) {
    $attref->{"TlsIssuerDn"}->{$ref->{"tls"}->{"issuerdn"}} = 1;
  }

  if (!exists($attref->{"TlsJa3hash"})) {
    $attref->{"TlsJa3hash"} = {};
  }

  if (exists($ref->{"tls"}->{"ja3"}->{"hash"})) {
    $attref->{"TlsJa3hash"}->{$ref->{"tls"}->{"ja3"}->{"hash"}} = 1;
  }

  if (!exists($attref->{"TlsSni"})) {
    $attref->{"TlsSni"} = {};
  }

  if (exists($ref->{"tls"}->{"sni"})) {
    $attref->{"TlsSni"}->{$ref->{"tls"}->{"sni"}} = 1;
  }

  if (!exists($attref->{"TlsSubject"})) {
    $attref->{"TlsSubject"} = {};
  }

  if (exists($ref->{"tls"}->{"subject"})) {
    $attref->{"TlsSubject"}->{$ref->{"tls"}->{"subject"}} = 1;
  }

  if (!exists($attref->{"TlsVersion"})) {
    $attref->{"TlsVersion"} = {};
  }

  if (exists($ref->{"tls"}->{"version"})) {
    $attref->{"TlsVersion"}->{$ref->{"tls"}->{"version"}} = 1;
  }

}


sub process_smtp_alert {

  my($ref, $attref) = @_;
  my($type, $elem);

  # if app_proto field of the alert is set to "smtp", but smtp attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"smtp"})) { return; }

  # parse smtp specific attributes

  if (!exists($attref->{"SmtpHelo"})) {
    $attref->{"SmtpHelo"} = {};
  }

  if (exists($ref->{"smtp"}->{"helo"})) {
    $attref->{"SmtpHelo"}->{$ref->{"smtp"}->{"helo"}} = 1;
  }

  if (!exists($attref->{"SmtpMailFrom"})) {
    $attref->{"SmtpMailFrom"} = {};
  }

  if (exists($ref->{"smtp"}->{"mail_from"})) {
    $attref->{"SmtpMailFrom"}->{$ref->{"smtp"}->{"mail_from"}} = 1;
  }

  if (!exists($attref->{"SmtpRcptTo"})) {
    $attref->{"SmtpRcptTo"} = {};
  }

  if (exists($ref->{"smtp"}->{"rcpt_to"})) {

    $type = ref($ref->{"smtp"}->{"rcpt_to"});

    if ($type eq "ARRAY") {

      foreach $elem (@{$ref->{"smtp"}->{"rcpt_to"}}) {
        $attref->{"SmtpRcptTo"}->{$elem} = 1;
      }

    } elsif ($type eq "") {
      $attref->{"SmtpRcptTo"}->{$ref->{"smtp"}->{"rcpt_to"}} = 1;
    }
  }

  if (!exists($attref->{"EmailFrom"})) {
    $attref->{"EmailFrom"} = {};
  }

  if (exists($ref->{"email"}->{"from"})) {
    $attref->{"EmailFrom"}->{$ref->{"email"}->{"from"}} = 1;
  }

  if (!exists($attref->{"EmailStatus"})) {
    $attref->{"EmailStatus"} = {};
  }

  if (exists($ref->{"email"}->{"status"})) {
    $attref->{"EmailStatus"}->{$ref->{"email"}->{"status"}} = 1;
  }

  if (!exists($attref->{"EmailTo"})) {
    $attref->{"EmailTo"} = {};
  }

  if (exists($ref->{"email"}->{"to"})) {

    $type = ref($ref->{"email"}->{"to"});

    if ($type eq "ARRAY") {

      foreach $elem (@{$ref->{"email"}->{"to"}}) {
        $attref->{"EmailTo"}->{$elem} = 1;
      }

    } elsif ($type eq "") {
      $attref->{"EmailTo"}->{$ref->{"email"}->{"to"}} = 1;
    }
  }

}


sub process_dns_alert {

  my($ref, $attref) = @_;
  my($elem);

  # if app_proto field of the alert is set to "dns", but dns attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"dns"})) { return; }

  # parse dns specific attributes

  if (!exists($attref->{"DnsRrname"})) {
    $attref->{"DnsRrname"} = {};
  }

  if (!exists($attref->{"DnsRrtype"})) {
    $attref->{"DnsRrtype"} = {};
  }

  if (exists($ref->{"dns"}->{"query"})) {

    foreach $elem (@{$ref->{"dns"}->{"query"}}) {

      if (exists($elem->{"rrname"})) {
        $attref->{"DnsRrname"}->{$elem->{"rrname"}} = 1;
      }

      if (exists($elem->{"rrtype"})) {
        $attref->{"DnsRrtype"}->{$elem->{"rrtype"}} = 1;
      }

    }
  }

}


sub process_ssh_alert {

  my($ref, $attref) = @_;

  # if app_proto field of the alert is set to "ssh", but ssh attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"ssh"})) { return; }

  # parse ssh specific attributes

  if (!exists($attref->{"SshServerProto"})) {
    $attref->{"SshServerProto"} = {};
  }

  if (exists($ref->{"ssh"}->{"server"}->{"proto_version"})) {
    $attref->{"SshServerProto"}->{$ref->{"ssh"}->{"server"}->{"proto_version"}} = 1;
  }

  if (!exists($attref->{"SshServerSoftware"})) {
    $attref->{"SshServerSoftware"} = {};
  }

  if (exists($ref->{"ssh"}->{"server"}->{"software_version"})) {
    $attref->{"SshServerSoftware"}->{$ref->{"ssh"}->{"server"}->{"software_version"}} = 1;
  }

  if (!exists($attref->{"SshClientProto"})) {
    $attref->{"SshClientProto"} = {};
  }

  if (exists($ref->{"ssh"}->{"client"}->{"proto_version"})) {
    $attref->{"SshClientProto"}->{$ref->{"ssh"}->{"client"}->{"proto_version"}} = 1;
  }

  if (!exists($attref->{"SshClientSoftware"})) {
    $attref->{"SshClientSoftware"} = {};
  }

  if (exists($ref->{"ssh"}->{"client"}->{"software_version"})) {
    $attref->{"SshClientSoftware"}->{$ref->{"ssh"}->{"client"}->{"software_version"}} = 1;
  }

}


sub process_http_alert {

  my($ref, $attref) = @_;
  my($key, @keys);
  
  # if app_proto field of the alert is set to "http", but http attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"http"})) { return; }

  # parse http specific attributes

  if (!exists($attref->{"HttpHostname"})) {
    $attref->{"HttpHostname"} = {};
  }

  if (exists($ref->{"http"}->{"hostname"})) {
    $attref->{"HttpHostname"}->{$ref->{"http"}->{"hostname"}} = 1;
  }

  if (!exists($attref->{"HttpContentType"})) {
    $attref->{"HttpContentType"} = {};
  }

  if (exists($ref->{"http"}->{"http_content_type"})) {
    $attref->{"HttpContentType"}->{$ref->{"http"}->{"http_content_type"}} = 1;
  }

  if (!exists($attref->{"HttpMethod"})) {
    $attref->{"HttpMethod"} = {};
  }

  if (exists($ref->{"http"}->{"http_method"})) {
    $attref->{"HttpMethod"}->{$ref->{"http"}->{"http_method"}} = 1;
  }

  if (!exists($attref->{"HttpRequestBody"})) {
    $attref->{"HttpRequestBody"} = {};
  }

  if (exists($ref->{"http"}->{"http_request_body_printable"})) {
    @keys = split(' ', $ref->{"http"}->{"http_request_body_printable"});
    foreach $key (@keys) { $attref->{"HttpRequestBody"}->{$key} = 1; }
  }

  if (!exists($attref->{"HttpResponseBody"})) {
    $attref->{"HttpResponseBody"} = {};
  }

  if (exists($ref->{"http"}->{"http_response_body_printable"})) {
    @keys = split(' ', $ref->{"http"}->{"http_response_body_printable"});
    foreach $key (@keys) { $attref->{"HttpResponseBody"}->{$key} = 1; }
  }

  if (!exists($attref->{"HttpUserAgent"})) {
    $attref->{"HttpUserAgent"} = {};
  }

  if (exists($ref->{"http"}->{"http_user_agent"})) {
    $attref->{"HttpUserAgent"}->{$ref->{"http"}->{"http_user_agent"}} = 1;
  }

  if (!exists($attref->{"HttpProtocol"})) {
    $attref->{"HttpProtocol"} = {};
  }

  if (exists($ref->{"http"}->{"protocol"})) {
    $attref->{"HttpProtocol"}->{$ref->{"http"}->{"protocol"}} = 1;
  }

  if (!exists($attref->{"HttpStatus"})) {
    $attref->{"HttpStatus"} = {};
  }

  if (exists($ref->{"http"}->{"status"})) {
    $attref->{"HttpStatus"}->{$ref->{"http"}->{"status"}} = 1;
  }

  if (!exists($attref->{"HttpUrl"})) {
    $attref->{"HttpUrl"} = {};
  }

  if (exists($ref->{"http"}->{"url"})) {
    $attref->{"HttpUrl"}->{$ref->{"http"}->{"url"}} = 1;
  }
  
}


sub store_alert {

  my($ref) = $_[0];
  my($id, $extip, $app_proto, $session_id, $attref);

  $id = $ref->{"alert"}->{"gid"} . ":" .  $ref->{"alert"}->{"signature_id"};

  if (!exists($sig_matches{$id})) {
    $sig_matches{$id} = { "Time" => time(), "Matches" => 0 };
  }

  ++$sig_matches{$id}->{"Matches"};

  $extip = $ref->{"extip"};

  $app_proto = exists($ref->{"app_proto"})?$ref->{"app_proto"}:"other";

  $session_id = "$extip $id";

  if (!exists($alerts{$session_id})) {

    $alerts{$session_id} = {
      "CreationTime" => time(),
      "Timestamp" => $ref->{"timestamp"},
      "ExtIP" => $ref->{"extip"},
      "SignatureID" => $id,
      "SignatureText" => $ref->{"alert"}->{"signature"},
      "Category" => $ref->{"alert"}->{"category"},
      "Priority" => $ref->{"alert"}->{"severity"},
      "AlertCount" => 0,
      "Proto" => {},
      "AppProto" => {},
      "Attributes" => {}      
    };
  }

  $alerts{$session_id}->{"UpdateTime"} = time();
  $alerts{$session_id}->{"Proto"}->{$ref->{"proto"}} = 1;
  $alerts{$session_id}->{"AppProto"}->{$app_proto} = 1;
  $alerts{$session_id}->{"IntIP"}->{$ref->{"intip"}} = 1;
  $alerts{$session_id}->{"IntPort"}->{$ref->{"intport"}} = 1;
  $alerts{$session_id}->{"ExtPort"}->{$ref->{"extport"}} = 1;

  ++$alerts{$session_id}->{"AlertCount"};

  $attref = $alerts{$session_id}->{"Attributes"};

  $attref->{"SignatureID"}->{$id} = 1;
  $attref->{"Proto"}->{$ref->{"proto"}} = 1;
  $attref->{"IntIP"}->{$ref->{"intip"}} = 1;
  $attref->{"IntPort"}->{$ref->{"intport"}} = 1;
  $attref->{"ExtIP"}->{$ref->{"extip"}} = 1;
  $attref->{"ExtPort"}->{$ref->{"extport"}} = 1;
  $attref->{"AppProto"}->{$app_proto} = 1;

  if (exists($app_proto_func{$app_proto})) { 
    $app_proto_func{$app_proto}->($ref, $attref);
  }

  return $session_id;
}


sub generate_vector_and_similarity {

  my($alert, $centroid, $label) = @_;
  my($centroidattr, $alertattr, $attr, $value, $sum, $n);
  my($vector, $similarity, $id, $days);

  $vector = {};

  $alertattr = $alert->{"Attributes"};
  $centroidattr = $centroid->{"Attributes"};
    
  foreach $attr (keys %{$centroidattr}) {

    if (!exists($alertattr->{$attr})) {
      $vector->{$attr} = -1;
      next;
    }

    if ($centroid != $default_centroid &&
        scalar(keys %{$centroidattr->{$attr}}) >= $max_attrtable_size &&
        $centroid->{"Entropies"}->{$attr} >= $max_attrtable_entropy) {

      $vector->{$attr} = 1;

    } else {

      $sum = 0;
      $n = 0;

      foreach $value (keys %{$alertattr->{$attr}}) {
        if (exists($centroidattr->{$attr}->{$value})) {
          $sum += $centroidattr->{$attr}->{$value};
        }
        ++$n;
      }

      if ($n) { $vector->{$attr} = $sum / $n; } 
        else { $vector->{$attr} = 0; }
    }
  }

  $alert->{"Vector"} = $vector;

  $sum = 0;
  $n = 0;

  foreach $attr (keys %{$vector}) {

    if ($attr eq "SignatureID" && $centroid != $default_centroid) { next; }

    if ($vector->{$attr} == -1) { next; }

    $sum += $vector->{$attr};
    ++$n;
  }

  if ($n) { $similarity = $sum / $n; } else { $similarity = 0; }

  $alert->{"Similarity"} = $similarity;

  $alert->{"SimilarityAttrCount"} = $n;

  $id = $alert->{"SignatureID"};

  $days = (time() - $sig_matches{$id}->{"Time"}) / 86400;

  if ($days >= 1) { 
    $alert->{"SignatureMatchesPerDay"} = $sig_matches{$id}->{"Matches"} / $days;
  } else {
    $alert->{"SignatureMatchesPerDay"} = 0;
  }

  $alert->{"Label"} = $label;
}


sub update_entropy {

  my($centroid, $attr) = @_;
  my($value, @values, $n, $sum, $entropy, $p);

  @values = values %{$centroid->{"Attributes"}->{$attr}};

  $sum = 0;
  foreach $value (@values) { $sum += $value; }

  $n = scalar(@values);

  if ($n > 1 && $sum != 0) {

    $entropy = 0;

    foreach $value (@values) {
      $p = $value / $sum;
      if ($p != 0) { $entropy -= $p * log($p); }
    }
        
    $entropy /= log($n);

  } else { $entropy = -1; }
  
  $centroid->{"Entropies"}->{$attr} = $entropy;
}


sub create_centroid {

  my($description) = $_[0];
  my($time, $attr, $ref);

  $time = time();

  $ref = { "Description" => $description,
           "CreationTime" => $time, 
           "UpdateTime" => $time,
           "Matches" => 0,
           "Attributes" => {}, 
           "Entropies" => {} };

  foreach $attr (keys %attributes) { 
    $ref->{"Attributes"}->{$attr} = {};
    $ref->{"Entropies"}->{$attr} = -1;
  }

  return $ref;
}


sub update_centroid {

  my($alert, $centroid) = @_;
  my($alertattr, $centroidattr, $attr, $value, $diff, @values);

  $alertattr = $alert->{"Attributes"};
  $centroidattr = $centroid->{"Attributes"};

  foreach $attr (keys %{$centroidattr}) {

    if (!exists($alertattr->{$attr})) {

      @values = keys %{$centroidattr->{$attr}};

      # in the case of signature centroids, attribute table is usually
      # empty if the alert does not have the given attribute, and in
      # order to avoid needless processing of the table, check its size

      if (scalar(@values)) {

        foreach $value (@values) {
          $diff = -$centroidattr->{$attr}->{$value};
          $centroidattr->{$attr}->{$value} += $alpha * $diff;
        }
      
        if ($centroid != $default_centroid) { 
          update_entropy($centroid, $attr); 
        }
      }

      next;
    }

    foreach $value (keys %{$alertattr->{$attr}}) {

      if (exists($centroidattr->{$attr}->{$value})) {
        $diff = 1 - $centroidattr->{$attr}->{$value};
        $centroidattr->{$attr}->{$value} += $alpha * $diff;
      } else {
        $centroidattr->{$attr}->{$value} = 1 / (2 / $alpha - 1);
      }
    }

    foreach $value (keys %{$centroidattr->{$attr}}) {

      if (exists($alertattr->{$attr}->{$value})) { next; }

      $diff = -$centroidattr->{$attr}->{$value};
      $centroidattr->{$attr}->{$value} += $alpha * $diff;
    }

    if ($centroid != $default_centroid) { 
      update_entropy($centroid, $attr); 
    }
  }

  $centroid->{"UpdateTime"} = time();
  ++$centroid->{"Matches"};
}


sub drop_attributes {

  my($centroid) = $_[0];
  my($attr, $value, $ret);

  foreach $attr (keys %{$centroid->{"Attributes"}}) {

    $ret = 0;

    foreach $value (keys %{$centroid->{"Attributes"}->{$attr}}) {
      if ($centroid->{"Attributes"}->{$attr}->{$value} < $min_attrkey_val) {
        delete $centroid->{"Attributes"}->{$attr}->{$value};
        $ret = 1;
      }
    }

    if ($ret && $centroid != $default_centroid) { 
      update_entropy($centroid, $attr); 
    }
  }
}


sub output_alert {

  my($alert) = $_[0];
  my($json);

  eval { $json = encode_json($alert); };

  if ($@) {
    print STDERR "Can't create JSON data structure: $@\n";
    return;
  }

  if (defined($output_file)) { 
    print $output_fh $json, "\n"; 
  }

  if (defined($syslog_tag)) {
    eval { syslog($syslog_level, '@cee: ' . $json) };
  }
}


sub process_alert {

  my($alert) = $_[0];
  my($id);

  $id = $alert->{"SignatureID"};

  if (exists($clusters{$id})) {

    generate_vector_and_similarity($alert, $clusters{$id}, 0);

    update_centroid($alert, $clusters{$id}, 1);

  } elsif (exists($candidates{$id})) {

    generate_vector_and_similarity($alert, $default_centroid, 1);

    update_centroid($alert, $candidates{$id});
    update_centroid($alert, $default_centroid);

  } else {

    generate_vector_and_similarity($alert, $default_centroid, 1);

    $candidates{$id} = create_centroid($alert->{"SignatureText"});

    update_centroid($alert, $candidates{$id});
    update_centroid($alert, $default_centroid);
  }

  delete $alert->{"Attributes"};

  $alert->{"ReportingTime"} = time();

  output_alert($alert);

}


sub process_stored_alerts {

  my($time, $session_id);

  $time = time();

  foreach $session_id (keys %alerts) {

    if ($time - $alerts{$session_id}->{"CreationTime"} > $session_length) {
      process_alert($alerts{$session_id});
      delete $alerts{$session_id};
    }
    elsif ($time - $alerts{$session_id}->{"UpdateTime"} > $session_timeout) {
      process_alert($alerts{$session_id});
      delete $alerts{$session_id};
    }
  }

}


sub maintain_lists {

  my($time, $id);

  $time = time();

  # maintain the list of candidates

  foreach $id (keys %candidates) {

    # drop the candidate if it is stale

    if ($time - $candidates{$id}->{"UpdateTime"} > $candidate_timeout) {
      delete $candidates{$id};
      next;
    }

    # if the candidate has reached the maximum age, promote it to cluster

    if ($time - $candidates{$id}->{"CreationTime"} > $max_candidate_age) {

      $clusters{$id} = $candidates{$id};
      delete $candidates{$id};
      next;
    }

    # scan the attribute tables of the candidate, 
    # and remove key-value pairs with too small values;
    # also, update the entropies

    drop_attributes($candidates{$id});
  } 

  # maintain the list of clusters

  foreach $id (keys %clusters) {

    # drop the cluster if it is stale

    if ($time - $clusters{$id}->{"UpdateTime"} > $cluster_timeout) {
      delete $clusters{$id};
      next;
    }

    # scan the attribute tables of the cluster, 
    # and remove key-value pairs with too small values

    drop_attributes($clusters{$id});
  }

  # scan the attribute tables of the default centroid,
  # and remove key-value pairs with too small values;
  # note that entropies are not updated!

  drop_attributes($default_centroid);

  # record the max number of clusters and candidates

  if ($max_clusters < scalar(keys %clusters)) {
    $max_clusters = scalar(keys %clusters);
  }

  if ($max_candidates < scalar(keys %candidates)) {
    $max_candidates = scalar(keys %candidates);
  }

}


sub read_state_file {

  my($ref);

  $ref = eval { retrieve($statefile) };

  if (!defined($ref)) {
    print STDERR "Can't read state file $statefile: $!\n";
    return;
  }

  %candidates = %{$ref->{"Candidates"}};
  %clusters = %{$ref->{"Clusters"}};

  $default_centroid = $ref->{"DefaultCentroid"};

  $max_clusters = $ref->{"MaxClusters"};
  $max_candidates = $ref->{"MaxCandidates"};

  %sig_matches = %{$ref->{"SignatureMatches"}};
}


sub write_state_file {

  my($ref, $ret);

  $ref = { "Candidates" => \%candidates, 
           "Clusters" => \%clusters,
           "DefaultCentroid" => $default_centroid,
           "MaxClusters" => $max_clusters,
           "MaxCandidates" => $max_candidates,
           "SignatureMatches" => \%sig_matches };

  $ret = eval { store($ref, $statefile) };

  if (!defined($ret)) {
    print STDERR "Can't write state file $statefile: $!\n";
    exit(1);
  }
}


sub read_line {

  my($pos, $line, $rin, $ret, $n);

  # if input buffer contains a full line, return it

  $pos = index($input_buffer, "\n");

  if ($pos != -1) {
    $line = substr($input_buffer, 0, $pos);
    substr($input_buffer, 0, $pos + 1) = "";
    return $line;
  }

  for (;;) {

    # check with select(2) if new input bytes are available

    $rin = '';
    vec($rin, fileno(STDIN), 1) = 1;
    $ret = select($rin, undef, undef, 0);

    # if select(2) failed and it was interrupted by signal, retry select(2),
    # otherwise terminate the program 

    if (!defined($ret) || $ret < 0) { 
      if ($! == EINTR) { next; }
      print STDERR "IO error when polling standard input: $!\n";
      exit(1);
    }

    # if select(2) reported that no new bytes are available, return undef

    if ($ret == 0) { return undef; }

    # read new bytes from standard input with read(2)

    $n = sysread(STDIN, $input_buffer, $blocksize, length($input_buffer));

    # if read(2) failed and it was interrupted by signal, retry polling
    # with select(2) and reading, otherwise terminate the program 

    if (!defined($n)) {
      if ($! == EINTR) { next; }
      print STDERR "IO error when reading from standard input: $!\n";
      exit(1);
    }

    # if select(2) reported the availability of new bytes but read(2)
    # returned 0 bytes, EOF has been reached, and exit from program

    if ($n == 0) { exit(0); }

    # if input buffer contains a full line, return it, otherwise continue 
    # with the polling and reading loop for getting the rest of the line

    $pos = index($input_buffer, "\n");

    if ($pos != -1) {
      $line = substr($input_buffer, 0, $pos);
      substr($input_buffer, 0, $pos + 1) = "";
      return $line;
    }

  }
}


sub open_outputs {

  if (defined($output_file)) {

    if ($output_file ne "-") {

      while (!open($output_fh, ">>", $output_file)) {
        if ($! == EINTR)  { next; }
        print STDERR "Can't open output file $output_file for writing: $!\n";
        exit(1);
      }

    } else {

      while (!open($output_fh, ">&", STDOUT)) {
        if ($! == EINTR)  { next; }
        print STDERR "Can't dup standard output: $!\n";
        exit(1);
      }
    }

    select($output_fh);
    $| = 1;
    select(STDOUT);
  }

  if (defined($syslog_tag)) {

    eval { openlog($syslog_tag, "pid", $syslog_facility) };

    if ($@) {
      print STDERR "Can't connect to syslog: $@\n";
      exit(1);
    }
  }

}


sub hup_handler {

  $SIG{HUP} = \&hup_handler;
  $reopen_output = 1;
}


sub usr2_handler {

  $SIG{USR2} = \&usr2_handler;
  $dumpstate = 1;
}


sub term_handler {

  $SIG{TERM} = \&term_handler;
  $terminate = 1;
}


sub main_loop {

  my($line, $json, $ref, $src_port, $dst_port);
  my($session_id, $time, $last_alert_proc);

  $last_alert_proc = time();

  for (;;) {

    if ($reopen_output) {

      if (defined($output_file)) { close($output_fh); }
      if (defined($syslog_tag)) { eval { closelog() }; }

      open_outputs();

      $reopen_output = 0;
    }

    if ($dumpstate) {
      if (defined($statefile)) { write_state_file(); }
      $dumpstate = 0;
    }

    if ($terminate) {
      if (defined($statefile)) { write_state_file(); }
      exit(0);
    }

    $time = time();

    if ($time - $last_maintenance >= $scantime) {
      maintain_lists();
      $last_maintenance = $time;
    }

    if ($session_length && $time > $last_alert_proc) {
      process_stored_alerts();
      $last_alert_proc = $time;
    }

    $line = read_line();

    if (!defined($line)) {
      select(undef, undef, undef, $sleeptime);
      next;
    }

    if (defined($parser_regexp)) {

      if ($line !~ $parser_regexp) {
        next;
      }

      if (!defined($+{json})) { next; }

      $json = $+{json};

    } else {

      $json = $line;
    }

    # decode JSON data in Suricata EVE event

    eval { $ref = decode_json($json); };

    if ($@) {
      print STDERR "Malformed JSON '$json': $@\n";
      next;
    }

    # ignore events which are not IDS alerts

    if ($ref->{"event_type"} ne "alert") { next; }

    $src_port = exists($ref->{"src_port"})?$ref->{"src_port"}:0;
    $dst_port = exists($ref->{"dest_port"})?$ref->{"dest_port"}:0;
 
    ($ref->{"intip"}, $ref->{"intport"}, $ref->{"extip"}, $ref->{"extport"}) = 
      detect_int_ext($ref->{"src_ip"}, $src_port, $ref->{"dest_ip"}, $dst_port);

    if (!defined($ref->{"intip"})) { next; }

    $session_id = store_alert($ref);  

    if (!$session_length) {
      process_alert($alerts{$session_id});
      delete $alerts{$session_id};
    }

  }
}


#####################################################################

# parse command line options

get_options();

# create pid file if --pid command line option was provided

if (defined($pid_file)) {

  my($handle);

  if (!open($handle, ">", $pid_file)) {
    print STDERR "Can't open pidfile $pid_file: $!\n";
    exit(1);
  }

  print $handle "$$\n";

  close($handle);
}

# initialize variables

$max_clusters = 0;
$max_candidates = 0;

$last_maintenance = time();

$input_buffer = "";

$app_proto_func{"tls"} = \&process_tls_alert;
$app_proto_func{"smtp"} = \&process_smtp_alert;
$app_proto_func{"dns"} = \&process_dns_alert;
$app_proto_func{"ssh"} = \&process_ssh_alert;
$app_proto_func{"http"} = \&process_http_alert;

%attributes = ( "SignatureID" => 1,
                "Proto" => 1, 
                "IntIP" => 1, 
                "IntPort" => 1,
                "ExtIP" => 1, 
                "ExtPort" => 1, 
                "AppProto" => 1,
                "HttpHostname" => 1, 
                "HttpContentType" => 1, 
                "HttpMethod" => 1, 
                "HttpRequestBody" => 1, 
                "HttpResponseBody" => 1, 
                "HttpUserAgent" => 1,
                "HttpProtocol" => 1, 
                "HttpStatus" => 1, 
                "HttpUrl" => 1, 
                "TlsFingerprint" => 1, 
                "TlsIssuerDn" => 1, 
                "TlsJa3hash" => 1, 
                "TlsSni" => 1, 
                "TlsSubject" => 1, 
                "TlsVersion" => 1,
                "SmtpHelo" => 1, 
                "SmtpMailFrom" => 1, 
                "SmtpRcptTo" => 1, 
                "EmailFrom" => 1, 
                "EmailStatus" => 1, 
                "EmailTo" => 1, 
                "DnsRrname" => 1, 
                "DnsRrtype" => 1, 
                "SshServerProto" => 1, 
                "SshServerSoftware" => 1,
                "SshClientProto" => 1, 
                "SshClientSoftware" => 1 );

# create the default centroid

$default_centroid = create_centroid("Default centroid");

# set signal handlers for HUP, USR2 and TERM

$reopen_output = 0;
$SIG{HUP} = \&hup_handler;

$dumpstate = 0;
$SIG{USR2} = \&usr2_handler;

$terminate = 0;
$SIG{TERM} = \&term_handler;

# make standard error unbuffered

select(STDERR);
$| = 1;
select(STDOUT);

# if --statefile command line option has been provided, restore
# candidates, clusters and the default centroid from state file

if (defined($statefile)) { read_state_file(); }

# open outputs

open_outputs();

# main loop

main_loop();

