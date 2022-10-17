#!/usr/bin/perl -w
#
# alert-proc-csv 0.01 - alert-proc-csv.pl
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

use Cpanel::JSON::XS;
use Getopt::Long;

use vars qw(
  $USAGE
  $regexp
  $parser_regexp
);

$USAGE = qq!Usage: $0 [options]

Options:

  --parser=<regular expression> 

    Regular expression for matching and parsing input lines, so that alert 
    groups in JSON format are extracted. The regular expression must set 
    \$+{json} match variable to JSON data string that represents the alert 
    group. For example, the following regular expression parses alert groups 
    from syslog log files:
    'alert-proc(?:\\[\\d+\\])?: \@cee:\\s*(?<json>\\{.+\\})\\s*\$'
    By default, no regular expression is applied for matching and parsing 
    input lines, and it is assumed that each input line is a valid JSON data 
    string representing an alert group.

  --help, -?

    Print the usage information.

  --version

    Print the version information.

!;

# parse the command line

sub get_options {

  my($help, $version);

  GetOptions( "parser=s" => \$regexp,
              "help|?" => \$help, 
              "version" => \$version );

  if ($help) {
    print $USAGE;
    exit(0);
  }

  if ($version) {
    print "alert-proc-csv version 0.01, Copyright (C) 2022 Risto Vaarandi\n";
    exit(0);
  }

  if (defined($regexp)) { 

    $parser_regexp = eval { qr/$regexp/ };

    if ($@) {
      print STDERR "Invalid regular expression $regexp: $@\n";
      exit(1);
    }

  }

}

# convert protocol name to number

sub proto2int {
  
  if ($_[0] eq "ICMP") { return 1; }
  elsif ($_[0] eq "TCP") { return 6; }
  elsif ($_[0] eq "UDP") { return 17; }

  return -1;
}

# convert IPv4 address to integer representation

sub ip2int {

  if ($_[0] !~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) { return -1; }

  return ($1 << 24) + ($2 << 16) + ($3 << 8) + $4; 
}

# read lines from standard input and convert them to CSV format

sub main_loop {

  my($line, $json, $header, $ref, $field);
  my(@data, @header, @sortedkeys, @values);

  $header = 0;

  while (<STDIN>) {

    # process the line from standard input

    $line = $_;
    chomp $line;

    if (defined($regexp)) {

      if ($line !~ $parser_regexp) { next; }

      if (!defined($+{json})) { next; }
   
      $json = $+{json};

    } else {

      $json = $line;

    }

    # parse the JSON string obtained from the line

    eval { $ref = decode_json($json); };

    if ($@) {
      print STDERR "Malformed JSON '$json': $@\n";
      next;
    }

    # if parsing JSON was successful and the CSV header has not yet been
    # printed (i.e., we are dealing with the very first successfully parsed
    # line), print the CSV header (note that a number of header field names
    # are taken from the JSON string)

    if (!$header) {

      @sortedkeys = sort keys %{$ref->{"Vector"}};
        
      print "Timestamp,";
      print "SignatureText,";
      print "SignatureID,";
      print "SignatureMatchesPerDay,";
      print "AlertCount,";

      print "Proto,";
      print "ExtIP,";
      print "ExtPort,";
      print "IntIP,";
      print "IntPort,";

      print "Similarity,";
      print "Label,";

      @header = map { $_ . "Similarity" } @sortedkeys;

      print join(",", @header), "\n";

      $header = 1;

    }

    # print the data from the JSON string in CSV format

    @data = ();

    push @data, $ref->{"ReportingTime"};

    $ref->{"SignatureText"} =~ s/,//g;

    push @data, $ref->{"SignatureText"};

    if ($ref->{"SignatureID"} =~ /^1:(\d+)$/) {
      push @data, $1;
    } else {
      print STDERR "Invalid alert group $json without proper signature ID\n";
      next;
    }

    push @data, $ref->{"SignatureMatchesPerDay"};

    push @data, $ref->{"AlertCount"};

    @values = keys %{$ref->{"Proto"}};

    if (scalar(@values) > 1) { 
      push @data, -1; 
    } else { 
      push @data, proto2int($values[0]); 
    }

    push @data, ip2int($ref->{"ExtIP"});

    @values = keys %{$ref->{"ExtPort"}};

    if (scalar(@values) > 1) { 
      push @data, -1; 
    } else { 
      push @data, $values[0]; 
    }

    @values = keys %{$ref->{"IntIP"}};

    if (scalar(@values) > 1) { 
      push @data, -1; 
    } else { 
      push @data, ip2int($values[0]); 
    }

    @values = keys %{$ref->{"IntPort"}};

    if (scalar(@values) > 1) { 
      push @data, -1; 
    } else { 
      push @data, $values[0]; 
    }

    push @data, $ref->{"Similarity"};
    push @data, $ref->{"Label"};
  
    foreach $field (@sortedkeys) { push @data, $ref->{"Vector"}->{$field}; }

    print join(",", @data);

    print "\n";

  }

}

############################################################################

# make standard error and standard output unbuffered

select STDERR;
$| = 1;
select STDOUT;
$| = 1;

# parse the command line

get_options();

# read and process lines from standard input

main_loop();
