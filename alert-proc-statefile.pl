#!/usr/bin/perl -w
#
# alert-proc-statefile 0.01 - alert-proc-statefile.pl
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

use Storable;

use vars qw(
  $ref
  $statefile
);


sub print_centroid {

  my($centroid) = $_[0];
  my($attr, $value, $n, $e);
  
  print "Description: ", $centroid->{"Description"}, "\n";

  print "Creation time: ", 
        scalar(localtime($centroid->{"CreationTime"})), "\n";

  print "Update time: ", 
        scalar(localtime($centroid->{"UpdateTime"})), "\n";

  print "Number of matches: ", $centroid->{"Matches"}, "\n";

  foreach $attr (sort keys %{$centroid->{"Attributes"}}) {

    $n = scalar(keys %{$centroid->{"Attributes"}->{$attr}});
    $e = $centroid->{"Entropies"}->{$attr};

    print "Attribute table for $attr (values: $n, entropy: $e)\n";

    foreach $value (sort keys %{$centroid->{"Attributes"}->{$attr}}) {
      print "\t$value = ", $centroid->{"Attributes"}->{$attr}->{$value}, "\n";
    }

    print "\n";
  }

  print "\n";
}


sub print_statefile {

  my($ref) = $_[0];
  my($outliers, $max_clusters, $max_candidates, $id, $sig);
  my(%clusters, %candidates, %sig_matches, @signatures);

  %clusters = %{$ref->{"Clusters"}};
  %candidates = %{$ref->{"Candidates"}};

  $outliers = $ref->{"DefaultCentroid"};

  $max_clusters = $ref->{"MaxClusters"};
  $max_candidates = $ref->{"MaxCandidates"};

  %sig_matches = %{$ref->{"SignatureMatches"}};

  print scalar(keys %clusters), " clusters (max $max_clusters):\n";
  print "-" x 60, "\n\n";

  foreach $id (keys %clusters) {
    print "SignatureID: $id\n";
    print_centroid($clusters{$id});
  }

  print scalar(keys %candidates), " candidates (max $max_candidates):\n";
  print "-" x 60, "\n\n";

  foreach $id (keys %candidates) {
    print "SignatureID: $id\n";
    print_centroid($candidates{$id});
  }

  print "Centroid of outliers:\n";
  print "-" x 60, "\n\n";

  print_centroid($outliers);

  print "Signature Matches:\n";
  print "-" x 60, "\n\n";

  @signatures = sort { $sig_matches{$b}->{"Matches"} <=> $sig_matches{$a}->{"Matches"} } keys %sig_matches;

  foreach $sig (@signatures) {
    print $sig, " = ", $sig_matches{$sig}->{"Matches"};
    print " matches since ", scalar(localtime($sig_matches{$sig}->{"Time"}));
    print "\n";
  }
}


#####################################################################


# when printing state file to standard output, convert Perl wide characters
# to corresponding UTF-8 characters

binmode(STDOUT, ":encoding(UTF-8)");

# process commandline arguments

if (scalar(@ARGV) < 1) {
  die "Usage: $0 <statefile>\n";
}

$statefile = $ARGV[0];

# read data structures from state file

$ref = eval { retrieve($statefile) };

if (!defined($ref)) {
  die "Can't read state file $statefile: $!\n";
}

# print data structures read from state file

print_statefile($ref);
