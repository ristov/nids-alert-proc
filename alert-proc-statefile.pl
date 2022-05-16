#!/usr/bin/perl -w


use Storable;

if (scalar(@ARGV) < 1) {
  die "Usage: $0 <statefile>\n";
}

$statefile = $ARGV[0];

sub print_centroid {

  my($centroid) = $_[0];
  my($attr, $value);
  
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

#####################################################################

binmode(STDOUT, ":encoding(UTF-8)");

$ref = eval { retrieve($statefile) };

if (!defined($ref)) {
  print STDERR "Can't read state file $statefile: $!\n";
  exit(1);
}

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
