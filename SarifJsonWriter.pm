#!/usr/bin/perl -w

package SarifJsonWriter;
use JSON::Streaming::Writer;
use Cwd;
use strict;

my $sarifVersion = "2.0.0";
my $sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema.json";

# Instantiates the writer and store some data for later use
sub new {
    my ($class, $parameters) = @_;

    open(my $fh, '>:encoding(UTF-8)', $parameters->{filename}) or die "Can't open $parameters->{filename}: $!";

    my $self = {};

    $self->{argv} = $parameters->{argvs};
    if ($parameters->{buildDir}) {
        $self->{buildDir} = $parameters->{buildDir};
    }
    if ($parameters->{invocations}) {
        $self->{invocations} = $parameters->{invocations};
    }
    if ($parameters->{sha256hashes}) {
        $self->{sha256hashes} = $parameters->{sha256hashes};
    }
    $self->{startTime} = ConvertEpoch($parameters->{startTime});

    $self->{fh} = $fh;
    $self->{writer} = JSON::Streaming::Writer->for_stream($fh);
    $self->{writer}->pretty_output($parameters->{pretty});

    bless $self, $class;
    return $self;
}

# Start writing initial data to the sarif file and save some data for later use
sub AddStartTag {
    my ($self, $initialData) = @_;
    my $writer = $self->{writer};

    $writer->start_object(); # Start sarif object
    $writer->add_property("version", $sarifVersion);
    $writer->add_property("\$schema", $sarifSchema);
    $writer->start_property("runs");
    $writer->start_array();

    my $path = AdjustPath(".", $initialData->{build_root_dir}, $initialData->{package_root_dir});
    $path = "file://".$path;

    $self->{root} = $path;
    $self->{uriBaseId} = $initialData->{build_root_dir};
    $self->{package_root_dir} = $initialData->{package_root_dir};

    # start new run object
    $writer->start_object();

    $writer->add_property("instanceGuid", $initialData->{uuid});
    $writer->start_property("tool");
    $writer->start_object();
    $writer->add_property("name", $initialData->{tool_name});
    $writer->add_property("version", $initialData->{tool_version});
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("originalUriBaseIds");
    $writer->start_object();
    $writer->add_property("PKGROOT", $self->{root});
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("properties");
    $writer->start_object();
    $writer->add_property("packageName", $initialData->{package_name});
    $writer->add_property("packageVersion", $initialData->{package_version});
    $writer->end_object();
    $writer->end_property();

    # Data from assessment summary
    my $invocations = $self->{invocations};
    if ($invocations) {
        $writer->start_property("invocations");
        $writer->start_array();

        foreach my $id (keys %{$invocations}) {
            $writer->start_object();
            CheckAndAddInvocation($self, "commandLine", $invocations->{$id}{commandLine});

            if (@{$invocations->{$id}{args}} > 1) {
                $writer->start_property("arguments");
                $writer->start_array();
                foreach my $arg (@{$invocations->{$id}{args}}) {
                    $writer->add_string($arg);
                    }
                    $writer->end_array();
                    $writer->end_property();
            }

            CheckAndAddInvocation($self, "startTime", $invocations->{$id}{startTime});
            CheckAndAddInvocation($self, "endTime", $invocations->{$id}{endTime});
            CheckAndAddInvocation($self, "workingDirectory", $invocations->{$id}{workingDirectory});

            if (defined $invocations->{$id}{env}) {
                $writer->start_property("environmentVariables");
                $writer->start_object();
                foreach my $key (keys %{$invocations->{$id}{env}}) {
                    my $value = $invocations->{$id}{env}{$key};
                    $writer->add_property($key, $value);
                }
                $writer->end_object();
                $writer->end_property();
            }

            CheckAndAddInvocation($self, "exitCode", $invocations->{$id}{exitCode});

            $writer->end_object();
        }

        $writer->end_array();
        $writer->end_property();
    }

    # Open results object
    $writer->start_property("results");
    $writer->start_array();
}

# Called when data for a bug instance is gathered.
# Writes out a result object, saves some data related to the bug
# for later use.
sub AddBugInstance {
    my ($self, $bugData) = @_;
    my $writer = $self->{writer};

    $writer->start_object();

    my @ruleId = ();
    push @ruleId, $bugData->{BugGroup} if $bugData->{BugGroup};
    push @ruleId, $bugData->{BugCode} if $bugData->{BugCode};
    $writer->add_property("ruleId", join('/', @ruleId));
    die "SCARF file has no BugGroup nor BugCode: $!" if @ruleId == 0;

    $writer->add_property("level", "warning");

    my $message = $bugData->{BugMessage};
    $message =~ s/\n\n Bug\ Path:\s* $ $ .*\Z//xms;
    $writer->start_property("message");
    $writer->start_object();
    $writer->add_property("text", $message);
    $writer->end_object();
    $writer->end_property();

    my $numLocations = @{$bugData->{BugLocations}};
    if ($numLocations > 0) {
        $writer->start_property("locations");
        $writer->start_array();

        foreach my $location (@{$bugData->{BugLocations}}) {
            if ($location->{primary}) {
                $writer->start_object();
                $writer->start_property("physicalLocation");
                $writer->start_object();
                $writer->start_property("fileLocation");
                $writer->start_object();
                my $filename = AdjustPath($self->{package_root_dir}, ".", $location->{SourceFile});
                $writer->add_property("uri", $filename);
                $writer->add_property("uriBaseId", "PKGROOT");
                $writer->end_object();
                $writer->end_property();

                if ((exists $location->{StartLine}) || (exists $location->{EndLine}) ||
                    (exists $location->{StartColumn}) || (exists $location->{EndColumn})) {
                    $writer->start_property("region");
                    $writer->start_object();

                    if (exists $location->{StartLine}) {
                        $writer->add_property("startLine", MakeInt($location->{StartLine}));
                    }
                    if (exists $location->{EndLine}) {
                        $writer->add_property("endLine", MakeInt($location->{EndLine}));
                    }
                    if (exists $location->{StartColumn}) {
                        $writer->add_property("startColumn", MakeInt($location->{StartColumn}));
                    }
                    if (exists $location->{EndColumn}) {
                        $writer->add_property("endColumn", MakeInt($location->{EndColumn}));
                    }

                    if ((!exists $location->{StartLine}) || (!exists $location->{EndLine})) {
                        die "start/end line doesn't exist in $location->{SourceFile}";
                    }

                    my $snippetFile = $self->{buildDir}.$location->{SourceFile};
                    if (-r $snippetFile) {
                        open (my $snippetFh, '<', $snippetFile) or die "Can't open $snippetFile: $!";

                        my $count = 1;
                        my $snippetString = "";
                        while(<$snippetFh>) {
                            if ($count > $location->{EndLine}) {
                                $writer->start_property("snippet");
                                $writer->start_object();
                                $writer->add_property("text", $snippetString);
                                $writer->end_object();
                                $writer->end_property();
                                close $snippetFh;
                                last;
                            }
                            if ($count >= $location->{StartLine}) {
                                $snippetString = $snippetString.$_;
                            }
                            $count++;
                        }
                    } else {
                        print STDERR "Unable to find $snippetFile\n";
                    }

                    $writer->end_object();
                    $writer->end_property();
                }

                $writer->end_object();
                $writer->end_property();

                if (defined $location->{Explanation}) {
                    $writer->start_property("message");
                    $writer->start_object();
                    $writer->add_property("text", $location->{Explanation});
                    $writer->end_object();
                    $writer->end_property();
                }

                $writer->end_object();

                # Store file uri to hash
                $self->{files}{$location->{SourceFile}} = 1;
            }
        }
        $writer->end_array();
        $writer->end_property();
    }

    $writer->start_property("conversionProvenance");
    $writer->start_array();
    $writer->start_object();
    $writer->start_property("fileLocation");
    $writer->start_object();
    $writer->add_property("uri", $bugData->{AssessmentReportFile});
    $writer->end_object();
    $writer->end_property();
    $writer->end_object();
    $writer->end_array();
    $writer->end_property();

    # Add CodeFlows object
    if (@{$bugData->{BugLocations}} > 1) {
        $writer->start_property("codeFlows");
        $writer->start_array();
        $writer->start_object();
        $writer->start_property("threadFlows");
        $writer->start_array();
        $writer->start_object();
        $writer->start_property("locations");
        $writer->start_array();
        AddThreadFlowsLocations($self, $bugData->{BugLocations});
        $writer->end_array();
        $writer->end_property();
        $writer->end_object();
        $writer->end_array();
        $writer->end_property();
        $writer->end_object();
        $writer->end_array();
        $writer->end_property();
    }

    # Save ClassName
    if (defined $bugData->{ClassName}) {
        $self->{ClassNames}{$bugData->{ClassName}} = 1;
    }

    # Save all method names
    foreach my $method (@{$bugData->{Methods}}) {
        $self->{Methods}{$method->{name}} = 1;
    }

    # Write data to property bad object
    if ($bugData->{BugSeverity} || $bugData->{CweIds}) {
        $writer->start_property("properties");
        $writer->start_object();

        if ($bugData->{BugSeverity}) {
            $writer->add_property("toolSeverity", $bugData->{BugSeverity});
        }

        if (@{$bugData->{CweIds}} > 0) {
            $writer->start_property("tags");
            $writer->start_array();
            foreach my $cweId (@{$bugData->{CweIds}}) {
                $writer->add_string("CWE/".$cweId);
            }
            $writer->end_array();
            $writer->end_property();
        }

        $writer->end_object();
        $writer->end_property();
    }

    $writer->end_object();

}

# Closes results array, write data saved from AddBugInstance()
# and finishes writing the SARIF file
sub Close {
    my ($self) = @_;
    my $writer = $self->{writer};

    $writer->end_array();
    $writer->end_property();
    AddLogicalLocations($self);
    AddFilesObject($self);
    AddConversionObject($self);
    $writer->end_object();

    $writer->end_array();
    $writer->end_property();
    $writer->end_object;
    close $self->{fh};
}

sub CheckAndAddInvocation {
    my ($self, $propertyName, $propertyValue) = @_;

    if (defined $propertyValue) {
        if ($propertyName eq "exitCode") {
            $self->{writer}->add_property($propertyName, MakeInt($propertyValue));
        } else {
            $self->{writer}->add_property($propertyName, $propertyValue);
        }
    }
}

# Helper function to write the logicalLocations object
sub AddLogicalLocations {
    my ($self) = @_;
    my $writer = $self->{writer};

    if ($self->{ClassNames} || $self->{Methods}) {
        $writer->start_property("logicalLocations");
        $writer->start_object();

        foreach my $className (keys %{$self->{ClassNames}}) {
            $writer->start_property($className);
            $writer->start_object();
            $writer->add_property("name", $className);
            $writer->add_property("kind", "type");
            $writer->end_object();
            $writer->end_property();
        }

        foreach my $method (keys %{$self->{Methods}}) {
            $writer->start_property($method);
            $writer->start_object();
            $writer->add_property("name", $method);
            $writer->add_property("kind", "function");
            $writer->end_object();
            $writer->end_property();
        }

        $writer->end_object();
        $writer->end_property();
    }
}

# Helper function to write the Files object
sub AddFilesObject {
    my ($self) = @_;
    my $writer = $self->{writer};

    $writer->start_property("files");
    $writer->start_object();
    foreach my $file (keys %{$self->{files}}) {
        my $filename = AdjustPath($self->{package_root_dir}, ".", $file);
        my $hashPath = "build/".$file;

        $writer->start_property($filename);
        $writer->start_object();

        if ($self->{sha256hashes}) {
            my $sha256 = FindSha256Hash($self->{sha256hashes}, $hashPath);
            if (defined $sha256) {
                $writer->start_property("hashes");
                $writer->start_array();
                $writer->start_object();
                $writer->add_property("algorithm", "sha-256");
                $writer->add_property("value", $sha256);
                $writer->end_object();
                $writer->end_array();
                $writer->end_property();
            } else {
                print "Unable to find sha256 hash for $file\n";
            }
        }
        
        $writer->end_object();
        $writer->end_property();
    }
    $writer->end_object();
    $writer->end_property();

    undef %{$self->{files}};
}

# Helper function to find the sha256 hash for a file
# Parameters:
# sha256   -> hash containing the key(filename) and value(sha256 hash) pair
# filename -> the path of the file including its name
sub FindSha256Hash {
    my ($sha256, $filename) = @_;

    while ($filename =~ s/[^\/]+\/\.\.(\/|$)//) {
    }

    return $sha256->{$filename};
}

# Helper function to write the conversion object
sub AddConversionObject {
    my ($self) = @_;
    my $writer = $self->{writer};
    
    $writer->start_property("conversion");
    $writer->start_object();
    $writer->start_property("tool");
    $writer->start_object();
    $writer->add_property("name", "SWAMP SARIF Translator");
    $writer->add_property("version", "0.0.1");
    $writer->end_object();
    $writer->end_property();
    
    $writer->start_property("invocation");
    
    $writer->start_object();
    $writer->add_property("commandLine", $0);
    
    $writer->start_property("arguments");
    $writer->start_array();
    foreach my $arg (@{$self->{argv}}) {
        $writer->add_string($arg);
    }
    $writer->end_array();
    $writer->end_property();
    $writer->add_property("workingDirectory", getcwd());
    $writer->start_property("environmentVariables");
    $writer->start_object();
    foreach (sort keys %ENV) {
        $writer->add_property($_, $ENV{$_});
    }
    $writer->end_object();
    $writer->end_property();
    $writer->add_property("exitCode", 0);
    $writer->add_property("startTime", $self->{startTime});
    $writer->add_property("endTime", ConvertEpoch(time()));
   
    $writer->end_object();
    $writer->end_property(); # end invocation
    
    $writer->end_object();
    $writer->end_property();
}   

# Helper function to write the threadFLowLocations object
sub AddThreadFlowsLocations {
    my ($self, $locations) = @_;
    my $writer = $self->{writer};

    foreach my $location (@{$locations}) {
        $writer->start_object();

        $writer->add_property("importance", "essential");
        $writer->start_property("location");
        $writer->start_object();
        $writer->start_property("physicalLocation");
        $writer->start_object();
        $writer->start_property("fileLocation");
        $writer->start_object();
        my $filename = AdjustPath($self->{package_root_dir}, ".", $location->{SourceFile});
        $writer->add_property("uri", $filename);
        $writer->add_property("uriBaseId", "PKGROOT");
        $writer->end_object();
        $writer->end_property();

        if ((exists $location->{StartLine}) || (exists $location->{EndLine}) ||
            (exists $location->{StartColumn}) || (exists $location->{EndColumn})) {
            $writer->start_property("region");
            $writer->start_object();
            if (exists $location->{StartLine}) {
                $writer->add_property("startLine", MakeInt($location->{StartLine}));
            }
            if (exists $location->{EndLine}) {
                $writer->add_property("endLine", MakeInt($location->{EndLine}));
            }
            if (exists $location->{StartColumn}) {
                $writer->add_property("startColumn", MakeInt($location->{StartColumn}));
            }
            if (exists $location->{EndColumn}) {
                $writer->add_property("endColumn", MakeInt($location->{EndColumn}));
            }
            $writer->end_object();
            $writer->end_property();
        }

        $writer->end_object();
        $writer->end_property(); # end physicalLocation

        if (defined $location->{Explanation}) {
            $writer->start_property("message");
            $writer->start_object();
            $writer->add_property("text", $location->{Explanation});
            $writer->end_object();
            $writer->end_property();
        }

        $writer->end_object();
        $writer->end_property(); # end location

        $writer->end_object();
    }
}

# NormalizePath - take a path and remove empty and '.' directory components
#                 empty directories become '.'
sub NormalizePath {
    my $p = shift;

    $p =~ s/\/\/+/\//g;        # collapse consecutive /'s to one /
    $p =~ s/\/(\.\/)+/\//g;    # change /./'s to one /
    $p =~ s/^\.\///;           # remove initial ./
    $p = '.' if $p eq '';      # change empty dirs to .
    $p =~ s/\/\.$/\//;                 # remove trailing . directory names
    $p =~ s/\/$// unless $p eq '/'; # remove trailing /
    
    return $p;
}

# AdjustPath - take a path that is relative to curDir and make it relative
#              to baseDir.  If the path is not in baseDir, do not modify.
#
#       baseDir    - the directory to make paths relative to
#       curDir     - the directory paths are currently relative to
#       path       - the path to change
sub AdjustPath {
    my ($baseDir, $curDir, $path) = @_;

    $baseDir = NormalizePath($baseDir);
    $curDir = NormalizePath($curDir);
    $path = NormalizePath($path);

    # if path is relative, prefix with current dir
    if ($path eq '.') {
        $path = $curDir;
    } elsif ($curDir ne '.' && $path !~ /^\//) {
        $path = "$curDir/$path";
    }

    # remove initial baseDir from path if baseDir is not empty
    $path =~ s/^\Q$baseDir\E\///;

    return $path;
}

# Convert Epoch time to UTC time and returns string that adheres to the SARIF format
sub ConvertEpoch {
    my ($time) = @_;

    my $fraction;
    if ($time =~ /.+\.(.+)/) {
        $fraction = $1;
    }

    my ($sec, $min, $hour, $day, $month, $year) = gmtime($time);

    $year += 1900;
    $month += 1;

    if ($month < 10) {
        $month = "0".$month;
    }
    if ($day < 10) {
        $day = "0".$day;
    }
    if ($hour < 10) {
        $hour = "0".$hour;
    }
    if ($min < 10) {
        $min = "0".$min;
    }
    if ($sec < 10) {
        $sec = "0".$sec;
    }

    if ($fraction) {
        return sprintf("%d-%02d-%02d%s%02d:%02d:%02d.%s%s", $year, $month, $day, "T", $hour, $min, $sec, $fraction, "Z");
    } else {
        return sprintf("%d-%02d-%02d%s%02d:%02d:%02d%s", $year, $month, $day, "T", $hour, $min, $sec, "Z");
    }
}

# Make the integer that is in a string into integer
sub MakeInt {
    my ($var) = @_;

    return 0 + $var;
}

1;
