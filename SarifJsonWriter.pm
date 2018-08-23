#!/usr/bin/perl -w

package SarifJsonWriter;
use JSON::Streaming::Writer;
use Data::Dumper;
use Cwd;
use strict;

sub new {
    my ($class, $parameters) = @_;

    open(my $fh, '>:encoding(UTF-8)', $parameters->{filename}) or die "Can't open $parameters->{filename}: $!";

    my $self = {};


    $self->{options} = $parameters->{options};
    $self->{argv} = $parameters->{argvs};
    if ($parameters->{summary}) {
        $self->{assessment_summary} = $parameters->{summary};
    }
    $self->{sha256hashes} = $parameters->{sha256hashes};
    $self->{startTime} = $parameters->{startTime};

    $self->{fh} = $fh;
    $self->{writer} = JSON::Streaming::Writer->for_stream($fh);
    $self->{writer}->pretty_output($parameters->{pretty});

    $self->{writer}->start_object();
    $self->{writer}->add_property("version", "2.0.0");
    $self->{writer}->start_property("runs");
    $self->{writer}->start_array();

    $self->{counter} = 0;

    bless $self, $class;
    return $self;
}

sub AddStartTag {
    my ($self, $initialHash) = @_;

    $self->{tool_name} = $initialHash->{name};
    $self->{tool_version} = $initialHash->{version};

    my $path = AdjustPath(".", $initialHash->{uriBaseId}, $initialHash->{package_root_dir});
    $path = "file://".$path;

    $self->{root} = $path;
    $self->{uriBaseId} = $initialHash->{uriBaseId};
    $self->{package_root_dir} = $initialHash->{package_root_dir};

    # start new run object
    $self->{writer}->start_object();

    $self->{writer}->add_property("instanceGuid", $initialHash->{instanceGuid});
    $self->{writer}->start_property("tool");
    $self->{writer}->start_object();
    $self->{writer}->add_property("name", $initialHash->{tool_name});
    $self->{writer}->add_property("version", $initialHash->{tool_version});
    $self->{writer}->end_object();
    $self->{writer}->end_property();

    $self->{writer}->start_property("originalUriBaseIds");
    $self->{writer}->start_object();
    $self->{writer}->add_property("PKGROOT", $self->{root});
    $self->{writer}->end_object();
    $self->{writer}->end_property();

    # Data from assessment summary
    if ($self->{options}{summary}) {
        $self->{writer}->start_property("invocations");
        $self->{writer}->start_array();

        foreach my $id (keys %{$self->{assessment_summary}}) {
            $self->{writer}->start_object();
            $self->{writer}->add_property("commandLine", $self->{assessment_summary}{$id}{commandLine});

            $self->{writer}->start_property("arguments");
            $self->{writer}->start_array();
            foreach my $arg (@{$self->{assessment_summary}{$id}{args}}) {
                $self->{writer}->add_string($arg);
            }
            $self->{writer}->end_array();
            $self->{writer}->end_property();

            $self->{writer}->add_property("startTime", $self->{assessment_summary}{$id}{startTime});
            $self->{writer}->add_property("endTime", $self->{assessment_summary}{$id}{endTime});
            $self->{writer}->add_property("workingDirectory", $self->{assessment_summary}{$id}{workingDirectory});

            $self->{writer}->start_property("environmentVariables");
            $self->{writer}->start_object();
            foreach my $key (keys %{$self->{assessment_summary}{$id}{env}}) {
                my $value = $self->{assessment_summary}{$id}{env}{$key};
                $self->{writer}->add_property($key, $value);
            }
            $self->{writer}->end_object();
            $self->{writer}->end_property();

            $self->{writer}->add_property("exitCode", MakeInt($self->{assessment_summary}{$id}{exitCode}));

            $self->{writer}->end_object();
        }

        $self->{writer}->end_array();
        $self->{writer}->end_property();
    }

    # Open results
    $self->{writer}->start_property("results");
    $self->{writer}->start_array();
}

sub AddBugInstance {
    my ($self, $bugData) = @_;

    # Add bug
    $self->{writer}->start_object();

    # FIXME Program dies if BugGroup or BugCode contains a "/"
    if ($bugData->{BugGroup} =~ m/\// or $bugData->{BugCode} =~ m/\//) {
        die "BugGroup or BugCode contains a \"/\": $!";
    }
    $self->{writer}->add_property("ruleId", $bugData->{BugGroup}."/".$bugData->{BugCode});

    my $message = $bugData->{BugMessage};
    # FIXME Regex to correctly deal with end of lines
    #$message =~ s/\n\nBug Path:\s*\n\n.*\Z//s;
    $message =~ s/\n\n Bug\ Path:\s* $ $ .*\Z//xms;
    $self->{writer}->start_property("message");
    $self->{writer}->start_object();
    $self->{writer}->add_property("text", $message);
    $self->{writer}->end_object();
    $self->{writer}->end_property();

    $self->{writer}->start_property("locations");
    $self->{writer}->start_array();
    if ($self->{counter} == 8649) {
        #print Dumper($bugData->{BugLocations});
    } else {
        $self->{counter} += 1;
    }
        
    foreach my $location (@{$bugData->{BugLocations}}) {
        if ($location->{primary}) {
            $self->{writer}->start_object();
            $self->{writer}->start_property("physicalLocation");
            $self->{writer}->start_object();
            $self->{writer}->start_property("fileLocation");
            $self->{writer}->start_object();
            my $filename = AdjustPath($self->{package_root_dir}, ".", $location->{SourceFile});
            $self->{writer}->add_property("uri", $filename);
            $self->{writer}->add_property("uriBaseId", "PKGROOT");
            $self->{writer}->end_object();
            $self->{writer}->end_property();

            if ((exists $location->{StartLine}) || (exists $location->{EndLine}) ||
                    (exists $location->{StartColumn}) || (exists $location->{EndColumn})) {
                $self->{writer}->start_property("region");
                $self->{writer}->start_object();
                
                if (exists $location->{StartLine}) {
                    $self->{writer}->add_property("startLine", MakeInt($location->{StartLine}));
                }
                if (exists $location->{EndLine}) {
                    $self->{writer}->add_property("endLine", MakeInt($location->{EndLine}));
                }
                if (exists $location->{StartColumn}) {
                    $self->{writer}->add_property("startColumn", MakeInt($location->{StartColumn}));
                }
                if (exists $location->{EndColumn}) {
                    $self->{writer}->add_property("endColumn", MakeInt($location->{EndColumn}));
                }
                
                if ((!exists $location->{StartLine}) || (!exists $location->{EndLine})) {
                    die "start/end line doesn't exist in $location->{SourceFile}";
                }

                # pass file path to FindSha256Hash function to check for existence of file
                my $hashName = "build/".$location->{SourceFile};
                my $exists = FindSha256Hash($self->{sha256hashes}, $hashName);
                if ($self->{options}{build} and defined $exists) {
                    my $name = $self->{options}{build}.$location->{SourceFile};
                    open (my $file, '<', $name) or die "Can't open $name: $!";

                    my $count = 1;
                    my $snippetString = "";
                    while(<$file>) {
                        if ($count > $location->{EndLine}) {
                            #print "$count: $snippetString\n-------------------------\n";
                            $self->{writer}->start_property("snippet");
                            $self->{writer}->start_object();
                            $self->{writer}->add_property("text", $snippetString);
                            $self->{writer}->end_object();
                            $self->{writer}->end_property();
                            close $file;
                            last;
                        }
                        if ($count >= $location->{StartLine}) {
                            $snippetString = $snippetString.$_;
                        }
                        $count++;
                    }
                }
                
                $self->{writer}->end_object();
                $self->{writer}->end_property();
            }

            $self->{writer}->end_object();
            $self->{writer}->end_property();

            if (defined $location->{Explanation}) {
                $self->{writer}->start_property("message");
                $self->{writer}->start_object();
                $self->{writer}->add_property("text", $location->{Explanation});
                $self->{writer}->end_object();
                $self->{writer}->end_property();
            }

            $self->{writer}->end_object();

            # Add file uri to hash
            $self->{files}{$location->{SourceFile}} = 1;
        }
    }
    $self->{writer}->end_array();
    $self->{writer}->end_property();

    $self->{writer}->start_property("conversionProvenance");
    $self->{writer}->start_array();
    $self->{writer}->start_object();
    $self->{writer}->start_property("fileLocation");
    $self->{writer}->start_object();
    $self->{writer}->add_property("uri", $bugData->{AssessmentReportFile});
    $self->{writer}->end_object();
    $self->{writer}->end_property();
    $self->{writer}->end_object();
    $self->{writer}->end_array();
    $self->{writer}->end_property();

    # Add CodeFlows object
    if (@{$bugData->{BugLocations}} > 1) {
        $self->{writer}->start_property("codeFlows");
        $self->{writer}->start_array();
        $self->{writer}->start_object();
        $self->{writer}->start_property("threadFlows");
        $self->{writer}->start_array();
        $self->{writer}->start_object();
        $self->{writer}->start_property("locations");
        $self->{writer}->start_array();
        AddThreadFlowsLocations($self, $bugData->{BugLocations});
        $self->{writer}->end_array();
        $self->{writer}->end_property();
        $self->{writer}->end_object();
        $self->{writer}->end_array();
        $self->{writer}->end_property();
        $self->{writer}->end_object();
        $self->{writer}->end_array();
        $self->{writer}->end_property();
    }

    if (defined $bugData->{ClassName}) {
        $self->{ClassNames}{$bugData->{ClassName}} = 1;
    }

    foreach my $method (@{$bugData->{Methods}}) {
        $self->{Methods}{$method->{name}} = 1;
    }

    if (defined $bugData->{InstanceLocation}{Xpath}) {
        $self->{writer}->start_property("properties");
        $self->{writer}->start_object();
        $self->{writer}->add_property("Xpath", $bugData->{InstanceLocation}{Xpath});
        $self->{writer}->end_object();
        $self->{writer}->end_property();
    }

    $self->{writer}->end_object();

}

sub Close {
    my ($self) = @_;

    # end run object
    $self->{writer}->end_array();
    $self->{writer}->end_property();
    AddLogicalLocations($self);
    AddFilesObject($self);
    AddConversionObject($self);
    $self->{writer}->end_object();

    $self->{writer}->end_array();
    $self->{writer}->end_property();
    $self->{writer}->end_object;
    close $self->{fh};
}

sub AddLogicalLocations {
    my ($self) = @_;

    if ($self->{ClassNames} || $self->{Methods}) {
        $self->{writer}->start_property("logicalLocations");
        $self->{writer}->start_object();

        foreach my $className (keys %{$self->{ClassNames}}) {
            $self->{writer}->start_property($className);
            $self->{writer}->start_object();
            $self->{writer}->add_property("name", $className);
            $self->{writer}->add_property("kind", "type");
            $self->{writer}->end_object();
            $self->{writer}->end_property();
        }

        foreach my $method (keys %{$self->{Methods}}) {
            $self->{writer}->start_property($method);
            $self->{writer}->start_object();
            $self->{writer}->add_property("name", $method);
            $self->{writer}->add_property("kind", "function");
            $self->{writer}->end_object();
            $self->{writer}->end_property();
        }

        $self->{writer}->end_object();
        $self->{writer}->end_property();
    }
}

sub AddFilesObject {
    my ($self) = @_;

    $self->{writer}->start_property("files");
    $self->{writer}->start_object();
    foreach my $file (keys %{$self->{files}}) {
        my $filename = AdjustPath($self->{package_root_dir}, ".", $file);
        my $hashPath = "build/".$file;

        $self->{writer}->start_property($filename);
        $self->{writer}->start_object();

        if ($self->{options}{hashes}) {
            my $sha256 = FindSha256Hash($self->{sha256hashes}, $hashPath);
            if (defined $sha256) {
                $self->{writer}->start_property("hashes");
                $self->{writer}->start_array();
                $self->{writer}->start_object();
                $self->{writer}->add_property("algorithm", "sha-256");
                $self->{writer}->add_property("value", $sha256);
                $self->{writer}->end_object();
                $self->{writer}->end_array();
                $self->{writer}->end_property();
            } else {
                print "Unable to find sha256 hash for $file\n";
                #die "Unable to find sha256 hash for $file";
            }
        }
        
        $self->{writer}->end_object();
        $self->{writer}->end_property();
    }
    $self->{writer}->end_object();
    $self->{writer}->end_property();

    undef %{$self->{files}};
}

sub FindSha256Hash {
    my ($sha256, $filename) = @_;

    while ($filename =~ s/[^\/]+\/\.\.(\/|$)//) {
    }

    return $sha256->{$filename};
}

sub AddConversionObject {
    my ($self) = @_;
    
    $self->{writer}->start_property("conversion");
    $self->{writer}->start_object();
    $self->{writer}->start_property("tool");
    $self->{writer}->start_object();
    $self->{writer}->add_property("name", "SWAMP SARIF Translator");
    $self->{writer}->add_property("version", "0.0.1");
    $self->{writer}->end_object();
    $self->{writer}->end_property();
    
    $self->{writer}->start_property("invocation");
    
    $self->{writer}->start_object();
    $self->{writer}->add_property("commandLine", $0);
    
    $self->{writer}->start_property("arguments");
    $self->{writer}->start_array();
    foreach my $arg (@{$self->{argv}}) {
        $self->{writer}->add_string($arg);
    }
    $self->{writer}->end_array();
    $self->{writer}->end_property();
    $self->{writer}->add_property("startTime", $self->{startTime});
    $self->{writer}->add_property("endTime", ConvertEpoch(time()));
    $self->{writer}->add_property("workingDirectory", getcwd());
    $self->{writer}->start_property("environmentVariables");
    $self->{writer}->start_object();
    #foreach (sort keys %ENV) {
        #self->{writer}->add_property($_, $ENV{$_});
        $self->{writer}->add_property("TestKey", "TestValue"); # DELETE THIS
        #}
    $self->{writer}->end_object();
    $self->{writer}->end_property();
    $self->{writer}->add_property("exitCode", 0); # MIGHT NOT BE 0?
    
    $self->{writer}->end_object();
    $self->{writer}->end_property(); # end invocation
    
    $self->{writer}->end_object();
    $self->{writer}->end_property();
}   

sub AddThreadFlowsLocations {
    my ($self, $locations) = @_;
    foreach my $location (@{$locations}) {
        $self->{writer}->start_object();

        $self->{writer}->start_property("location");
        $self->{writer}->start_object();
        $self->{writer}->start_property("physicalLocation");
        $self->{writer}->start_object();
        $self->{writer}->start_property("fileLocation");
        $self->{writer}->start_object();
        my $filename = AdjustPath($self->{package_root_dir}, ".", $location->{SourceFile});
        $self->{writer}->add_property("uri", $filename);
        $self->{writer}->add_property("uriBaseId", "PKGROOT");
        $self->{writer}->end_object();
        $self->{writer}->end_property();

        if ((exists $location->{StartLine}) || (exists $location->{EndLine}) ||
            (exists $location->{StartColumn}) || (exists $location->{EndColumn})) {
            $self->{writer}->start_property("region");
            $self->{writer}->start_object();
            if (exists $location->{StartLine}) {
                $self->{writer}->add_property("startLine", MakeInt($location->{StartLine}));
            }
            if (exists $location->{EndLine}) {
                $self->{writer}->add_property("endLine", MakeInt($location->{EndLine}));
            }
            if (exists $location->{StartColumn}) {
                $self->{writer}->add_property("startColumn", MakeInt($location->{StartColumn}));
            }
            if (exists $location->{EndColumn}) {
                $self->{writer}->add_property("endColumn", MakeInt($location->{EndColumn}));
            }
            $self->{writer}->end_object();
            $self->{writer}->end_property();
        }

        $self->{writer}->end_object();
        $self->{writer}->end_property(); # end physicalLocation

        if (defined $location->{Explanation}) {
            $self->{writer}->start_property("message");
            $self->{writer}->start_object();
            $self->{writer}->add_property("text", $location->{Explanation});
            $self->{writer}->end_object();
            $self->{writer}->end_property();
        }

        $self->{writer}->end_object();
        $self->{writer}->end_property(); # end location

        $self->{writer}->end_object();
    }
}

# 
# NormalizePath - take a path and remove empty and '.' directory components
#                 empty directories become '.'
#
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

# 
# AdjustPath - take a path that is relative to curDir and make it relative
#              to baseDir.  If the path is not in baseDir, do not modify.
#
#       baseDir    - the directory to make paths relative to
#       curDir     - the directory paths are currently relative to
#       path       - the path to change
#
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
        return "$year-$month-$day"."T"."$hour:$min:$sec.$fraction" . "Z";
    } else {
        return "$year-$month-$day"."T"."$hour:$min:$sec" . "Z";
    }
}

#
# Makes a string of integer into integer
#
sub MakeInt {
    my ($var) = @_;

    return 0 + $var;
}

1;
