#!/usr/bin/perl -w

# https://github.com/mirswamp/swamp-sarif-io
# SWAMP: https://continuousassurance.org
#
# Copyright 2018 Yuan Zhe Bugh, James A. Kupsch
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the Lincense is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package SarifJsonWriter;
use strict;
use JSON::Streaming::Writer;
use Data::Dumper;
use Exporter 'import';
our @EXPORT_OK = qw(CheckInitialData CheckInvocations CheckResultData CheckRuleData);

my $sarifVersion = "2.0.0-csd.2.beta.2019-01-09";
my $sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-2.0.0-csd.2.beta.2019-01-09.json";
my $externalSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-external-property-file-schema.json";

# Instantiates the writer and store some data for later use
sub new {
    my ($class, $output, $encoding) = @_;

    if ($encoding ne "utf-8") {
        die "Only utf-8 encoding is supported: $!"
    }

    open(my $fh, '>:encoding(UTF-8)', $output) or die "Can't open $output: $!";

    my $self = {};

    $self->{pretty} = 0;
    $self->{error_level} = 2;
    $self->{fh} = $fh;
    $self->{writer} = JSON::Streaming::Writer->for_stream($fh);
    $self->{writer}->pretty_output($self->{pretty});
    $self->{output} = $output; # store output path for external files to adjust to
    $self->{xwriters} = {}; # writers for external files
    $self->{files_array} = ();
    $self->{logicalLocations_array} = ();

    bless $self, $class;
    return $self;
}

# Set options for program
sub SetOptions {
    my ($self, $options) = @_;

    # Set whether the writer pretty prints (meaning add indentation)
    if (defined $options->{pretty}) {
        $self->{pretty} = $options->{pretty};
        $self->{writer}->pretty_output($self->{pretty});
    }

    if (defined $options->{error_level}) {
        if ($options->{error_level} >= 0 && $options->{error_level} <= 2) {
            $self->{error_level} = $options->{error_level};
        }
    }

    print "\$options->{external}: \n";
    print Dumper($options->{external});
    if ($options->{external}) {
        my %opened; # for where more than 1 object is externalized in same external file
        foreach my $key (keys %{$options->{external}}) {
            if ($options->{external}{$key}) {
                if (exists $opened{$options->{external}{$key}{name}}) {
                    my $value = $opened{$options->{external}{$key}{name}};
                    $self->{external}{$key}{instanceGuid} = $self->{external}{$value}{instanceGuid};
                    $self->{xwriters}{$key} = $self->{xwriters}{$value};
                } else {
                    if (defined $options->{external}{$key}{maxItems}) {
                        $self->{external}{$key}{maxItems} = $options->{external}{$key}{maxItems};
                        $self->{external}{$key}{currItems} = ();
                        push @{$self->{external}{$key}{currItems}}, 0;

                        # change file name to add a "-1" at the back (means the first external file)
                        $self->{external}{$key}{originalFileName} = $options->{external}{$key}{name};
                        if ($options->{external}{$key}{name} =~ /(.+)\.sarif/) {
                            $options->{external}{$key}{name} = $1."-1".".sarif-external-properties";
                        } else {
                            die "Cannot determine proper file name for external file with property $key: $!";
                        }
                    }
                    open(my $fh, '>:encoding(UTF-8)', $options->{external}{$key}{name}) or
                    die "Can't open $options->{external}{$key}: $!";
                    $self->{xwriters}{$key} = JSON::Streaming::Writer->for_stream($fh);
                    $self->{xwriters}{$key}->pretty_output($self->{pretty});

                    $self->{external}{$key}{fh} = $fh; # store fh to close later
                    $self->{external}{$key}{instanceGuid} = ();
                    push @{$self->{external}{$key}{instanceGuid}}, GetUuid();

                    $opened{$options->{external}{$key}{name}} = $key;
                }
                $self->{external}{$key}{fileName} = ();
                push @{$self->{external}{$key}{fileName}}, $options->{external}{$key}{name};
            }
        }
        print "\%opened: \n";
        print Dumper(\%opened);
    }

    print "\$self: \n";
    print Dumper($self);
}

# Returns a boolean that shows whether the writer currently pretty prints
sub GetPretty {
    my ($self) = @_;

    return $self->{pretty};
}

# Get the value of error_level
sub GetErrorLevel {
    my ($self) = @_;

    return $self->{error_level};
}

sub CheckInitialData {
    my ($initialData) = @_;
    my @errors = ();

    foreach my $key (qw/ build_root_dir package_root_dir results_root_dir uuid tool_name
                         tool_version package_name package_version/) {
        if (!defined $initialData->{$key}) {
            push @errors, "Required key $key not found in initialData";
        }
    }

    return \@errors;
}

# Start writing sarif file with data that comes before "runs"
sub BeginFile {
    my ($self) = @_;
    my $writer = $self->{writer};

    $writer->start_object(); # Start sarif object
    $writer->add_property("version", $sarifVersion);
    $writer->add_property("\$schema", $sarifSchema);
    $writer->start_property("runs");
    $writer->start_array();
}

# Start writing initial data to the sarif file and save some data for later use
sub BeginRun {
    my ($self, $initialData) = @_;
    my $writer = $self->{writer};

    my $errors = CheckInitialData($initialData);
    if (@{$errors}) {
        if ($self->{error_level} != 0) {
            foreach (@{$errors}) {
                print "$_\n";
            }
        }

        if ($self->{error_level} == 2) {
            die "Error with initialData hash. Program exiting."
        }
    }

    $self->{package_root_dir} = $initialData->{package_root_dir};

    if ($initialData->{sha256hashes}) {
        $self->{sha256hashes} = $initialData->{sha256hashes};
    }
    if ($initialData->{buildDir}) {
        $self->{buildDir} = $initialData->{buildDir};
    }

    # start new run object
    $writer->start_object();

    $writer->start_property("id");
    $writer->start_object();
    $writer->add_property("instanceGuid", $initialData->{uuid});
    $writer->end_object();
    $writer->end_property();

    # Start external files
    foreach my $key (keys %{$self->{external}}) {
        # Find unique external writers
        if (exists $self->{external}{$key}{fh}) {
            StartExternal($self, $key);
        }
    }

    $writer->start_property("tool");
    $writer->start_object();
    $writer->add_property("name", $initialData->{tool_name});
    $writer->add_property("version", $initialData->{tool_version});
    $writer->end_object();
    $writer->end_property();

    AddPropertiesObject($self, $initialData);
}

# Start writing data to the external file
sub StartExternal {
    my ($self, $key) = @_;
    my $writer = $self->{xwriters}{$key};

    $writer->start_object(); # Start sarif object
    $writer->add_property("version", $sarifVersion);
    $writer->add_property("\$schema", $externalSchema);
    $writer->add_property("instanceGuid", $self->{external}{$key}{instanceGuid}[-1]);
}

# Add the originalUriBaseIds object
# expected baseIds hash:
# baseIds => {
#   HOMEROOT    => "...",
#   BUILDROOT   => "...",
#   PACKAGEROOT => "...",
#   TOOLROOT    => "...",
#   RESULTSROOT => "...",
# }
sub AddOriginalUriBaseIds {
    my ($self, $baseIds) = @_;
    my $writer = $self->{writer};

    $writer->start_property("originalUriBaseIds");
    $writer->start_object();

    foreach my $k (keys %{$baseIds}) {
        if (defined $baseIds->{$k}) {
            $writer->start_property($k);
            $writer->start_object();
            $writer->add_property("uri", $baseIds->{$k});
            $writer->end_object();
            $writer->end_property();

            # store it
            $self->{baseIds}{$k} = $baseIds->{$k};
        }
    }

    $writer->end_object();
    $writer->end_property();
}

# Checks if new external file needs to be opened,
# and opens a new one if so
sub NewExternal {
    my ($self, $key) = @_;
    my $openNew = 0;

    if ($self->{external}{$key} &&
        exists $self->{external}{$key}{maxItems} && 
        $self->{external}{$key}{maxItems} > 0 && 
        $self->{external}{$key}{currItems}[-1] >= $self->{external}{$key}{maxItems}) {
        $openNew = 1;
    }

    if ($openNew) {
        EndPropertyArray($self, $key);
        $self->{xwriters}{$key}->end_object();
        close $self->{external}{$key}{fh};
        
        my $newName;
        if ($self->{external}{$key}{originalFileName} =~ /(.+)\.sarif-external-properties/) {
            my $num = @{$self->{external}{$key}{currItems}} + 1;
            $newName = $1."-".$num.".sarif-external-properties";
        }
        open(my $fh, '>:encoding(UTF-8)', $newName) or
        die "Can't open $newName: $!";
        $self->{xwriters}{$key} = JSON::Streaming::Writer->for_stream($fh);
        $self->{xwriters}{$key}->pretty_output($self->{pretty});

        $self->{external}{$key}{fh} = $fh;
        push @{$self->{external}{$key}{fileName}}, $newName;
        push @{$self->{external}{$key}{instanceGuid}}, GetUuid();
        push @{$self->{external}{$key}{currItems}}, 0;

        StartExternal($self, $key);
        BeginPropertyArray($self, $key);
        return 1;
    } else {
        return 0;
    }
}

# Checks that fields in the invocations array is filled
sub CheckInvocations {
    my ($invocations) = @_;
    my @errors = ();

    if (ref($invocations) ne "ARRAY") {
        push @errors, "\$ruleData is expected to be an array";
    }

    foreach my $i (@{$invocations}) {
        foreach my $key (qw/commandLine args startTimeUtc endTimeUtc workingDirectory env exitCode/) {
            if (!defined $i->{$key}) {
                push @errors, "Required key $key not found in an object in the invocations array";
            }
        }
        if (ref($i->{args}) ne "ARRAY") {
            push @errors, "The key args is expected to be an array";
        }
    }

    return \@errors;
}

# Helper method to write the invocations object
sub AddInvocations {
    my ($self, $invocations) = @_;
    my $writer;

    if ($self->{xwriters}{invocations}) {
        $writer = $self->{xwriters}{invocations};
    } else {
        $writer = $self->{writer};
    }

    BeginPropertyArray($self, "invocations");

    foreach my $assessment (@{$invocations}) {
        if (NewExternal($self, "invocations")) { # Creates a new external file is needed
            $writer = $self->{xwriters}{invocations}; # Reassigns the writer variable
        }

        $writer->start_object();
        CheckAndAddInvocation($writer, "commandLine", $assessment->{commandLine});

        if ($assessment->{args} && @{$assessment->{args}} > 0) {
            $writer->start_property("arguments");
            $writer->start_array();
            foreach my $arg (@{$assessment->{args}}) {
                $writer->add_string($arg);
            }
            $writer->end_array();
            $writer->end_property();
        }

        CheckAndAddInvocation($writer, "startTimeUtc", $assessment->{startTime});
        CheckAndAddInvocation($writer, "endTimeUtc", $assessment->{endTime});

        $writer->start_property("workingDirectory");
        $writer->start_object();
        my $wd = AdjustPath($self->{baseIds}{PACKAGEROOT}, ".", $assessment->{workingDirectory});
        $writer->add_property("uri", $wd);
        $writer->add_property("uriBaseId", "PACKAGEROOT");
        $writer->end_object();
        $writer->end_property();

        if (defined $assessment->{env}) {
            $writer->start_property("environmentVariables");
            $writer->start_object();
            foreach my $key (keys %{$assessment->{env}}) {
                my $value = $assessment->{env}{$key};
                $writer->add_property($key, $value);
            }
            $writer->end_object();
            $writer->end_property();
        }

        CheckAndAddInvocation($writer, "exitCode", $assessment->{exitCode});
        $writer->end_object();

        if ($self->{external}{invocations} && exists $self->{external}{invocations}{currItems}) {
            $self->{external}{invocations}{currItems}[-1] += 1;
        }
    }

    EndPropertyArray($self, "invocations");
}

# Check if bugInstance hash contains required fields
sub CheckResultData {
    my ($bugInstance) = @_;
    my @errors = ();

    for my $key (qw/BugMessage/) {
        if (!defined $bugInstance->{$key}) {
            push @errors, "Required key $key not found in bugInstance";
        }
    }

    foreach my $location (@{$bugInstance->{BugLocations}}) {
        if (!defined $location->{SourceFile}) {
            push @errors, "Required key SourceFile not found in a BugLocation object";
        }
    }

    foreach my $method (@{$bugInstance->{Methods}}) {
        if (!defined $method->{name}) {
            push @errors, "Required key name not found in a method object";
        }
    }

    return \@errors;
}


# Start the results property and array
sub BeginResults {
    my ($self) = @_;
    
    BeginPropertyArray($self, "results");
}

# Starts an external property in an external file
sub BeginPropertyArray {
    my ($self, $key) = @_;
    my $writer;

    if ($self->{xwriters}{$key}) {
        $writer = $self->{xwriters}{$key};
        $writer->start_property("run.".$key);
    } else {
        $writer = $self->{writer};
        $writer->start_property($key);
    }
    $writer->start_array();
}

# Called when data for a bug instance is gathered.
# Writes out a result object, saves some data related to the bug
# for later use.
sub AddResult {
    my ($self, $bugData) = @_;
    my $writer;

    NewExternal($self, "results"); # Starts a new external file if needed

    if ($self->{xwriters}{results}) {
        $writer = $self->{xwriters}{results};
    } else {
        $writer = $self->{writer};
    }

    my $errors = CheckResultData($bugData);
    if (@{$errors}) {
        if ($self->{error_level} != 0) {
            foreach (@{$errors}) {
                print "$_\n";
            }
        }
        if ($self->{error_level} == 2) {
            die "Error with bugData hash. Program exiting."
        }
    }

    if ($self->{external}{results} && exists $self->{external}{results}{currItems}) {
        $self->{external}{results}{currItems}[-1] += 1;
    }
    $writer->start_object();

    my @ruleId = ();
    push @ruleId, $bugData->{BugGroup} if $bugData->{BugGroup};
    push @ruleId, $bugData->{BugCode} if $bugData->{BugCode};
    if (@ruleId == 0) {
        push @ruleId, "__UNKNOWN__";
    }
    $writer->add_property("ruleId", join('/', @ruleId));

    $writer->add_property("level", "warning");

    if (defined $bugData->{BugRank}) {
        $writer->add_property("rank", $bugData->{BugRank});
    } else {
        $writer->add_property("rank", -1.0);
    }

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
                my $filename = AdjustPath($self->{package_root_dir}, ".", $location->{SourceFile});
                my $fileIndex;
                if (exists $self->{files}{$location->{SourceFile}}) {
                    $fileIndex = $self->{files}{$location->{SourceFile}};
                } else {
                    push @{$self->{files_array}}, $location->{SourceFile};
                    $fileIndex = @{$self->{files_array}} - 1;
                    $self->{files}{$location->{SourceFile}} = $fileIndex;
                }

                $writer->start_object();
                $writer->start_property("physicalLocation");
                $writer->start_object();
                AddFileLocationUri($writer, $filename, "PACKAGEROOT", $fileIndex);

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

                    if ($self->{buildDir} && defined $location->{StartLine} && defined $location->{EndLine}) {
                        my $snippetFile = AdjustPath(".", $self->{buildDir}, $location->{SourceFile});
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
                            print "Unable to find $snippetFile\n";
                        }
                    }

                    $writer->end_object();
                    $writer->end_property(); # end region
                }

                $writer->end_object();
                $writer->end_property(); # end physicalLocation

                my $llIndex;
                # Save ClassName
                if (defined $bugData->{ClassName}) {
                    if (exists $self->{logicalLocation}{$bugData->{ClassName}}) {
                        $llIndex = $self->{logicalLocations}{$bugData->{ClassName}}{index};
                    } else {
                        push @{$self->{logicalLocations_array}}, $bugData->{ClassName};
                        $llIndex = @{$self->{logicalLocations_array}} - 1;
                        %{$self->{logicalLocations}{$bugData->{ClassName}}} = (
                            index => $llIndex,
                            kind => "type",
                        );
                    }
                }

                if (defined $location->{Explanation}) {
                    $writer->start_property("message");
                    $writer->start_object();
                    $writer->add_property("text", $location->{Explanation});
                    $writer->end_object();
                    $writer->end_property();
                }

                $writer->end_object();
            }
        }
        $writer->end_array();
        $writer->end_property();
    }

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
        AddThreadFlowsLocations($self, $writer, $bugData->{BugLocations});
        $writer->end_array();
        $writer->end_property();
        $writer->end_object();
        $writer->end_array();
        $writer->end_property();
        $writer->end_object();
        $writer->end_array();
        $writer->end_property();
    }

    $writer->start_property("provenance");
    $writer->start_object();
    $writer->add_property("invocationIndex", $bugData->{BuildId} - 1);
    $writer->start_property("conversionSources");
    $writer->start_array();
    $writer->start_object();
    AddFileLocationUri($writer, $bugData->{AssessmentReportFile}, "RESULTSROOT");
    $writer->end_object();
    $writer->end_array();
    $writer->end_property();
    $writer->end_object();
    $writer->end_property();

    # Write data to property bag object
    if ($bugData->{BugSeverity} || $bugData->{CweIds}) {
        $writer->start_property("properties");
        $writer->start_object();

        if ($bugData->{BugSeverity}) {
            $writer->add_property("toolSeverity", $bugData->{BugSeverity});
        }

        if ($bugData->{CweIds}) {
            if (@{$bugData->{CweIds}} > 0) {
                $writer->start_property("tags");
                $writer->start_array();
                foreach my $cweId (@{$bugData->{CweIds}}) {
                    $writer->add_string("CWE/".$cweId);
                }
                $writer->end_array();
                $writer->end_property();
            }
        }

        $writer->end_object();
        $writer->end_property();
    }

    $writer->end_object();

}

# Ends the results array and property
sub EndResults {
    my ($self) = @_;
    
    EndPropertyArray($self, "results");
}

sub EndPropertyArray {
    my ($self, $key) = @_;
    my $writer;

    if ($self->{xwriters}{$key}) {
        $writer = $self->{xwriters}{$key};
    } else {
        $writer = $self->{writer};
    }

    $writer->end_array();
    $writer->end_property();
}

sub CheckRuleData {
    my ($ruleData) = @_;
    my @errors = ();
    
    if (ref($ruleData) ne "ARRAY") {
        push @errors, "\$ruleData is expected to be an array";
    }

    foreach my $rule (@{$ruleData}) {
        foreach my $key (qw/id fullDescription/) {
            if (!defined $rule->{$key}) {
                push @errors, "Required key $key not found in an object in the ruleData array";
            }
        }
    }

    return \@errors;
}

# Adds the resouces object
sub AddResources {
    my ($self, $ruleData) = @_;
    my $writer;

    if ($self->{xwriters}{resources}) {
        $writer = $self->{xwriters}{resources};
    } else {
        $writer = $self->{writer};
    }

    my $errors = CheckRuleData($ruleData);
    if (@{$errors}) {
        if ($self->{error_level} != 0) {
            foreach (@{$errors}) {
                print "$_\n";
            }
        }

        if ($self->{error_level} == 2) {
            die "Error with ruleData hash. Program exiting."
        }
    }

    $writer->start_property("resources");
    $writer->start_object();
    $writer->start_property("rules");
    $writer->start_array();

    foreach my $rule (@{$ruleData}) {
        $writer->start_object();
        $writer->add_property("id", $rule->{id});
        $writer->add_property("defaultLevel", $rule->{defaultLevel}) if (defined $rule->{defaultLevel});
        $writer->add_property("defaultRank", $rule->{defaultRank}) if (defined $rule->{defaultRank});
        if (defined $rule->{shortDescription}) {
            $writer->start_property("shortDescription");
            $writer->start_object();
            $writer->add_property("text", $rule->{shortDescription});
            $writer->end_object();
            $writer->end_property();
        }
        $writer->start_property("fullDescription");
        $writer->start_object();
        $writer->add_property("text", $rule->{fullDescription});
        $writer->end_object();
        $writer->end_property();
        $writer->end_object();
    }

    $writer->end_array();
    $writer->end_property();
    $writer->end_object();
    $writer->end_property();
}

# This method is supported in ScarfXmlWriter, but is not
# currently supported by SarifJsonWriter
sub CheckMetric {

}

# This method is supported in ScarfXmlWriter, but is not
# currently supported by SarifJsonWriter
sub AddMetric {

}

# This method is supported in ScarfXmlWriter, but is not
# currently supported by SarifJsonWriter
sub AddSummary {

}

# This method is supported in ScarfXmlWriter, but is not
# currently supported by SarifJsonWriter
sub AddEndTag {

}

# Closes results array, write data saved from AddBugInstance()
sub EndRun {
    my ($self, $endData) = @_;
    my $writer = $self->{writer};

    #AddLogicalLocations($self);
    AddFilesObject($self, $endData->{sha256hashes});
    if (keys %{$self->{xwriters}} > 0) {
        AddExternalPropertyFiles($self);
    }
    AddConversionObject($self, $endData->{conversion});

    $writer->end_object(); # end run object

    foreach my $key (keys %{$self->{external}}) {
        if (exists $self->{external}{$key}{fh}) {
            $self->{xwriters}{$key}->end_object();
            close $self->{external}{$key}{fh};
        }
    }
}

sub EndFile {
    my ($self) = @_;
    my $writer = $self->{writer};

    $writer->end_array();
    $writer->end_property();
    $writer->end_object();

    print Dumper($self);

    close $self->{fh};
}

# Helper method to write the external property files object
sub AddExternalPropertyFiles {
    my ($self) = @_;
    my $writer = $self->{writer};

    $writer->start_property("externalPropertyFiles");
    $writer->start_object();

    my @externalizableObject = qw/
        conversion
        graphs
        properties
        resources/;

    my @externalizableArray = qw/
        files
        invocations
        results
        logicalLocations/;

    foreach my $e (@externalizableObject) {
        if ($self->{xwriters}{$e}) {
            $writer->start_property($e);
            $writer->start_object();

            my $outputDir = "";
            if ($self->{output} =~ /(.*)\/.+\.sarif/) {
                $outputDir = $1;
            }
            my $filePath = AdjustPath($outputDir, ".", $self->{external}{$e}{fileName}[0]);
            AddFileLocationUri($writer, $filePath);
            $writer->add_property("instanceGuid", $self->{external}{$e}{instanceGuid}[0]);
            $writer->end_object();
            $writer->end_property();
        }
    }

    foreach my $e (@externalizableArray) {
        if ($self->{xwriters}{$e}) {
            $writer->start_property($e);
            $writer->start_array();

            foreach my $i (0 .. $#{$self->{external}{$e}{fileName}}) {
                $writer->start_object();
                my $outputDir = "";
                if ($self->{output} =~ /(.*)\/.+\.sarif/) {
                    $outputDir = $1;
                }
                my $filePath = AdjustPath($outputDir, ".", $self->{external}{$e}{fileName}[$i]);
                AddFileLocationUri($writer, $filePath);
                $writer->add_property("instanceGuid", $self->{external}{$e}{instanceGuid}[$i]);
                $writer->end_object();
            }

            $writer->end_array();
            $writer->end_property();
        }
    }

    $writer->end_object();
    $writer->end_property();
}

# Helper method to write a fileLocation object
# if only 1 property -> adds only uri property
# else -> adds uri, uriBaseId and fileIndex
sub AddFileLocationUri {
    my ($writer, $uri, $uriBaseId, $fileIndex) = @_;

    $writer->start_property("fileLocation");
    $writer->start_object();
    $writer->add_property("uri", $uri);
    $writer->add_property("uriBaseId", $uriBaseId) if (defined $uriBaseId);
    $writer->add_property("fileIndex", $fileIndex) if (defined $fileIndex);
    $writer->end_object();
    $writer->end_property();
}

# Helper method to write the properties object
sub AddPropertiesObject {
    my ($self, $initialData) = @_;
    my $writer;

    if ($self->{xwriters}{properties}) {
        $writer = $self->{xwriters}{properties};
        $writer->start_property("run.properties");
    } else {
        $writer = $self->{writer};
        $writer->start_property("properties");
    }

    $writer->start_object();
    $writer->add_property("packageName", $initialData->{package_name});
    $writer->add_property("packageVersion", $initialData->{package_version});
    $writer->end_object();
    $writer->end_property();
}

# Only method to call after new() when there is a failure.
# Writes only a sarif file with the conversion object.
# Inside the conversion object is the property "toolNotifications"
# which will contain the error message
sub AddFailure {
    my ($self, $data) = @_;
    my $writer = $self->{writer};
    my $conversion = $data->{conversion};

    $writer->start_object(); # Start sarif object
    $writer->add_property("version", $sarifVersion);
    $writer->add_property("\$schema", $sarifSchema);
    $writer->start_property("runs");
    $writer->start_array();
    $writer->start_object(); # Start new run object

    # start tool object
    $writer->start_property("tool");
    $writer->start_object();
    $writer->add_property("name", $data->{tool}{tool_name});
    $writer->end_object();
    $writer->end_property();

    # start conversion object
    $writer->start_property("conversion");
    $writer->start_object();
    $writer->start_property("tool");
    $writer->start_object();
    $writer->add_property("name", $conversion->{tool_name});
    $writer->add_property("version", $conversion->{tool_version});
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("invocation");

    $writer->start_object();
    $writer->add_property("commandLine", $conversion->{commandLine});

    $writer->start_property("arguments");
    $writer->start_array();
    foreach my $arg (@{$conversion->{argv}}) {
        $writer->add_string($arg);
    }
    $writer->end_array();
    $writer->end_property();

    $writer->start_property("workingDirectory");
    $writer->start_object();
    $writer->add_property("uri", $conversion->{workingDirectory});
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("environmentVariables");
    $writer->start_object();
    foreach my $key (keys %{$conversion->{env}}) {
        $writer->add_property($key, $conversion->{env}{$key});
    }
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("toolNotifications");
    $writer->start_array();
    $writer->start_object();
    $writer->add_property("level", "error");
    $writer->start_property("message");
    $writer->start_object();
    $writer->add_property("text", $data->{message});
    $writer->end_object();
    $writer->end_property();
    $writer->end_object();
    $writer->end_array();
    $writer->end_property();

    $writer->add_property("exitCode", 0);
    $writer->add_property("startTimeUtc", ConvertEpoch($conversion->{startTime}));
    $writer->add_property("endTimeUtc", ConvertEpoch(time()));

    $writer->end_object();
    $writer->end_property(); # end invocation

    $writer->end_object();
    $writer->end_property(); # end conversion

    $writer->end_object();
    $writer->end_array();
    $writer->end_property();
    $writer->end_object();
    close $self->{fh};
}

# Helper function to check if a given property in invocation exists and
# write it if it does.
sub CheckAndAddInvocation {
    my ($writer, $propertyName, $propertyValue) = @_;

    if (defined $propertyValue) {
        if ($propertyName eq "exitCode") {
            $writer->add_property($propertyName, MakeInt($propertyValue));
        } else {
            $writer->add_property($propertyName, $propertyValue);
        }
    }
}

# Helper function to write the logicalLocations object
sub AddLogicalLocations {
    my ($self) = @_;
    my $writer;

    if ($self->{xwriters}{logicalLocations}) {
        $writer = $self->{xwriters}{logicalLocations};
        $writer->start_property("run.logicalLocations");
    } else {
        $writer = $self->{writer};
        $writer->start_property("logicalLocations");
    }

    $writer->start_array();

    foreach my $l (@{$self->{logicalLocations_array}}) {
        $writer->start_object();
        $writer->add_property("name", $l);
        $writer->add_property("kind", $self->{logicalLocations}{$l}{kind});
        $writer->end_object();
    }

    $writer->end_array();
    $writer->end_property();
}

# Helper function to write the Files object
sub AddFilesObject {
    my ($self, $sha256hashes) = @_;
    my $writer;

    if ($self->{xwriters}{files}) {
        $writer = $self->{xwriters}{files};
    } else {
        $writer = $self->{writer};
    }

    BeginPropertyArray($self, "files");

    if ($self->{files_array} && @{$self->{files_array}} > 0) {
        foreach my $file (@{$self->{files_array}}) {
            if (NewExternal($self, "files")) { # Creates a new external file is needed
                $writer = $self->{xwriters}{files}; # Reassigns the writer variable
            }

            $writer->start_object();
            my $filename = AdjustPath($self->{package_root_dir}, ".", $file);
            AddFileLocationUri($writer, $filename, "PACKAGEROOT");

            my $hashPath = "build/".$file;
            if ($sha256hashes) {
                my $sha256 = FindSha256Hash($sha256hashes, $hashPath);
                if (defined $sha256) {
                    $writer->start_property("hashes");
                    $writer->start_object();
                    $writer->add_property("sha-256", $sha256);
                    $writer->end_object();
                    $writer->end_property();
                } else {
                    print "Unable to find sha256 hash for $file\n";
                }
            }
            $writer->end_object();

            if ($self->{external}{files} && exists $self->{external}{files}{currItems}) {
                $self->{external}{files}{currItems}[-1] += 1;
            }
        }
    }

    EndPropertyArray($self, "files");
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
    my ($self, $conversion) = @_;
    my $writer;

    if ($self->{xwriters}{conversion}) {
        $writer = $self->{xwriters}{conversion};
        $writer->start_property("run.conversion");
    } else {
        $writer = $self->{writer};
        $writer->start_property("conversion");
    }

    $writer->start_object();
    $writer->start_property("tool");
    $writer->start_object();
    $writer->add_property("name", $conversion->{tool_name});
    $writer->add_property("version", $conversion->{tool_version});
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("invocation");

    $writer->start_object();
    $writer->add_property("commandLine", $conversion->{commandLine});

    $writer->start_property("arguments");
    $writer->start_array();
    foreach my $arg (@{$conversion->{argv}}) {
        $writer->add_string($arg);
    }
    $writer->end_array();
    $writer->end_property();

    $writer->start_property("workingDirectory");
    $writer->start_object();
    $writer->add_property("uri", $conversion->{workingDirectory});
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("environmentVariables");
    $writer->start_object();
    foreach my $key (keys %{$conversion->{env}}) {
        $writer->add_property($key, $conversion->{env}{$key});
    }
    $writer->end_object();
    $writer->end_property();
    $writer->add_property("exitCode", 0);
    $writer->add_property("startTimeUtc", ConvertEpoch($conversion->{startTime}));
    $writer->add_property("endTimeUtc", ConvertEpoch(time()));

    $writer->end_object();
    $writer->end_property(); # end invocation

    $writer->end_object();
    $writer->end_property();
}

# Helper function to write the threadFLowLocations object
sub AddThreadFlowsLocations {
    my ($self, $writer, $locations) = @_;

    foreach my $location (@{$locations}) {
        $writer->start_object();

        $writer->add_property("importance", "essential");
        $writer->start_property("location");
        $writer->start_object();
        $writer->start_property("physicalLocation");
        $writer->start_object();

        my $filename = AdjustPath($self->{package_root_dir}, ".", $location->{SourceFile});
        my $fileIndex;
        if (exists $self->{files}{$location->{SourceFile}}) {
            $fileIndex = $self->{files}{$location->{SourceFile}};
        } else {
            push @{$self->{files_array}}, $location->{SourceFile};
            $fileIndex = @{$self->{files_array}} - 1;
            $self->{files}{$location->{SourceFile}} = $fileIndex;
        }
        AddFileLocationUri($writer, $filename, "PACKAGEROOT", $fileIndex);

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

            if ($self->{buildDir} && defined $location->{StartLine} && defined $location->{EndLine}) {
                my $snippetFile = AdjustPath(".", $self->{buildDir}, $location->{SourceFile});
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
                    print "Unable to find $snippetFile\n";
                }
            }

            $writer->end_object();
            $writer->end_property(); # end region
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

# Generate Uuid
sub GetUuid {
    my $s = `uuidgen`;
    chomp $s;
    return $s;
}

# Make the integer that is in a string into integer
sub MakeInt {
    my ($var) = @_;

    return 0 + $var;
}

1;
