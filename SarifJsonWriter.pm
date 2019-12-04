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
use FindBin;
use lib "$FindBin::Bin";
use JSON::Streaming::Writer;
use Data::Dumper;
use Digest::file qw(digest_file_hex);
use Exporter 'import';
our @EXPORT_OK = qw(CheckInitialData CheckInvocations CheckResultData CheckRuleData);

my $sarifVersion = "2.1.0";
my $sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema.json";
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
    $self->{fh} = $fh;
    $self->{writer} = JSON::Streaming::Writer->for_stream($fh);
    $self->{writer}->pretty_output($self->{pretty});
    $self->{output} = $output; # store output path for external files to adjust to
    $self->{xwriters} = {}; # writers for external files
    $self->{artifacts_counter} = 0;
    $self->{artifacts} = {}; # Hash to lookup if file has been read before
    $self->{artifacts_array} = (); # Array of structs for all artifacts
    $self->{invocation_indexes} = {}; # Hash to store map of buildId to invocationIndex
    $self->{invocation_index_counter} = 0;
    $self->{numBugs} = 0; # keep track of number of results added for the result parser to print the weaknesses count file
    $self->{numMetrics} = 0;

    # Know what is externalizable and if the type is an object or array
    %{$self->{externalizableObject}} = (
        conversion => 0,
        properties => 0,
        'tool.driver' => 0
    );

    %{$self->{externalizableArray}} = (
        addresses => 0,
        artifacts => 0,
        graphs => 0,
        invocations => 0,
        logicalLocations => 0,
        policies => 0,
        webRequests => 0,
        webResponses => 0,
        results => 0,
        taxonomies => 0,
        threadFlowLocations => 0,
        translations => 0,
        'tool.extensions' => 0,
    );

    bless $self, $class;
    return $self;
}

# Set options for program
sub SetOptions {
    my ($self, $options) = @_;
    my @errors;

    # Set whether the writer pretty prints (meaning add indentation)
    if (defined $options->{pretty}) {
        $self->{pretty} = $options->{pretty};
        $self->{writer}->pretty_output($self->{pretty});
    }

    if (defined $options->{error_level}) {
        if ($options->{error_level} >= 0 && $options->{error_level} <= 2) {
            $self->{error_level} = $options->{error_level};
        }
    } else {
        $self->{error_level} = 2;
    }

    if (defined $options->{addArtifacts}) {
        $self->{addArtifacts} = $options->{addArtifacts} ? 1 : 0;
    }
    if (defined $options->{addArtifactsNoLocation}) {
        $self->{addArtifactsNoLocation} = $options->{addArtifactsNoLocation} ? 1 : 0;
    }
    if (defined $options->{addArtifacts} && !$options->{addArtifacts} && $options->{addArtifactsNoLocation}) {
        push @errors, 'Cannot make addArtifactsNoLocation true while addArtifacts is false';
    }
    if (!defined $options->{addArtifacts} && !defined $options->{addArtifactsNoLocation}) {
        $self->{addArtifacts} = 1;
        $self->{addArtifactsNoLocation} = 0;
    }

    if (defined $options->{addProvenance}) {
        $self->{addProvenance} = $options->{addProvenance} ? 1 : 0;
    } else {
        $self->{addProvenance} = 1;
    }

    if (defined $options->{artifactHashes}) {
        $self->{artifactHashes} = $options->{artifactHashes} ? 1 : 0;
    } else {
        $self->{artifactHashes} = 1;
    }

    if (defined $options->{sortKeys}) {
        $self->{sortKeys} = $options->{sortKeys} ? 1 : 0;
    }

    if (defined $options->{addSnippets}) {
        $self->{addSnippets} = $options->{addSnippets} ? 1 : 0;
    } else {
        $self->{addSnippets} = 1;
    }

    $self->{extraSnippets} = 0;
    if (defined $options->{extraSnippets}) {
        if ($options->{extraSnippets} < 0) {
            push @errors, 'extraSnippets must be set to a positive number';
        }
        $self->{extraSnippets} = $options->{extraSnippets};
    }

    if ($options->{external}) {
        my %opened; # for where more than 1 object is externalized in same external file
        foreach my $key (keys %{$options->{external}}) {
            if ($options->{external}{$key}) {
                if (exists $opened{$options->{external}{$key}{name}}) {
                    my $value = $opened{$options->{external}{$key}{name}};
                    $self->{external}{$key}{guid} = $self->{external}{$value}{guid};
                    $self->{xwriters}{$key} = $self->{xwriters}{$value};
                } else {
                    if (defined $options->{external}{$key}{maxItems}) {
                        $self->{external}{$key}{maxItems} = $options->{external}{$key}{maxItems};

                        # change file name to add a "-1" at the back (means the first external file)
                        $self->{external}{$key}{originalFileName} = $options->{external}{$key}{name};
                        if ($options->{external}{$key}{name} =~ /(.+)\.sarif-external-properties(\.json)?$/) {
                            $options->{external}{$key}{name} = $1."-1".".sarif-external-properties";
                            $options->{external}{$key}{name} .= $2 if $2; # if name ends in .json
                        } else {
                            die "Cannot determine proper file name for external file with property $key: $!";
                        }
                    }

                    if (exists $self->{externalizableArray}{$key}) {
                        $self->{external}{$key}{currItems} = ();
                        push @{$self->{external}{$key}{currItems}}, 0;
                    }

                    open(my $fh, '>:encoding(UTF-8)', $options->{external}{$key}{name}) or
                    die "Can't open $options->{external}{$key}: $!";
                    $self->{xwriters}{$key} = JSON::Streaming::Writer->for_stream($fh);
                    $self->{xwriters}{$key}->pretty_output($self->{pretty});

                    $self->{external}{$key}{fh} = $fh; # store fh to close later
                    $self->{external}{$key}{guid} = ();
                    push @{$self->{external}{$key}{guid}}, GetUuid();

                    $opened{$options->{external}{$key}{name}} = $key;
                }
                $self->{external}{$key}{fileName} = ();
                push @{$self->{external}{$key}{fileName}}, $options->{external}{$key}{name};
            }
        }
    }

    if ($self->{error_level} != 0 && @errors) {
        if ($self->{error_level} != 0) {
            foreach (@errors) {
                print STDERR "$_\n";
            }
        }

        if ($self->{error_level} == 2) {
            die "Error with optionsData. Program exiting."
        }
    }
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

    foreach my $key (qw/ build_root_dir package_root_dir uuid tool_name
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

    if ($self->{error_level} != 0) {
        my $errors = CheckInitialData($initialData);
        if (@{$errors}) {
            foreach (@{$errors}) {
                print STDERR "$_\n";
            }

            if ($self->{error_level} == 2) {
                die "Error with initialData hash. Program exiting."
            }
        }
    }

    $self->{build_root_dir} = $initialData->{build_root_dir};
    $self->{package_root_dir} = $initialData->{package_root_dir};
    $self->{results_root_dir} = $initialData->{results_root_dir};

    if ($initialData->{sha256hashes}) {
        $self->{sha256hashes} = $initialData->{sha256hashes};
    }
    if ($initialData->{buildDir}) {
        $self->{buildDir} = $initialData->{buildDir};
    }

    # start new run object
    $writer->start_object();

    $writer->start_property("automationDetails");
    $writer->start_object();
    $writer->add_property("guid", $initialData->{uuid});
    $writer->end_object();
    $writer->end_property();

    # Start external files
    foreach my $key (keys %{$self->{external}}) {
        # Find unique external writers (only unique ones have the fh property)
        if (exists $self->{external}{$key}{fh}) {
            StartExternal($self, $key);
        }
    }

    AddPropertiesObject($self, $initialData);
}

# Adds the tool object
sub AddToolData {
    my ($self, $toolData) = @_;
    my $writer = $self->{writer};

    $writer->start_property("tool");
    $writer->start_object();
    
    $writer->start_property("driver");
    AddToolComponentObject($self, $writer, $toolData->{driver});
    $writer->end_property(); # end driver

    if ($toolData->{extensions} && @{$toolData->{extensions}}) {
        $writer->start_property("extensions");
        $writer->start_array();
        foreach my $ext (@{$toolData->{extensions}}) {
            AddToolComponentObject($self, $writer, $toolData->{extensions});
        }
        $writer->end_array();
        $writer->end_property(); # end extensions
    }

    $writer->end_object();
    $writer->end_property(); # end tool

}

# Helper method to start writing data to the external file
sub StartExternal {
    my ($self, $key) = @_;
    my $writer = $self->{xwriters}{$key};

    $writer->start_object(); # Start sarif object
    $writer->add_property("version", $sarifVersion);
    $writer->add_property("\$schema", $externalSchema);
    $writer->add_property("guid", $self->{external}{$key}{guid}[-1]);
}

# Add the originalUriBaseIds object
sub AddOriginalUriBaseIds {
    my ($self, $baseIds) = @_;
    my $writer = $self->{writer};

    $writer->start_property("originalUriBaseIds");
    $writer->start_object();

    my @keys;
    if ($self->{sortKeys}) {
        @keys = sort keys %{$baseIds};
    } else {
        @keys = keys %{$baseIds};
    }
    foreach my $k (@keys) {
        if (defined $baseIds->{$k}) {
            # uri must end in a '/'
            if ($baseIds->{$k}{uri} !~ /\/$/) {
                $baseIds->{$k}{uri} = $baseIds->{$k}{uri} . "/";
            }
            $writer->start_property($k);
            $writer->start_object();
            $writer->add_property("uri", $baseIds->{$k}{uri});
            $writer->add_property("uriBaseId", $baseIds->{$k}{uriBaseId}) if $baseIds->{$k}{uriBaseId};
            if ($baseIds->{$k}{description}) {
                $writer->start_property("description");
                AddMessage($writer, $baseIds->{$k}{description}, 0);
                $writer->end_property();
            }
            $writer->end_object();
            $writer->end_property();
        }
    }

    $writer->end_object();
    $writer->end_property();
}

# Adds the specialLocations property
sub AddSpecialLocations {
    my ($self, $displayBase) = @_;
    my $writer = $self->{writer};

    $writer->start_property("specialLocations");
    $writer->start_object();
    $writer->start_property("displayBase");
    AddArtifactLocation($writer, $displayBase->{uri}, $displayBase->{uriBaseId}, undef, 0);
    $writer->end_property();
    $writer->end_object();
    $writer->end_property();
}

# Helper method that checks if a new external file needs to be opened (maxItems reached),
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
        if ($self->{external}{$key}{originalFileName} =~ /(.+)\.sarif-external-properties(\.json)?$/) {
            my $num = @{$self->{external}{$key}{currItems}} + 1;
            $newName = $1."-".$num.".sarif-external-properties";
            $newName .= $2 if $2; # if name ends in .json
        } else {
            die "Unable to parse external property file name -- unable to open new external property file: $!";
        }
        open(my $fh, '>:encoding(UTF-8)', $newName) or
        die "Can't open $newName: $!";
        $self->{xwriters}{$key} = JSON::Streaming::Writer->for_stream($fh);
        $self->{xwriters}{$key}->pretty_output($self->{pretty});

        $self->{external}{$key}{fh} = $fh;
        push @{$self->{external}{$key}{fileName}}, $newName;
        push @{$self->{external}{$key}{guid}}, GetUuid();
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

# Adds the invocation property
sub AddInvocations {
    my ($self, $invocations) = @_;
    my $writer;

    if (@{$invocations}) {
        # Mark invocations is added so that invocationIndex can be added in result
        $self->{hasInvocations} = 1;
    }

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

        AddInvocationObject($self, $writer, $assessment);

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

    if ($bugInstance->{BugLocations}) {
        foreach my $location (@{$bugInstance->{BugLocations}}) {
            if (!$location->{SourceFile}) {
                push @errors, "Required key SourceFile not found in a BugLocation object";
            }
            if (!$location->{SourceFile} && $location->{StartLine}) {
                push @errors, "Can't have StartLine when SourceFile doesn't exist";
            }
            if (!$location->{SourceFile} && $location->{EndLine}) {
                push @errors, "Can't have EndLine when SourceFile doesn't exist";
            }
            if ($location->{StartLine} && $location->{EndLine} && $location->{EndLine} > $location->{StartLine}) {
                push @errors, "EndLine is greater than StartLine";
            }
        }
    } else {
        push @errors, "Required key BugLocations not found in bugInstance";
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
    } else {
        $writer = $self->{writer};
    }
    $writer->start_property($key);
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

    if ($self->{error_level} != 0) {
        my $errors = CheckResultData($bugData);
        if (@{$errors}) {
            foreach (@{$errors}) {
                print STDERR "$_\n";
            }

            if ($self->{error_level} == 2) {
                die "Error with bugData hash. Program exiting."
            }
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
        $writer->add_property("rank", MakeInt($bugData->{BugRank}));
    }

    my $message = $bugData->{BugMessage};
    $message =~ s/(\n\n )?Bug\ Path:\s* $ $ .*\Z//xms;
    if (!$message) {
        $message = "No message exists. Try looking at messages in each location."
    }

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
            if ($location->{primary} && $location->{primary} ne 'false') {
                $writer->start_object();

                AddPhysicalLocation($self, $writer, $location);

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

    if ($self->{addProvenance}) {
        $writer->start_property("provenance");
        $writer->start_object();
        if ($self->{hasInvocations} && defined $bugData->{BuildId}) {
            $writer->add_property("invocationIndex", $self->{invocation_indexes}{$bugData->{BuildId}});
        }
        $writer->start_property("conversionSources");
        $writer->start_array();
        $writer->start_object();

        if ($bugData->{AssessmentReportFile}) {
            my $artifactBaseId = "RESULTSROOT";
            my $artifactIndex;
            if (exists $self->{artifacts}{$artifactBaseId}{$bugData->{AssessmentReportFile}}) {
                $artifactIndex = $self->{artifacts}{$artifactBaseId}{$bugData->{AssessmentReportFile}}{index};
            } else {
                my %struct = (
                    uri => $bugData->{AssessmentReportFile},
                    uriBaseId => $artifactBaseId,
                    index => $self->{artifacts_counter}
                );
                $self->{artifacts}{$artifactBaseId}{$bugData->{AssessmentReportFile}} = \%struct;
                push @{$self->{artifacts_array}}, \%struct;
                $artifactIndex = $self->{artifacts_counter}++;
            }
            if ($self->{addArtifactsNoLocation}) {
                AddArtifactLocation($writer, undef, undef, $artifactIndex, 1);
            } else {
                if ($self->{addArtifacts}) {
                    AddArtifactLocation($writer, $bugData->{AssessmentReportFile}, $artifactBaseId, $artifactIndex, 1);
                } else {
                    AddArtifactLocation($writer, $bugData->{AssessmentReportFile}, $artifactBaseId, undef, 1);
                }
            }
        }

        if ($bugData->{InstanceLocation}{LineNum}{Start} || $bugData->{InstanceLocation}{LineNum}{End}) {
            $writer->start_property("region");
            $writer->start_object();
            $writer->add_property("startLine", MakeInt($bugData->{InstanceLocation}{LineNum}{Start})) if $bugData->{InstanceLocation}{LineNum}{Start};
            $writer->add_property("endLine", MakeInt($bugData->{InstanceLocation}{LineNum}{End})) if $bugData->{InstanceLocation}{LineNum}{End};
            $writer->end_object();
            $writer->end_property();
        }
        
        $writer->end_object();
        $writer->end_array();
        $writer->end_property();

        if ($bugData->{InstanceLocation}{Xpath}) {
            $writer->start_property("properties");
            $writer->start_object();
            $writer->add_property("Xpath", $bugData->{InstanceLocation}{Xpath});
            $writer->end_object();
            $writer->end_property();
        }

        $writer->end_object();
        $writer->end_property(); # end provenance
    }

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
    $self->{numBugs} += 1;
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

    if ($self->{error_level} != 0) {
        my $errors = CheckRuleData($ruleData);
        if (@{$errors}) {
            foreach (@{$errors}) {
                print STDERR "$_\n";
            }

            if ($self->{error_level} == 2) {
                die "Error with ruleData hash. Program exiting."
            }
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
    my ($self, $metric) = @_;

    ++$self->{numMetrics};
}

# This method is supported in ScarfXmlWriter, but is not
# currently supported by SarifJsonWriter
sub AddSummary {

}

# Returns the number of bugs
sub GetNumBugs {
    my ($self) = @_;

    return $self->{numBugs};
}

# Returns the number of metrics
sub GetNumMetrics {
    my ($self) = @_;

    return $self->{numMetrics};
}

# Get filenames created by SarifJsonWriter
sub GetWriterAttrs {
    my ($self, $hash) = @_;

    $hash->{'sarif-file'} = $self->{output};

    foreach my $key (keys %{$self->{external}}) {
        if ($self->{external}{$key}{maxItems}) {
            my $keyName = "sarif-$key-";
            my $length = @{$self->{external}{$key}{fileName}};

            for (my $i = 1; $i <= $length; $i++) {
                $hash->{$keyName . "$i-file"} = $self->{external}{$key}{fileName}[$i-1];
            }
        } else {
            $hash->{"sarif-$key-file"} = $self->{external}{$key}{fileName}[0];
        }
    }
}

# Closes results array, write data saved from AddBugInstance()
sub EndRun {
    my ($self, $endData) = @_;
    my $writer = $self->{writer};

    if ($self->{addArtifacts} || $self->{addArtifactsNoLocation}) {
        AddArtifactsObject($self, $endData->{sha256hashes});
    }
    if (keys %{$self->{xwriters}} > 0) {
        AddExternalPropertyFiles($self);
    }
    AddConversionObject($self, $endData->{conversion}) if defined $endData->{conversion};

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

    close $self->{fh};
}

# Helper method to write the toolComponent object
sub AddToolComponentObject {
    my ($self, $writer, $toolData) = @_;

    $writer->start_object();

    $writer->add_property("name", $toolData->{name});
    $writer->add_property("fullName", $toolData->{fullName}) if $toolData->{fullName};
    $writer->add_property("guid", $toolData->{guid}) if $toolData->{guid};
    $writer->add_property("version", $toolData->{version});
    $writer->add_property("semanticVersion", $toolData->{semanticVersion}) if $toolData->{semanticVersion};
    $writer->add_property("dottedQuadFileVersion", $toolData->{dottedQuadFileVersion}) if $toolData->{dottedQuadFileVersion};
    $writer->add_property("releaseDateUtc", $toolData->{releaseDateUtc}) if $toolData->{releaseDateUtc};
    $writer->add_property("downloadUri", $toolData->{downloadUri}) if $toolData->{downloadUri};
    $writer->add_property("informationUri", $toolData->{informationUri}) if $toolData->{informationUri};
    $writer->add_property("organization", $toolData->{organization}) if $toolData->{organization};
    $writer->add_property("product", $toolData->{product}) if $toolData->{product};
    $writer->add_property("productSuite", $toolData->{productSuite}) if $toolData->{productSuite};
    if ($toolData->{shortDescription}) {
        $writer->start_property("shortDescription");
        AddMultiformatMessageString($writer, $toolData->{shortDescription});
        $writer->end_property();
    }
    if ($toolData->{fullDescription}) {
        $writer->start_property("fullDescription");
        AddMultiformatMessageString($writer, $toolData->{fullDescription});
        $writer->end_property();
    }
    $writer->add_property("language", $toolData->{language}) if $toolData->{language};
    if ($toolData->{globalMessageStrings}) {
        $writer->start_property("globalMessageStrings");
        $writer->start_object();
        my @globalMessageStringsKeys;
        if ($self->{sortKeys}) {
            @globalMessageStringsKeys = sort keys %{$toolData->{globalMessageStrings}};
        } else {
            @globalMessageStringsKeys = keys %{$toolData->{globalMessageStrings}}
        }
        foreach my $key (@globalMessageStringsKeys) {
            next unless defined $toolData->{globalMessageStrings}{$key};
            $writer->start_property($key);
            AddMultiformatMessageString($writer, $toolData->{globalMessageStrings}{$key});
            $writer->end_property();
        }
        $writer->end_object();
        $writer->end_property();
    }
    if ($toolData->{rules} && @{$toolData->{rules}}) {
        $writer->start_property("rules");
        $writer->start_array();
        foreach my $rule (@{$toolData->{rules}}) {
            AddReportingDescriptorObject($self, $writer, $rule);
        }
        $writer->end_array();
        $writer->end_property();
    }
    if ($toolData->{notifications} && @{$toolData->{notifications}}) {
        $writer->start_property("notifications");
        $writer->start_array();
        foreach my $notification (@{$toolData->{notifications}}) {
            AddReportingDescriptorObject($self, $writer, $notification);
        }
        $writer->end_array();
        $writer->end_property();
    }
    if ($toolData->{taxa} && @{$toolData->{taxa}}) {
        $writer->start_property("taxa");
        $writer->start_array();
        foreach my $t (@{$toolData->{taxa}}) {
            AddReportingDescriptorObject($self, $writer, $t);
        }
        $writer->end_array();
        $writer->end_property();
    }
    if ($toolData->{supportedTaxonomies} && @{$toolData->{supportedTaxonomies}}) {
        $writer->start_property("supportedTaxonomies");
        foreach my $t (@{$toolData->{supportedTaxonomies}}) {
            AddToolComponentReferenceObject($self, $writer, $t);
        }
        $writer->end_property();
    }
    if ($toolData->{translationMetadata} && %{$toolData->{translationMetadata}}) {
        $writer->start_property("translationMetadata");
        AddTranslationMetadataObject($self, $writer, $toolData->{translationMetadata});
        $writer->end_property();
    }
    if ($toolData->{contents} && @{$toolData->{contents}}) {
        $writer->start_property("contents");
        $writer->start_array();
        foreach my $x (@{$toolData->{contents}}) {
            $writer->add_string($x);
        }
        $writer->end_array();
        $writer->end_property();
    }
    if (defined $toolData->{isComprehensive}) {
        $writer->start_property("isComprehensive");
        $writer->add_boolean($toolData->{isComprehensive});
        $writer->end_property();
    }
    $writer->add_property("localizedDataSemanticVersion", $toolData->{localizedDataSemanticVersion}) if $toolData->{localizedDataSemanticVersion};
    $writer->add_property("minimumRequiredLocalizedDataSemanticVersion", $toolData->{minimumRequiredLocalizedDataSemanticVersion}) if $toolData->{minimumRequiredLocalizedDataSemanticVersion};
    if ($toolData->{associatedComponent} && %{$toolData->{associatedComponent}}) {
        $writer->start_property("associatedComponent");
        AddToolComponentReferenceObject($self, $writer, $toolData->{associatedComponent});
        $writer->end_property();
    }

    $writer->end_object();
}

# Helper method to write the external property files object
sub AddExternalPropertyFiles {
    my ($self) = @_;
    my $writer = $self->{writer};

    $writer->start_property("externalPropertyFileReferences");
    $writer->start_object();

    foreach my $e (keys %{$self->{externalizableObject}}) {
        if ($self->{xwriters}{$e}) {
            if ($e eq "properties") {
                $writer->start_property("externalizedProperties")
            } else {
                $writer->start_property($e);
            }
            $writer->start_object();

            my $outputDir = "";
            if ($self->{output} =~ /(.*)\/.+\.sarif/) {
                $outputDir = $1;
            }
            my $filePath = AdjustPath($outputDir, ".", $self->{external}{$e}{fileName}[0]);
            AddArtifactLocation($writer, $filePath, undef, undef, 1);
            $writer->add_property("guid", $self->{external}{$e}{guid}[0]);
            $writer->end_object();
            $writer->end_property();
        }
    }

    foreach my $e (keys %{$self->{externalizableArray}}) {
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
                AddArtifactLocation($writer, $filePath, undef, undef, 1);
                $writer->add_property("guid", $self->{external}{$e}{guid}[$i]);
                $writer->add_property("itemCount", MakeInt($self->{external}{$e}{currItems}[$i]));
                $writer->end_object();
            }

            $writer->end_array();
            $writer->end_property();
        }
    }

    $writer->end_object();
    $writer->end_property();
}

# Helper method to add a message object
sub AddMessage {
    my ($writer, $message, $startProperty) = @_;

    $writer->start_property("message") if $startProperty;
    $writer->start_object();
    $writer->add_property("text", $message->{text}) if $message->{text};
    $writer->add_property("markdown", $message->{markdown}) if $message->{markdown};
    $writer->add_property("id", $message->{id}) if defined $message->{id};
    $writer->add_property("arguments", $message->{arguments}) if $message->{arguments};
    $writer->end_object();
    $writer->end_property() if $startProperty;
}

# Helper method to add a multiformatMessageString object
sub AddMultiformatMessageString {
    my ($writer, $mms) = @_;

    $writer->start_object();
    $writer->add_property("text", $mms->{text}) if $mms->{text};
    $writer->add_property("markdown", $mms->{markdown}) if $mms->{markdown};
    $writer->end_object();
}

# Helper method to add a reportingDescriptor object
sub AddReportingDescriptorObject {
    my ($self, $writer, $obj) = @_;
    $writer->add_property("id", $obj->{id}) if $obj->{id};
    if ($obj->{deprecatedIds} && @{$obj->{deprecatedIds}}) {
        $writer->start_property("deprecatedIds");
        $writer->start_array();
        foreach my $x (@{$obj->{deprecatedIds}}) {
            $writer->add_string($x);
        }
        $writer->end_array();
        $writer->end_property();
    }
    $writer->add_property("guid", $obj->{guid}) if $obj->{guid};
    if ($obj->{deprecatedGuids} && @{$obj->{deprecatedGuids}}) {
        $writer->start_property("deprecatedGuids");
        $writer->start_array();
        foreach my $x (@{$obj->{deprecatedGuids}}) {
            $writer->add_string($x);
        }
        $writer->end_array();
        $writer->end_property();
    }
    $writer->add_property("name", $obj->{name}) if $obj->{name};
    if ($obj->{deprecatedNames} && @{$obj->{deprecatedNames}}) {
        $writer->start_property("deprecatedNames");
        $writer->start_array();
        foreach my $x (@{$obj->{deprecatedNames}}) {
            $writer->add_string($x);
        }
        $writer->end_array();
        $writer->end_property();
    }
    if ($obj->{shortDescription}) {
        $writer->start_property("shortDescription");
        $writer->start_object();
        $writer->add_property("text", $obj->{shortDescription}{text}) if $obj->{shortDescription}{text};
        $writer->add_property("markdown", $obj->{shortDescription}{markdown}) if $obj->{shortDescription}{markdown};
        $writer->end_object();
        $writer->end_property();
    }
    if ($obj->{fullDescription}) {
        $writer->start_property("fullDescription");
        $writer->start_object();
        $writer->add_property("text", $obj->{fullDescription}{text}) if $obj->{fullDescription}{text};
        $writer->add_property("markdown", $obj->{fullDescription}{markdown}) if $obj->{fullDescription}{markdown};
        $writer->end_object();
        $writer->end_property();
    }
    if ($obj->{messageStrings}) {
        $writer->start_property("messageStrings");
        my @messageStringsKeys;
        if ($self->{sortKeys}) {
            @messageStringsKeys = sort keys %{$obj->{messageStrings}};
        } else {
            @messageStringsKeys = keys %{$obj->{messageStrings}};
        }
        foreach my $key (@messageStringsKeys) {
            next unless $obj->{messageStrings}{$key} && %{$obj->{messageStrings}{$key}};
            $writer->start_property($key);
            $writer->start_object();
            $writer->add_property("text", $obj->{messageStrings}{$key}{text}) if $obj->{messageStrings}{$key}{text};
            $writer->add_property("markdown", $obj->{messageStrings}{$key}{markdown}) if $obj->{messageStrings}{$key}{markdown};
            $writer->end_object();
            $writer->end_property();
        }
        $writer->end_property();
    }
    $writer->add_property("helpUri", $obj->{helpUri}) if $obj->{helpUri};
    if ($obj->{help} && %{$obj->{help}}) {
        $writer->start_property("help");
        $writer->start_object();
        $writer->add_property("text", $obj->{help}{text}) if $obj->{help}{text};
        $writer->add_property("markdown", $obj->{help}{markdown}) if $obj->{help}{markdown};
        $writer->end_object();
        $writer->end_property();
    }
    # Add defaultConfiguration property here
    # Add relationships property here
}

# Helper method to write a toolComponentReference object
sub AddToolComponentReferenceObject {
    my ($self, $writer, $obj) = @_;

    $writer->start_object();
    
    $writer->add_property("name", $obj->{name}) if $obj->{name};
    $writer->add_property("index", $obj->{index}) if $obj->{index};
    $writer->add_property("guid", $obj->{guid}) if $obj->{guid};

    $writer->end_object();
}

# Helper method to write a translationMetadata object
sub AddTranslationMetadataObject {
    my ($self, $writer, $obj) = @_;

    $writer->start_object();

    $writer->add_property("name", $obj->{name}) if $obj->{name};
    $writer->add_property("fullName", $obj->{fullName}) if $obj->{fullName};
    if ($obj->{shortDescription}) {
        $writer->start_property("shortDescription");
        $writer->start_object();
        $writer->add_property("text", $obj->{shortDescription}{text}) if $obj->{shortDescription}{text};
        $writer->add_property("markdown", $obj->{shortDescription}{markdown}) if $obj->{shortDescription}{markdown};
        $writer->end_object();
        $writer->end_property();
    }
    if ($obj->{fullDescription}) {
        $writer->start_property("fullDescription");
        $writer->start_object();
        $writer->add_property("text", $obj->{fullDescription}{text}) if $obj->{fullDescription}{text};
        $writer->add_property("markdown", $obj->{fullDescription}{markdown}) if $obj->{fullDescription}{markdown};
        $writer->end_object();
        $writer->end_property();
    }
    $writer->add_property("downloadUri", $obj->{downloadUri}) if $obj->{downloadUri};
    $writer->add_property("informationUri", $obj->{informationUri}) if $obj->{informationUri};

    $writer->end_object();
}

# Helper method to write an invocation object
sub AddInvocationObject {
    my ($self, $writer, $invocation, $isConversion) = @_;

    if (!$isConversion) {
        if (!exists $self->{invocation_indexes}{$invocation->{"build-artifact-id"}}) {
            $self->{invocation_indexes}{$invocation->{"build-artifact-id"}} = $self->{invocation_index_counter};
            $self->{invocation_index_counter} += 1;
        } else {
            die "This invocation object's build-artifact-id exists in another invocation object, which should not be possible.";
        }
    }

    $writer->start_object();

    CheckAndAddInvocation($writer, "commandLine", $invocation->{commandLine});

    if ($invocation->{args} && @{$invocation->{args}}) {
        $writer->start_property("arguments");
        $writer->start_array();
        foreach my $arg (@{$invocation->{args}}) {
            $writer->add_string($arg);
        }
        $writer->end_array();
        $writer->end_property();
    }

    if ($invocation->{env} && %{$invocation->{env}}) {
        $writer->start_property("environmentVariables");
        $writer->start_object();
        my @envKeys;
        if ($self->{sortKeys}) {
            @envKeys = sort keys %{$invocation->{env}};
        } else {
            @envKeys = keys %{$invocation->{env}};
        }
        foreach my $k (@envKeys) {
            $writer->add_property($k, $invocation->{env}{$k});
        }
        $writer->end_object();
        $writer->end_property();
    }

    if ($invocation->{workingDirectory}) {
        $writer->start_property("workingDirectory");
        $writer->start_object();
        if (!$isConversion) {
            # Necessary to AdjustPath() twice because the workingDirectory is an absolute path
            my $wd = AdjustPath(".", $self->{build_root_dir}, $self->{package_root_dir});
            $wd = AdjustPath($wd, ".", $invocation->{workingDirectory});
            $writer->add_property("uri", $wd);
            $writer->add_property("uriBaseId", "PACKAGEROOT");       
        } else {
            $writer->add_property("uri", $invocation->{workingDirectory});
        }
        $writer->end_object();
        $writer->end_property();  
    }

    if (!$isConversion) {
        CheckAndAddInvocation($writer, "exitCode", $invocation->{exitCode});
    } else {
        CheckAndAddInvocation($writer, "exitCode", 0);
    }

    if (!defined $invocation->{executionSuccessful}) {
        if ($self->{error_level} > 0) {
            print STDERR "executionSuccessful does not exist on this invocation object, defaulting to TRUE.\n";

            if ($self->{error_level} == 2) {
                die "Required key executionSuccessful does not exist on this invocation object. Exiting.";
            }
        }
        $invocation->{executionSuccessful} = 1;
    }
    $writer->start_property("executionSuccessful");
    $writer->add_boolean($invocation->{executionSuccessful});
    $writer->end_property();

    if ($invocation->{toolExecutionNotifications}) {
        $writer->start_property("toolExecutionNotifications");
        $writer->start_array();
        foreach my $n (@{$invocation->{toolExecutionNotifications}}) {
            $writer->start_object();
            $writer->add_property("level", $n->{level});
            AddMessage($writer, $n->{message}, 1);
            $writer->end_object();
        }
        $writer->end_array();
        $writer->end_property();
    }

    CheckAndAddInvocation($writer, "startTimeUtc", ConvertEpoch($invocation->{startTime}));
    if (!$isConversion) {
        CheckAndAddInvocation($writer, "endTimeUtc", ConvertEpoch($invocation->{endTime}));
    } else {
        CheckAndAddInvocation($writer, "endTimeUtc", ConvertEpoch(time()));
    }

    $writer->end_object();
}

# Helper method to write a location object
sub AddLocation {
    my ($self, $writer, $location) = @_;

    $writer->start_object();
    my $id = defined $location->{id} ? $location->{id} : -1;
    $writer->add_property("id", $id);

    AddPhysicalLocation($self, $writer, $location) if $location->{physicalLocation};
    AddMessage($writer, $location->{message}, 1) if $location->{message};

    # The AddRegionObject() method is not using the right data structure yet (still follows SCARF structure)
    # if ($location->{annotations}) {
    #     $writer->start_property("annotations");
    #     $writer->start_array();
    #     foreach my $r (@{$location->{annotations}}) {
    #        AddRegionObject($self, $writer);
    #     }
    #     $writer->end_array();
    #     $writer->end_property();
    # }

    if ($location->{relationships}) {
        $writer->start_property("relationships");
        $writer->start_array();
        foreach my $r (@{$location->{relationships}}) {
            AddLocationRelationship($writer, $r);
        }
        $writer->end_array();
        $writer->end_property();
    }
}

# Helper method to write a physicalLocation object
sub AddPhysicalLocation {
    my ($self, $writer, $location) = @_;

    $writer->start_property("physicalLocation");
    $writer->start_object();

    if ($location->{SourceFile}) {
        my $artifactname = AdjustPath($self->{package_root_dir}, ".", $location->{SourceFile});
        my $artifactBaseId = "PACKAGEROOT";
        my $artifactIndex;

        if (exists $self->{artifacts}{$artifactBaseId}{$location->{SourceFile}}) {
            $artifactIndex = $self->{artifacts}{$artifactBaseId}{$location->{SourceFile}}{index};
        } else {
            my %struct = (
                index => $self->{artifacts_counter},
                uriBaseId => $artifactBaseId,
                uri => $location->{SourceFile}
            );
            $self->{artifacts}{$artifactBaseId}{$location->{SourceFile}} = \%struct;
            push @{$self->{artifacts_array}}, \%struct;
            $artifactIndex = $self->{artifacts_counter}++;
        }

        if ($self->{addArtifactsNoLocation}) {
            AddArtifactLocation($writer, undef, undef, $artifactIndex, 1);
        } else {
            if ($self->{addArtifacts}) {
                AddArtifactLocation($writer, $artifactname, $artifactBaseId, $artifactIndex, 1);
            } else {
                AddArtifactLocation($writer, $artifactname, $artifactBaseId, undef, 1);
            }
        }
    }

    AddRegionObject($self, $writer, $location);

    $writer->end_object();
    $writer->end_property();
}

# Helper method to write a locationRelationship object
sub AddLocationRelationship {
    my ($writer, $r) = @_;

    $writer->start_object();
    $writer->add_property("target", $r->{target}) if defined $r->{target};
    if ($r->{kinds}) {
        $writer->add_property("kinds", $r->{kinds});
    } else {
        my @kinds = qw/relevant/;
        $writer->add_property("kinds", \@kinds);
    }
    AddMessage($writer, $r->{description}, 1) if $r->{description};
    $writer->end_object();
}

# Helper method to write an artifactLocation object
# if only 1 property -> adds only uri property
# else -> adds uri, uriBaseId and artifactIndex
sub AddArtifactLocation {
    my ($writer, $uri, $uriBaseId, $artifactIndex, $writeProperty) = @_;

    $writer->start_property("artifactLocation") if $writeProperty;
    $writer->start_object();
    $writer->add_property("uri", $uri) if (defined $uri);
    $writer->add_property("uriBaseId", $uriBaseId) if (defined $uriBaseId);
    $writer->add_property("index", $artifactIndex) if (defined $artifactIndex);
    $writer->end_object();
    $writer->end_property() if $writeProperty;
}

# Helper method to write the properties object
sub AddPropertiesObject {
    my ($self, $initialData) = @_;
    my $writer;

    if ($self->{xwriters}{properties}) {
        $writer = $self->{xwriters}{properties};
        $writer->start_property("externalizedProperties");
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

# Helper function to write the Files object
sub AddArtifactsObject {
    my ($self, $sha256hashes) = @_;
    my $writer;

    if ($self->{xwriters}{artifacts}) {
        $writer = $self->{xwriters}{artifacts};
    } else {
        $writer = $self->{writer};
    }

    BeginPropertyArray($self, "artifacts");

    foreach my $artifact (@{$self->{artifacts_array}}) {
        if (NewExternal($self, "artifacts")) { # Creates a new external file is needed
            $writer = $self->{xwriters}{artifacts}; # Reassigns the writer variable
        }

        my $artifactname = AdjustPath($self->{package_root_dir}, ".", $artifact->{uri});

        $writer->start_object();

        $writer->start_property("location");
        $writer->start_object();
        $writer->add_property("uri", $artifactname);
        $writer->add_property("uriBaseId", $artifact->{uriBaseId});
        $writer->end_object();
        $writer->end_property();

        if ($artifact->{uriBaseId} eq "PACKAGEROOT") {
            $writer->add_property("roles", ["resultFile"]);
        }

        if ($self->{artifactHashes}) {
            my $sha256;
            if ($sha256hashes && $artifact->{uriBaseId} eq "PACKAGEROOT") {
                # if a file containing all the hashes is provided
                my $hashPath = "build/".$artifact->{uri};
                $sha256 = FindSha256Hash($sha256hashes, $hashPath);
            } else {
                # no file containing all the hashes is provided, so attempt to compute it myself
                my $hashPath;
                if ($artifact->{uriBaseId} eq "PACKAGEROOT") {
                    $hashPath = AdjustPath($self->{package_root_dir}, $self->{build_root_dir}, $artifact->{uri});
                } elsif ($artifact->{uriBaseId} eq "RESULTSROOT") {
                    $hashPath = AdjustPath(".", $self->{results_root_dir}, $artifact->{uri});
                }
                if (-r $hashPath && -f $hashPath) {
                    $sha256 = digest_file_hex($hashPath, "SHA-256");
                }
            }

            if ($sha256) {
                $writer->start_property("hashes");
                $writer->start_object();
                $writer->add_property("sha-256", $sha256);
                $writer->end_object();
                $writer->end_property();
            } elsif ($self->{error_level} > 0) {
                print STDERR "Unable to find sha256 hash for $artifact->{uri}\n";
                if ($self->{error_level} == 2) {
                    die "Unable to find sha256hash. Exiting."
                }
            }
        }

        $writer->end_object();

        if ($self->{external}{artifacts} && exists $self->{external}{artifacts}{currItems}) {
            $self->{external}{artifacts}{currItems}[-1] += 1;
        }
    }


    EndPropertyArray($self, "artifacts");
}

# Helper function to write the region object
sub AddRegionObject {
    my ($self, $writer, $location) = @_;

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

        if ($self->{addSnippets} && $location->{SourceFile} && defined $location->{StartLine} && defined $location->{EndLine}) {
            my $snippetFile;
            if ($self->{buildDir}) {
                $snippetFile = AdjustPath(".", $self->{buildDir}, $location->{SourceFile});
            } else {
                $snippetFile = AdjustPath(".", $self->{build_root_dir}, $location->{SourceFile});
            }
            if (-r $snippetFile && -f $snippetFile) {
                open (my $snippetFh, '<', $snippetFile) or die "Can't open $snippetFile: $!";

                my $count = 1;
                my $snippetString = "";
                my $start;
                if ($location->{StartLine} - $self->{extraSnippets} < 1) {
                    $start = 1;
                } else {
                    $start = $location->{StartLine} - $self->{extraSnippets};
                }
                while(<$snippetFh>) {
                    if ($count > ($location->{EndLine} + $self->{extraSnippets})) {
                        last;
                    }
                    
                    if ($count >= $start) {
                        $snippetString = $snippetString . $_;
                    }
                    $count++;
                }

                if ($snippetString) {
                    $writer->start_property("snippet");
                    $writer->start_object();
                    $writer->add_property("text", $snippetString);
                    $writer->end_object();
                    $writer->end_property();
                    close $snippetFh;
                }
            } elsif ($self->{error_level} > 0) {
                print STDERR "Unable to read snippet from the file $snippetFile\n";

                if ($self->{error_level} == 0) {
                    die "Unable to read snippet. Exiting"
                }
            }
        }

        $writer->end_object();
        $writer->end_property(); # end region
    }
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
    } else {
        $writer = $self->{writer};
    }

    $writer->start_property("conversion");
    $writer->start_object();

    $writer->start_property("tool");
    $writer->start_object();
    $writer->start_property("driver");
    AddToolComponentObject($self, $writer, $conversion->{tool}{driver});
    $writer->end_property();
    $writer->end_object();
    $writer->end_property();

    $writer->start_property("invocation");
    AddInvocationObject($self, $writer, $conversion, 1);
    $writer->end_property();

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
        AddPhysicalLocation($self, $writer, $location);

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

# Convert Epoch time to UTC time and returns the string that adheres to the SARIF format
sub ConvertEpoch {
    my ($time) = @_;

    my $fraction;
    if ($time =~ /.+\.(.+)/) {
        $fraction = $1;
    }

    my ($sec, $min, $hour, $day, $month, $year) = gmtime($time);

    $year += 1900;
    $month += 1;

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

# Make the integer that is in a string into an integer
sub MakeInt {
    my ($var) = @_;

    return 0 + $var;
}

1;
