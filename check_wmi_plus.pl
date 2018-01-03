#!/usr/bin/perl -w
#
# check_wmi_plus.pl - nagios plugin for agentless checking of Windows
#
# Copyright (C) 2011 Matthew Jurgens
# You can email me using: mjurgens (the at goes here) edcint.co.nz
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

my $VERSION="1.34";

use strict;
use Getopt::Long;
use vars qw($PROGNAME);
use lib "/usr/lib/nagios/plugins"; # CHANGE THIS IF NEEDED
use utils qw ($TIMEOUT %ERRORS &print_revision &support);
use Data::Dumper;

my $default_bytefactor=1024;  

my $opt_Version='';
my $opt_host='';
my $opt_help='';
my $opt_mode='';
my $opt_sub_mode='';
my $opt_username='';
my $opt_password='';
my $opt_arguments='';
my $opt_other_arguments='';
my $opt_warn='';
my $opt_critical='';
my $opt_timeout='';
my $opt_bytefactor='';
my $debug=0;
my $opt_new='';
my $opt_value='';
my $opt_z='';
my $opt_delay=10; # the default value if none is specified

my ($wmi_commandline, $output);
$PROGNAME="check_wmi";

my $wmic_command='/opt/nagios/bin/plugins/wmic'; # CHANGE THIS IF NEEDED
if (! -x $wmic_command) {
   print "This plugin requires the linux implementation of wmic eg from zenoss.\nOnce wmic is installed, configure its location by setting the \$wmic_command variable in this plugin.";
   exit $ERRORS{"UNKNOWN"};
}

# set the location of the ini file. Set to '' if not using it
my $wmi_ini_file=''; # CHANGE THIS IF NEEDED
if ($wmi_ini_file && ! -f $wmi_ini_file) {
   print "This plugin requires an INI file.\nConfigure its location by setting the \$wmi_ini_file variable in this plugin.";
   exit $ERRORS{"UNKNOWN"};
} else {
   # now that we are using an ini file we need this module 
   use Config::IniFiles;
}


# list all valid modes with dedicated subroutines here
# all the modes that can take a critical/warning specification set to value of 1
my %mode_list = ( 
   checkcpu => 1,
   checkcpuq => 1,
   checknetwork => 0,
   checkmem => 1,
   checkuptime => 1,
   checkdrivesize => 1,
   checkeventlog  => 1,
   checkfileage   => 1,
   checkfilesize  => 1,
   checkprocess   => 1,
   checkservice   => 1,
   checkwsusserver=> 0,
   checkfoldersize=> 1,
);

# multipliers are calculated as BYTEFACTOR^mulitpler eg m = x * 1000^2 or x * 1024^2
my %multipliers=(
   k  => 1,
   m  => 2,
   g  => 3,
   t  => 4,
   p  => 5,
   e  => 6,
);

my %time_multipliers=(
   sec   => 1,
   min   => 60,
   hr    => 3600,
   day   => 86400,
   wk    => 604800,
   mth   => 2629800,  # this one is not exact. We assume that there are 365.25/12=30.4375 days in a month on average
   yr    => 31557600, # this one is also approximate. We assume that there are 365.25 days per year
);

# this regex finds if a multiplier is valid - just list all multiplier options in here
my $multiplier_regex="[KMGTPE|min|hr|day|wk|mth|yr]";

Getopt::Long::Configure('no_ignore_case');
GetOptions(
   "Version"      => \$opt_Version,
   "help"         => \$opt_help,
   "mode=s"       => \$opt_mode,
   "submode=s"    => \$opt_sub_mode,
   "Hostname=s"   => \$opt_host,
   "username=s"   => \$opt_username,
   "password=s"   => \$opt_password,
   "arguments=s"  => \$opt_arguments,
   "otheraguments=s"=>\$opt_other_arguments,
   "warning=s"    => \$opt_warn,
   "critical=s"   => \$opt_critical,
   "timeout=i"    => \$opt_timeout,
   "bytefactor=s" => \$opt_bytefactor,
   "debug"        => \$debug,
   "value=s"      => \$opt_value,
   "ydelay=s"     => \$opt_delay,
   "z"            => \$opt_z,
   );
 
if ($opt_timeout) {
   $TIMEOUT=$opt_timeout;
}

if ($opt_bytefactor) {
   if ($opt_bytefactor ne '1024' && $opt_bytefactor ne '1000') {
      print "The BYTEFACTOR option must be 1024 or 1000. '$opt_bytefactor' is not valid.\n";
      short_usage();
   }
}
my $actual_bytefactor=$opt_bytefactor || $default_bytefactor;

# Setup the trap for a timeout
$SIG{'ALRM'} = sub {
   print "UNKNOWN - Plugin Timed out ($TIMEOUT sec)\n";
   exit $ERRORS{"UNKNOWN"};
};
alarm($TIMEOUT);
 
if ($opt_help) {
   usage();
}
if ($opt_Version) {
   print "Version: $VERSION\n";
   exit $ERRORS{'OK'};
}

if ($opt_warn && $opt_critical && $opt_value) {
   # making it easier to test warning/critical values
   # pass in -w SPEC -c SPEC and -v VALUE
   my ($test_result,$neww,$newc)=test_limits($opt_warn,$opt_critical,$opt_value);
   print "Overall Status Generated = $test_result ($neww,$newc)\n";
   exit $test_result;
}

if (! $opt_host) {
   print "No Hostname specified\n\n";
   short_usage();
}
 
#if ($mode_list{$opt_mode} && !$opt_critical) {
#   print "No critical threshold specified\n\n";
#   short_usage();
#}
#
#if ($mode_list{$opt_mode} && !$opt_warn) {
#   print "No warning threshold specified\n\n";
#   short_usage();
#} 

# now run the appropriate sub for the check
if (defined($mode_list{$opt_mode})) {
   # have to set a reference to the subroutine since strict ref is set
   my $subref=\&$opt_mode;
   &$subref('');
} else {
   my $mode_ok=0;
   if ($wmi_ini_file) {
      # maybe the mode is defined in the ini file
      # read the ini file and check
      my $wmi_ini = new Config::IniFiles( -file => "$wmi_ini_file", -allowcontinue => 1 );
      # load the ini file groups into an array - a group is a mode
      my @ini_modes=$wmi_ini->Groups();
       # see if we have found the mode
      my @found_modes=grep(/^$opt_mode$/,@ini_modes);
      if ($#found_modes==0) {
         print "Found $opt_mode\n";
         $mode_ok=1;
      }

   }

   if (!$mode_ok) {
      print "A valid MODE must be specified\n";
      short_usage();
   }
}

# if we get to here we default to an OK exit
exit $ERRORS{'OK'};

#-------------------------------------------------------------------------
sub short_usage {
my ($no_exit)=@_;
print <<EOT;
Usage: -H HOSTNAME -u DOMAIN/USER -p PASSWORD -m MODE [-b BYTEFACTOR] [-a ARG ] [-w WARN] [-c CRIT] [-o OTHERARG] [-t TIMEOUT] [-y DELAY] [-d] [-z]
EOT
if (!$no_exit) {
   print "Specify the --help parameter to view the complete help information\n";
   exit $ERRORS{'UNKNOWN'};
}
}
#-------------------------------------------------------------------------
sub usage {
my $multiplier_list=join(', ',keys %multipliers);
my $time_multiplier_list=join(', ',keys %time_multipliers);

# there is probably a better way to do this
# I want to list out all the keys in the hash %mode_list where the value = 0
my $modelist='';
for my $mode (sort keys %mode_list) {
   if (!$mode_list{$mode}) {
      $modelist.="$mode, "
   }
}
$modelist=~s/, $/./;

short_usage(1);
print <<EOT;

where 
BYTEFACTOR is either 1000 or 1024 and is used for conversion units eg bytes to GB. Default is 1024.
TIMEOUT is in seconds
-d Enable debug
-z Provide full specification warning and critical values for performance data. 
   Not all performance data processing software can handle this eg PNP4Nagios

MODE=checkfilesize
------------------
   ARG: full path to the file. Use '/' (forward slash) instead of '\\' (backslash).
      eg "C:/pagefile.sys" or "C:/windows/winhlp32.exe"
   WARN/CRIT can be used as described below. They match against the file size.

MODE=checkfileage
----------------
   ARG: full path to the file. Use '/' (forward slash) instead of '\\' (backslash).
   WARN/CRIT can be used as described below. They match against the age of a file.
      The warning/critical values should be specified in seconds. However you can use the time multipliers
      ($time_multiplier_list) to make it easier to use 
      eg instead of putting -w 3600 you can use -w 1hr
      eg instead of putting -w 5400 you can use -w 1.5hr
      Typically you would specify something like -w 24: -c 48:
   OTHERARG: set this to one of the time multipliers ($time_multiplier_list)
      This becomes the display unit and the unit used in the performance data. Default is hr.
      -z can not be used for this mode.

MODE=checkfoldersize
--------------------
   WARNING - This check can be slow and may timeout, especially if including subdirectories. 
      It can overload the Windows machine you are checking. Use with caution.
   ARG: full path to the file. Use '/' (forward slash) instead of '\\' (backslash).
      eg "C:/windows" or "C:/windows/system32"
   OTHERARG: set this to s to include files from subdirectories eg -o s
   WARN/CRIT can be used as described below. The match against the folder size.

MODE=checkdrivesize
-------------------
   ARG: drive letter of the disk to check
      To include multiple drives separate them with a | or use the word All
      eg "C" or "C:" or "C|E" or "All"
   WARN/CRIT can be used as described below. They match against the used %.

MODE=checkcpu
-------------
   DELAY: (optional) specifies the number of seconds over which the CPU utilisation is calculated. The 
      default value is $opt_delay. If specifying longer values you may also need to use the -t parameter to 
      set a longer script timeout.
   WARN/CRIT can be used as described below. They match against the utilisation %.

MODE=checkcpuq
-------------
   The WMI implementation of CPU Queue length is a point value.
   We try and improve this slightly by performing several checks and averaging the values.
   ARG: (optional) specifies how many point checks and the delay between each one in the format
      COUNT:DELAY eg 3:2 for 3 checks, 2 seconds apart
      DELAY can be 0 but in reality there will always be some delay between checks as it takes time
      to perform the actual WMI query 
   WARN/CRIT can be used as described below. They match against the average queue length.
   
   Note: Microsoft says "A sustained processor queue of greater than two threads generally indicates
   processor congestion.". However, we recommended testing your warning/critical levels to determine the
   optimal value for you.
   
MODE=checknetwork
-------------
   Shows various network parameters. Note that the BYTEFACTOR is set to 1000 by default for this mode.
   ARG: (Recommended) Specify with network adapter the stats are collected for.
      The name of the network adaptors as seen from WMI are similar to what is seen in the output of the 
      ipconfig/all command on Windows. However, its not exactly the same. Run without -a to list the adapter
      names according to WMI. Typically you need to use '' around the adapter name when specifying.
      eg -a 'Intel[R] PRO_1000 T Server Adapter _2 - Packet Scheduler Miniport'
   WARN/CRIT are ignored for now. Later we intend to add the ability to warn/crit off any of the returned values.
   BYTEFACTOR defaults to 1000 for this mode. You can override this if you wish.
   
MODE=checkmem
-------------
   ARG: "physical" for physical memory "page" for pagefile
   WARN/CRIT can be used as described below. They match against the used %.

MODE=checkeventlog
------------------
   ARG: 3 parameters separated by commas "Name of the log, Severity, Number of past hours to check for events",
      where the name can be "System" or "Application" for example, the severity is 2 = warning 1 = error.
      for example to report all errors that got logged in the past 24 hours in the System event log use: "System,1,24".
      It ignores errors from Terminal Server printers, as they occur at every RDP connection from an admin.
   WARN/CRIT can be used as described below. They match against the number of events found.

MODE=checkservice
-----------------
   ARG: the short or long service name that can be seen in the properties of the service in Windows
      Regular expressions can be used. Use Auto to check that all automatically started services are OK.
   WARN/CRIT can be used as described below. They match against the number of processes. 
   OTHERARG can be specfied as "good", "bad" (the default), or total and makes the WARN/CRIT values match either the number
      of services that are in a "good" state (running ok), in a "bad" state (stopped/failed etc), or the total number of
      services matched. eg -a Exchange -o bad -c 0

MODE=checkprocess
-----------------
   ARG: the name of a process to look for. Use % for wildcard.
   WARN/CRIT can be used as described below. They match against the number of processes found.

MODE=checkwsusserver
--------------------
   If there are any WSUS related errors in the event log in the last 24 hours a CRITICAL state is returned.

MODE=checkuptime
----------------
   WARN/CRIT can be used as described below. They match against the number of minutes of uptime.
      Typically you would specify something like -w 10: -c 20:

WARNING and CRITICAL Specification:
===================================

If warning or critical specifications are not provided then no checking is done and the check simply returns the value and any related performance data. If they are specified then they should be formatted as shown below.

A range is defined as a start and end point (inclusive) on a numeric scale (possibly negative or positive infinity). The theory is that the plugin will do some sort of check which returns back a numerical value, or metric, which is then compared to the warning and critical thresholds. 

This is the generalised format for ranges:
[@]start:end

Notes:
   1. start <= end
   2. start and ":" is not required if start=0
   3. if range is of format "start:" and end is not specified, assume end is infinity
   4. to specify negative infinity, use "~"
   5. alert is raised if metric is outside start and end range (inclusive of endpoints)
   6. if range starts with "@", then alert if inside this range (inclusive of endpoints)
   7. The start and end values can use multipliers from the following list: $multiplier_list
      eg 1G for 1 x 10^9 or 2.5k for 2500

Example ranges:

WARN/CRIT definition    Generate an alert if x...
10                      < 0 or > 10, (outside the range of {0 .. 10})
10:                     < 10, (outside {10 .. 8})
~:10                    > 10, (outside the range of {-8 .. 10})
10:20                   < 10 or > 20, (outside the range of {10 .. 20})
\@10:20                  = 10 and = 20, (inside the range of {10 .. 20})
10                      < 0 or > 10, (outside the range of {0 .. 10})
10G                     < 0 or > 10G, (outside the range of {0 .. 10G})

WARN and/or CRIT are not used for the following MODES: $modelist
EOT

exit $ERRORS{'UNKNOWN'};
}
#-------------------------------------------------------------------------
sub display_uptime {
# pass in an uptime string
# if it looks like it is in seconds then we convert it to look like days, hours minutes etc
my ($uptime_string)=@_;
my $new_uptime_string=$uptime_string;
if ($uptime_string=~/^[0-9\.]+$/) {
   # its in seconds, so convert it
   my $uptime_minutes=sprintf("%d",$uptime_string/60);
   my $uptime=$uptime_string;
   my $days=int($uptime/86400);
   $uptime=$uptime%86400;
   my $hours=int($uptime/3600);
   $uptime=$uptime%3600;
   my $mins=int($uptime/60);
   $uptime=$uptime%60;

   my $day_info='';
   if ($days==1) {
      $day_info="$days day";
   } elsif ($days>1) {
      $day_info="$days days";
   }
   $new_uptime_string="$day_info " . sprintf("%02d:%02d:%02d (%smin)",$hours,$mins,$uptime,$uptime_minutes);
}
return $new_uptime_string; 
}
#-------------------------------------------------------------------------
sub scaled_bytes {
# from http://www.perlmonks.org/?node_id=378538
# very cool
(sort { length $a <=> length $b }
map { sprintf '%.3g%s', $_[0]/$actual_bytefactor**$_->[1], $_->[0] }
[" bytes"=>0],[KB=>1],[MB=>2],[GB=>3],[TB=>4],[PB=>5],[EB=>6])[0]
}
#-------------------------------------------------------------------------
sub get_multiple_wmi_samples {
# perform the same WMI query 1 or more times with a time delay in between and return the results in an array
# good for using RAW performance data and gives me a standard way to perform queries and have the results loaded into a known structure
# pass in
# number of samples to get
# the WMI query to get the values you are wanting
# the regular expression to extract the names of the values
# the regular expression to extract the results
# an array reference where the results will be placed. Index 0 will contain the first values, index 1 the second values
# the delay (passed to the sleep command) between queries. This is reference that "passed back" so that the calling sub can see what was actually used. Pass by reference using \$VARIABLE
# An array reference listing the column titles that we should provide sums for - these will be made available in array index 0 prefixed by SUM_ - I can see us needing to add more flexibility to this option later

# we return an empty string if it worked ok, a msg if it failed
my ($num_samples,$wmi_query,$column_name_regex,$value_regex,$results,$specified_delay,$provide_sums)=@_;

# the array @[$results} will look something like this when we have loaded it
# @array[INDEX1][INDEX2]{HASH1}=VALUE
# where
# INDEX1 is number of the query eg if we do 2 queries then INDEX1 will be 0 and 1
# INDEX2 is the result line, with one index per line returned in the WMI query eg if we do a query which lists 5 processes INDEX2 will be from 0 to 4
# HASH1 will contain the field names eg ProcessorQueueLength
# the value will be the value of the field eg 16
# There are some special values also stored in this structure
# @array[0][0]{'CHECKSOK'}=the number of checks that were completed OK
# @array[INDEX1][0]{'ROWSFOUND'}=the number of rows returned by the WMI query number INDEX1
# If providing Sums then @array[0][INDEX2]{'SUM_FIELDNAME'}=the sum of all FIELDNAMES found at ROW number INDEX2 - I can see this one might need to change at some point - but it works for now
# So if you are doing only a single query that returns a single row then INDEX1 always=0 and then INDEX always=0 as well


# extract parameters from arguments
my $delay=$opt_delay; # this is the default delay if none is specified
if ($$specified_delay ne '') {
   $delay=$$specified_delay;
   if ($delay>=0) {
      # all good - we assume
   } else {
      print "Delay not specified correctly. Should be a number >= zero.\n";
      exit $ERRORS{'UNKNOWN'};
   }
}

# set the actual delay to be used so that it is passed back to the caller
$$specified_delay=$delay;

$wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host '$wmi_query'";

my $all_output=''; # this holds information if any errors are encountered

my $failure=0;
my $checks_ok=0;
my @hardcoded_field_list;

for (my $i=0;$i<$num_samples;$i++) {
   $output = `$wmi_commandline 2>&1`;
   # output of the command depends on the query. We use the regex to determine if it worked ok
   # could be something like this:
   #CLASS: Win32_PerfRawData_PerfOS_Processor
   #Name|PercentProcessorTime|Timestamp_Sys100NS
   #_Total|2530739524720|129476821059431200

   $all_output.=$output;
   $debug && print "Round #$i, looking for $column_name_regex\n";
   $debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";
   # doing this check each time helps validate the results
   # after this column name regex the next regex should start looking after the column names
   if ($output=~/$column_name_regex/sg) {
      my @column_names=();
      
      my $j=0;
      # I'd really like to use a perl 5.10 construct here (Named Capture buffers ie the hash $+) to make it much nicer code but have decided to do it an ugly way to accomodate older versions
      # so now we have to go through $1, $2 one at a time in a hardcoded fashion (is there a better way to do this?) 
      # this places a hard limit on the number of fields we can find in our regex
      #------------------------------------------------------
      # add more hardcoding here as needed - yuk - at some point we will use %+ - when enough people are on perl 5.10 or more
      # hopefully putting these to zero if they do not have any value will be ok, need a way to tell if $1 is '' or 0 really
      @hardcoded_field_list=( $1||0,$2||0,$3||0,$4||0,$5||0,$6||0,$7||0,$8||0,$9||0 );
      #------------------------------------------------------
      $debug && print "COLUMNS:";
      foreach my $regex_field (@hardcoded_field_list) {
         $debug && print "$regex_field, ";
         if ($regex_field ne '') {
            $column_names[$j]=$regex_field;
         }
         $j++;
      }
      $debug && print "\n";
      # increment the ok counter
      $$results[0][0]{'CHECKSOK'}++;

      # now find the results
      $debug && print "Now looking for $value_regex\n";
      my $found=0;
      while ($output=~/$value_regex/sg) {
         # now we have matched a result row, so break it up into fields
         my $j=0;
         #------------------------------------------------------
         # add more hardcoding here as needed - yuk - at some point we will use %+ - when enough people are on perl 5.10 or more
         # hopefully putting these to zero if they do not have any value will be ok, need a way to tell if $1 is '' or 0 really
         @hardcoded_field_list=( $1||0,$2||0,$3||0,$4||0,$5||0,$6||0,$7||0,$8||0,$9||0 );
         #------------------------------------------------------
         $debug && print "FIELDS:";
         foreach my $regex_field (@hardcoded_field_list) {
            $debug && print "$regex_field, ";
            if ($regex_field ne '') {
               $$results[$i][$found]{$column_names[$j]}=$regex_field;
            }
            $j++;
         }
         $debug && print "\n";
         # $debug && print "Regex Succeeded $&\n" - apparently using $& slows down perl
         $debug && print "Regex Succeeded\n";
         
         # provide Sums if the parameter is defined
         foreach my $field_name (@{$provide_sums}) {
            # we have to sum up all the fields named $field_name
            # we can assume that they are numbers
            # and we also assume that they are valid for this WMI query! ie that the programmer got it right!
            $$results[0][$found]{"SUM_$field_name"}+=$$results[$i][$found]{$field_name};
         }
         # increment the results counter for this query
         $found++;         
      }
      # record the number of rows found for this query
      $$results[$i][0]{'ROWSFOUND'}=$found;
   } else {
      $failure++;
   }  
   if ($i+1!=$num_samples) {
      # only need to sleep the first time round and its not the last
      sleep $delay;
   }

}

$debug && print Dumper($results);

my $sub_result='';
if ($failure>0) {
   $sub_result=$all_output;
}
return $sub_result;
}
#-------------------------------------------------------------------------
sub checkcpu {
my @collected_data;
my $data_errors=get_multiple_wmi_samples(2,
   "select PercentProcessorTime,Timestamp_Sys100NS from Win32_PerfRawData_PerfOS_Processor where Name=\"_Total\"",
   '(PercentProcessorTime)\|(Timestamp_Sys100NS)\n',
   '_Total\|(.*?)\|(.*?)\n',
   \@collected_data,
   \$opt_delay,
   
   );

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   # at this point we can assume that we have all the data we need stored in @collected_data
   # see http://msdn.microsoft.com/en-us/library/aa392397%28v=vs.85%29.aspx
   # all our results in in the first query [0] and on the first row [0]
   my $avg_cpu_util=(1- 
      (      ($collected_data[1][0]{'PercentProcessorTime'} - $collected_data[0][0]{'PercentProcessorTime'}) / 
             ($collected_data[1][0]{'Timestamp_Sys100NS'} - $collected_data[0][0]{'Timestamp_Sys100NS'})
      ) )* 100;
   my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$avg_cpu_util);
   my $display_info="Average CPU Utilisation " . sprintf("%.0f", $avg_cpu_util) . "% (Over approx ${opt_delay} sec period)|'Avg CPU Utilisation'=" . sprintf("%.0f", $avg_cpu_util) . "%;$warn_perf_spec;$critical_perf_spec;";
   print "$display_info\n";
   exit $test_result;
}

}
#-------------------------------------------------------------------------
sub checknetwork {
my @collected_data;

# for network stuff we often want $actual_bytefactor to be 1000
# so lets use that unless the user has set something else
if (!$opt_bytefactor) {
   $actual_bytefactor=1000;
}

my $where_bit='';
if ($opt_arguments ne '') {
   $where_bit="where Name=\"$opt_arguments\"";
}
my $data_errors=get_multiple_wmi_samples(1,
   "select CurrentBandwidth,BytesReceivedPerSec,BytesSentPerSec,Name,OutputQueueLength,PacketsReceivedErrors,PacketsReceivedPerSec,PacketsSentPerSec,Timestamp_Sys100NS from Win32_PerfFormattedData_Tcpip_NetworkInterface $where_bit",
   '(BytesReceivedPersec)\|(BytesSentPersec)\|(CurrentBandwidth)\|(Name)\|(OutputQueueLength)\|(PacketsReceivedErrors)\|(PacketsReceivedPersec)\|(PacketsSentPersec)\|(Timestamp_Sys100NS)\n',
   '([0-9]+?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\n',
   \@collected_data,
   \$opt_delay,
   
   );

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} elsif ($#collected_data>=0) {
   # at this point we can assume that we have all the data we need stored in @network_data
   # there is some point collected data that could be useful to average over a few samples here
   # I may do that later
   
   if ($where_bit) {
      #my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$avg_cpu_util);
      my $test_result=0;
      # all our results in in the first query [0] and on the first row [0]
      my $display_info="Interface: $collected_data[0][0]{'Name'} (Rate:" . scaled_bytes($collected_data[0][0]{'CurrentBandwidth'}) . ") - Send Rate = " . scaled_bytes($collected_data[0][0]{'BytesSentPersec'}) . "/s, Receive Rate = " . scaled_bytes($collected_data[0][0]{'BytesReceivedPersec'}) . "/s, Send Packets/s = $collected_data[0][0]{'PacketsSentPersec'}, Receive  Packets/s = $collected_data[0][0]{'PacketsReceivedPersec'}, Output Queue Length = $collected_data[0][0]{'OutputQueueLength'}|'Bytes Sent persec'=$collected_data[0][0]{'BytesSentPersec'}persec; 'Bytes Received persec'=$collected_data[0][0]{'BytesSentPersec'}persec; 'Output Queue Length'=$collected_data[0][0]{'OutputQueueLength'}; 'Packets Sent persec'=$collected_data[0][0]{'PacketsSentPersec'}persec; 'Packets Received persec'=$collected_data[0][0]{'PacketsReceivedPersec'}persec;";
      print "$display_info\n";
      exit $test_result;
   } else {
      # no where_bit specified so just list out all the adapter names
      print "Adapter Names are:\n" . list_collected_values_from_all_rows(\@collected_data,'Name',"\n") . "\nSpecify the -a parameter with an adapter name.";
      exit $ERRORS{'UNKNOWN'};
   }
} else {
   print "No data returned. Possibly the Network Adapter Name does not exist. Stop using the -a parameter and this will list valid adapter names.";
   exit $ERRORS{'UNKNOWN'};
}

}
#-------------------------------------------------------------------------
sub checkcpuq {
# extract parameters from arguments
my $check_count=3;
my $check_delay=1;
if ($opt_arguments) {
   # specified as COUNT:DELAY
   ($check_count,$check_delay)=split(':',$opt_arguments);
   if ($check_count && $check_delay>=0) {
      # all good - we assume
   } else {
      print "Check delay and check count not specified correctly. Should be in the format COUNT:DELAY.\n";
      exit $ERRORS{'UNKNOWN'};
   }
}

my @collected_data;
my $data_errors=get_multiple_wmi_samples($check_count,
   "select ProcessorQueueLength from Win32_PerfRawData_PerfOS_System",
   '(ProcessorQueueLength)\n',
   '([0-9]+?)\n',
   \@collected_data,
   \$check_delay,
   [ 'ProcessorQueueLength' ]
   );

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   # at this point we can assume that we have all the data we need stored in @collected_data
   my $avg_cpu_queue_length=$collected_data[0][0]{'SUM_ProcessorQueueLength'}/$collected_data[0][0]{'CHECKSOK'};
   my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$avg_cpu_queue_length);
   my $display_info="Average CPU Queue Length " . sprintf("%.1f", $avg_cpu_queue_length) . " ($check_count points with $check_delay sec delay gives values: " . list_collected_values_from_all_rows(\@collected_data,'ProcessorQueueLength',', ') . ")|'Avg CPU Queue Length'=" . sprintf("%.1f", $avg_cpu_queue_length) . ";$warn_perf_spec;$critical_perf_spec;";
   print "$display_info\n";
   exit $test_result;
}

}
#-------------------------------------------------------------------------
sub checkmem {
# note that for this check WMI returns data in kiobytes so we have to multiply it up to get bytes before using scaled_bytes

my $display_type='';
if ($opt_arguments eq "physical") {
   $display_type='Physical Memory';
   $wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host \"Select Name,FreePhysicalMemory,TotalVisibleMemorySize from Win32_OperatingSystem\"";
   # expect output like
   #CLASS: Win32_OperatingSystem
   #FreePhysicalMemory|Name|TotalVisibleMemorySize
   #515204|Microsoft Windows XP Professional|C:\WINDOWS|\Device\Harddisk0\Partition1|1228272   
} elsif ($opt_arguments eq "page") {
   $display_type='Page File';
   $wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host \"Select Name,FreeVirtualMemory,TotalVirtualMemorySize from Win32_OperatingSystem\"";
   # expect output like
   #CLASS: Win32_OperatingSystem
   #FreeVirtualMemory|Name|TotalVirtualMemorySize
   #2051912|Microsoft Windows XP Professional|C:\WINDOWS|\Device\Harddisk0\Partition1|2097024
} else {
   print "UNKNOWN: invalid argument in the checkmem function - should be page or physical.\n";
   exit $ERRORS{'UNKNOWN'};
}

$output = `$wmi_commandline 2>&1`;
$debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";

if ($output=~/CLASS: Win32_OperatingSystem/) {
   
   if ($output=~/CLASS: Win32_OperatingSystem\n.*?\n(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\n/s) {
      my $mem_total=$5;
      my $mem_free=$1;
      my $mem_used=$mem_total-$mem_free;
      my $mem_used_percent=sprintf("%.0f",$mem_used/$mem_total*100);
      my $mem_free_percent=sprintf("%.0f",$mem_free/$mem_total*100);

      my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$mem_used_percent);
         
      my $display_info="$display_type: Total: " . scaled_bytes($mem_total*$actual_bytefactor) . 
         " - Used: " . scaled_bytes($mem_used*$actual_bytefactor) . " (${mem_used_percent}%)" .
         " - Free: " . scaled_bytes($mem_free*$actual_bytefactor) . " (${mem_free_percent}%)" . 
         "|'$display_type%'=${mem_used_percent}%;$warn_perf_spec;$critical_perf_spec;";
      
      print "$display_info\n"; 
      exit $test_result;
   } else {
      print "Could not find required values. Output follows -\n$output";
      exit $ERRORS{'UNKNOWN'};
   }

} else {
   print "UNKNOWN: $output";
   exit $ERRORS{'UNKNOWN'};
}
  
}
#-------------------------------------------------------------------------
sub checkfileage {
# initial idea from steav on github.com
# its a good idea and we modified to for our use using our programming techniques and 
# ensuring that the warning/critical criteria were consistently used
# this is where we also first introduced the time multipliers

use DateTime;

# replace any / in the $opt_arguments with \\ since \ are difficult to use in linux on the command line
# we replace it with \\ to pass an actual \ to the command line
# use # as the delimiter for the regex to make it more readable
my $internal_opt_arguments=$opt_arguments;
$internal_opt_arguments=~s#\/#\\\\#g;

my $perf_data_unit='hr'; # default unit is hours
# if the user specifies it but it is not valid we silently fail
if (defined($time_multipliers{$opt_other_arguments})) {
   # looks like the user has specified a valid time multiplier for use in the performance data
   $perf_data_unit=$opt_other_arguments;  
}
my $perf_data_divisor=$time_multipliers{$perf_data_unit};

# we can not support full performance data with warn/crit since we want to divide it by whatever units the user specifies
$opt_z=''; 

my @collected_data;

my $data_errors=get_multiple_wmi_samples(1,
   "Select name,lastmodified from CIM_DataFile where name=\"$internal_opt_arguments\"",
   '(LastModified)\|(Name)\n',
   '(.+?)\|(.*?)\n',
   \@collected_data,
   \$opt_delay,
   
   );

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {

   # check to see if we found the file
   if ($collected_data[0][0]{'Name'}) {
      my $lastmodified=$collected_data[0][0]{'LastModified'};
      
      if ($lastmodified=~/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).(\d*)([+\-])+(\d*)$/) {
         # now convert that fileage to seconds
         my $dt = DateTime->new(
            year       => $1,
            month      => $2,
            day        => $3,
            hour       => $4,
            minute     => $5,
            second     => $6,
            nanosecond => $7,
            # we initially think that we don't care about the timezone
            # its possible that this might be wrong if the systems are in different timezones?
            # if we need to we have the WMI returned timezone as $8 . sprintf("%04d",$9) (it has to be padded with leading zeros)
            time_zone  => 'floating' 
           );
         my $lastmod_sec=$dt->epoch();
         my $current_dt=DateTime->now( time_zone => 'local' )->set_time_zone('floating');
         my $current_sec=$current_dt->epoch();
         my $fileage=$current_sec-$lastmod_sec;
         $debug && print "Fileage returned as $1,$2,$3,$4,$5,$6,$7,$8,$9 = $lastmod_sec sec vs Current $current_sec sec, Fileage=$fileage sec\n";
         
         my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$fileage);
   
         my $display_fileage=sprintf("%.2f",$fileage/$perf_data_divisor);
         my $nicely_formatted_fileage=display_uptime($fileage);
         # performance data should always be in a fixed unit (we use seconds) for consistency
         # apply the /$perf_data_divisor throughout the performance data
         my $performance_data="'$opt_arguments $perf_data_unit'=$display_fileage$perf_data_unit;" . $warn_perf_spec/$perf_data_divisor . ";" . $critical_perf_spec/$perf_data_divisor . "; ";
   
         my $triggered_range='';
         if ($test_result==$ERRORS{'WARNING'}) {
            $triggered_range=" The range criteria not met is $opt_warn.";
         } elsif ($test_result==$ERRORS{'CRITICAL'}) {
            $triggered_range=" The range criteria not met is $opt_critical.";
         }
         print "Age of file $opt_arguments is $nicely_formatted_fileage or $display_fileage ${perf_data_unit}(s).$triggered_range|$performance_data\n";
         exit $test_result;
         
      } else {
         print "UNKNOWN: Could not correct recognise the returned time format $lastmodified";
         exit $ERRORS{'UNKNOWN'};
      }
   } else {
      print "UNKNOWN: Could not find the file $opt_arguments";
      exit $ERRORS{'UNKNOWN'};
   }
   
}

}
#-------------------------------------------------------------------------
sub checkfilesize {
# replace any / in the $opt_arguments with \\ since \ are difficult to use in linux on the command line
# we replace it with \\ to pass an actual \ to the command line
# use # as the delimiter for the regex to make it more readable
my $internal_opt_arguments=$opt_arguments;
$internal_opt_arguments=~s#\/#\\\\#g;

# note that this query encloses the whole SELECT with '' and uses "" to enclose substrings
$wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host 'Select name,filesize from CIM_DataFile where name=\"$internal_opt_arguments\"'";
$output = `$wmi_commandline 2>&1`;
$debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";

#print "$wmi_commandline\n$output\n";

# expect output like this:
#OUTPUT: CLASS: CIM_DataFile
#FileSize|Name
#10240|c:\windows\write.exe
# sometimes we get
#CLASS: Win32_PageFile
#FileSize|Name
#1346371584|C:\pagefile.sys

if ($output eq  "") {
   print "CRITICAL: File $opt_arguments does not exist.\n";
   exit $ERRORS{'CRITICAL'};
}

if ($output=~/^CLASS: CIM_DataFile|Win32_PageFile/) {
   # looks like we have something back

   # use a regex to get the info
   if ($output=~/FileSize\|Name\n(.*?)\|(.*?)\n/s) {
      my $filesize=$1;
      my $filename=$2;
      my $display_filesize=scaled_bytes($filesize);

      my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$filesize);

      # performance data should always be in a fixed unit (we use bytes) for consistency
      my $performance_data="'$opt_arguments Bytes'=${filesize}Bytes;$warn_perf_spec;$critical_perf_spec; ";

      if ($filesize>0) {
         my $triggered_range='';
         if ($test_result==$ERRORS{'WARNING'}) {
            $triggered_range=" The range criteria not met is $opt_warn.";
         } elsif ($test_result==$ERRORS{'CRITICAL'}) {
            $triggered_range=" The range criteria not met is $opt_critical.";
         }
         print "File $opt_arguments is $display_filesize.$triggered_range|$performance_data\n";
         exit $test_result;
      } else {
         print "CRITICAL: File $opt_arguments is NOT found\n";
         exit $ERRORS{'CRITICAL'};
      }
      
   } else {
      print "UNKNOWN: $output";
      exit $ERRORS{'UNKNOWN'};
   }
      

} else {
   print "UNKNOWN: $output";
   exit $ERRORS{'UNKNOWN'};
}

}
#-------------------------------------------------------------------------
sub checkfoldersize {
# make sure the path ends with a / to make sure we only get matching folders
if ($opt_arguments!~/\/$/) {
   # no slash on the end so add it
   $opt_arguments="$opt_arguments/";
}

# we split up the query to drive letter and path since this should be faster than a linear search for all matching filenames
my $drive_letter='';
my $path='';
if ($opt_arguments=~/^(\w:)(.*)/) {
   $drive_letter=$1;
   $path=$2;
} else {
   print "Could not extract drive letter and path from $opt_arguments\n";
   exit $ERRORS{'UNKNOWN'};
}

my $wildcard='';
my $operator='=';
if ($opt_other_arguments eq 's') {
   # we want to get all sub dirs as well
   $wildcard='%';
   $operator='like';
}

# replace any / in the $opt_arguments with \\ since \ are difficult to use in linux on the command line
# we replace it with \\ to pass an actual \ to the command line
# use # as the delimiter for the regex to make it more readable
$path=~s#\/#\\\\#g;

# note that this query encloses the whole SELECT with '' and uses "" to enclose substrings
$wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host 'Select name,filesize from CIM_DataFile where drive=\"$drive_letter\" AND path $operator \"${path}$wildcard\"'";
$output = `$wmi_commandline 2>&1`;
$debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";

# print "$wmi_commandline\n$output\n";

# expect output like this:
#CLASS: CIM_DataFile                  - sometimes CLASS: Win32_PageFile
#FileSize|Name
#3578923|c:\temp\p1.jpg
#2773913|c:\temp\p12.jpg
#169622|c:\temp\ss00000.jpg

if ($output eq  "") {
   print "CRITICAL: File $opt_arguments does not exist.\n";
   exit $ERRORS{'CRITICAL'};
}

if ($output=~/^CLASS: CIM_DataFile|CLASS: Win32_PageFile/) {
   # looks like we have something back
   # we need to loop through all the files we found
   # locate the first regex at the start of the first file row
   $output=~/FileSize\|Name\n/sg;
   
   my $filesize=0;
   # loop through the files and add up all the sizes
   while ($output=~/(.*?)\|(.*?)\n/sg) {
      # print "Found:$1,$2\n";
      $filesize+=$1;
   }

   my $display_filesize=scaled_bytes($filesize);

   my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$filesize);

   # performance data should always be in a fixed unit (we use bytes) for consistency
   my $performance_data="'$opt_arguments Bytes'=${filesize}Bytes;$warn_perf_spec;$critical_perf_spec; ";

   if ($filesize>0) {
      my $triggered_range='';
      if ($test_result==$ERRORS{'WARNING'}) {
         $triggered_range=" The range criteria not met is $opt_warn.";
      } elsif ($test_result==$ERRORS{'CRITICAL'}) {
         $triggered_range=" The range criteria not met is $opt_critical.";
      }
      print "Folder $opt_arguments is $display_filesize.$triggered_range|$performance_data\n";
      exit $test_result;
   } else {
      print "CRITICAL: File $opt_arguments is NOT found\n";
      exit $ERRORS{'CRITICAL'};
   }
   
} else {
   print "UNKNOWN: $output";
   exit $ERRORS{'UNKNOWN'};
}

}
#-------------------------------------------------------------------------
sub checkwsusserver {
use DateTime;
my $age = DateTime->now(time_zone => 'local')->subtract(hours => 24);
$wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host \"Select SourceName,Message from Win32_NTLogEvent where Logfile='Application' and EventType < 2 and SourceName = 'Windows Server Update Services' and TimeGenerated > '" . $age->year . sprintf("%02d",$age->month) . sprintf("%02d",$age->day) . sprintf("%02d",$age->hour) . sprintf("%02d",$age->minute) . "00.00000000'\"";
$output = `$wmi_commandline 2>&1`;
$debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";
if ($output eq  "") {
   print "OK: WSUS Database clean.\n";
   exit $ERRORS{'OK'};
}
if ($output=~/CLASS: Win32_NTLogEvent/) {
   $output =~ s/\r(Application)\|/Application\|/g;
   $output =~ s/\r//g;
   $output =~ s/\n//g;
   $output =~ s/\|/-/g;
   $output =~ s/(Application)-/\n\nApplication-/g;
   $output = substr($output, 64);
   print "CRITICAL: WSUS Server has errors, check eventlog for download failures, database may need to be purged by running the Server Cleanup Wizard.\|;\n$output";
   exit $ERRORS{'CRITICAL'};
} else {
   print "UNKNOWN: $output";
   exit $ERRORS{'UNKNOWN'};
}
}
#-------------------------------------------------------------------------
sub checkprocess {
my @collected_data;
my $data_errors=get_multiple_wmi_samples(1,
   "select Name from Win32_Process WHERE Name LIKE \"$opt_arguments\"",
   'CLASS: Win32_Process\nHandle\|(Name)\n',
   '([0-9]+?)\|(.*?)\n',
   \@collected_data,
   \$opt_delay,
   
   );

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   # at this point we can assume that we have all the data we need stored in @collected_data
   # note that it might be empty if the query worked but returned nothing
   my $num_found=$collected_data[0][0]{'ROWSFOUND'}||0;

   my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$num_found);

   # performance data should always be in a fixed unit for consistency
   my $performance_data="'Process Count'=$num_found;$warn_perf_spec;$critical_perf_spec; ";

   # if we get through to here it means that opt_c and/or opt_w are specified and did not generate any errors
   if ($num_found>=0) {
      my $triggered_range='';
      if ($test_result==$ERRORS{'WARNING'}) {
         $triggered_range=" The range criteria not met is $opt_warn.";
      } elsif ($test_result==$ERRORS{'CRITICAL'}) {
         $triggered_range=" The range criteria not met is $opt_critical.";
      }
      print "Process $opt_arguments: Found $num_found instance(s) running.$triggered_range|$performance_data\n";
      exit $test_result;
   } else {
      print "CRITICAL: Process $opt_arguments is not running.\n";
      exit $ERRORS{'CRITICAL'};
   }
}
}
#-------------------------------------------------------------------------
sub checkservice {
# ------------------------ checking all services
my $where_bit='';
my $auto_mode='';
if (lc($opt_arguments) eq 'auto') {
   # for this query we need to look for all automatic services
   # check that all auto services are 
   # STARTED=True, STATE=Running and STATUS=OK
   # we do a query that actually always should return data so that we know that the query works
   # we could do a select just listing the bad ones, but it returns nothing if good. hard to tell if it really worked ok.
   $where_bit="where StartMode=\"auto\"";
   $auto_mode=1;
} else {
   # for this query we have been passed a regex and must look for that
   # so the WMI query should return all services and then we will apply the regex
   # this is the default
}

# wmic returns something like:
# CLASS: Win32_Service
# DisplayName|Name|Started|StartMode|State|Status
# Telnet|TlntSvr|False|Auto|Stopped|OK
# Security Center|wscsvc|True|Auto|Running|OK

my @collected_data;
my $data_errors=get_multiple_wmi_samples(1,
   "select displayname, Started, StartMode, State, Status FROM Win32_Service $where_bit",
   '(DisplayName)\|(Name)\|(Started)\|(StartMode)\|(State)\|(Status)\n',
   '(.+?)\|(.+?)\|(.+?)\|(.+?)\|(.+?)\|(.+?)\n',
   \@collected_data,
   \$opt_delay,
   
   );

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   # at this point we can assume that we have all the data we need stored in @collected_data
   my $result_text='';
   # now loop through the results, showing the ones requested
   my $num_ok=0;
   my $num_bad=0;
   # so we want to loop through all the rows in the first query result $collected_data[0]
   foreach my $row (@{$collected_data[0]}) {
      $debug && print Dumper($row);
      if (  $auto_mode || 
            ( !$auto_mode && ($$row{'DisplayName'}=~/$opt_arguments/i || $$row{'Name'}=~/$opt_arguments/i) ) 
         ) {
         if ($$row{'Started'} eq 'True' && $$row{'State'} eq 'Running' && $$row{'Status'} eq 'OK') {
            $num_ok++;
            if (!$auto_mode) {
               # if we have using the regex mode then list out the services we find
               $result_text.="$$row{'DisplayName'} ($$row{'Name'}) is $$row{'State'}, ";
            }
         } else {
            $num_bad++;
            $result_text.="$$row{'DisplayName'} ($$row{'Name'}) is $$row{'State'}, ";
         }
      }
   }
   
   $result_text=~s/, $/./;

   my $num_total=$num_ok+$num_bad;
   my $check_value=$num_bad;
   my $check_description='';
   if ($opt_other_arguments eq 'good') {
      $check_value=$num_ok;
   } elsif ($opt_other_arguments eq 'total') {
      $check_value=$num_total;
   }

   my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$check_value);

   # performance data should always be in a fixed unit for consistency
   my $performance_data="'Total Service Count'=${num_total}; 'Service Count OK State'=${num_ok}; 'Service Count Problem State'=${num_bad}; ";

   print "Found $num_total service(s). $num_ok OK and $num_bad with problems. $result_text|$performance_data\n";
   $debug && print "Checking Warn/Crit against $opt_other_arguments. Check $check_value against warn:$opt_warn and crit:$opt_critical\n";

   exit $test_result;
}

}
#-------------------------------------------------------------------------
sub checkuptime {
my @collected_data;
# expect ouput like
#CLASS: Win32_PerfFormattedData_PerfOS_System
#SystemUpTime
#33166
my $data_errors=get_multiple_wmi_samples(1,
   "Select SystemUpTime from Win32_PerfFormattedData_PerfOS_System",
   '(SystemUpTime)\n',
   '(.+?)\n',
   \@collected_data,
   \$opt_delay,
   
   );

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   my $uptime_min=int($collected_data[0][0]{'SystemUpTime'}/60);
   my $display=display_uptime($collected_data[0][0]{'SystemUpTime'});
   
   my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$uptime_min);

   # performance data should always be in a fixed unit for consistency
   my $performance_data="'Uptime Minutes'=${uptime_min}Minutes;$warn_perf_spec;$critical_perf_spec; ";
   
   print "System Uptime is $display.|$performance_data\n";
   exit $test_result;
}
}
#-------------------------------------------------------------------------
sub checkdrivesize {
# strip any % in the warning/critical specification
$opt_critical =~ s/\%//;
$opt_warn =~ s/\%//;

$wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host \"Select DeviceID,freespace,Size from Win32_LogicalDisk where DriveType=3\"";
$output = `$wmi_commandline 2>&1`;
$debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";

#CLASS: Win32_LogicalDisk
#DeviceID|FreeSpace|Size
#C:|9765203968|21467947008
#D:|9765203968|21467947008

my $results_text='';
my $result_code=$ERRORS{'UNKNOWN'};
my $performance_data='';
my $num_critical=0;
my $num_warning=0;

# firstly locate the regex at the start of the first drive data line
if ($output=~/Size\n/sg) {

   #print "$output\n";
   # now loop through the results, showing the ones requested
   while ($output=~/(.*?)\|(.*?)\|(.*?)\n/sg) {
      #print "FOUND:$1,$2,$3\n";
      my $driveletter=$1 || '';
      my $drivefree=$2 || '';
      my $drivesize=$3 || '';
      if (lc($opt_arguments) eq 'all' || $driveletter=~/$opt_arguments/i) {
         # include this drive in the results
         if ($drivesize>0) {
            # got valid data
            my $drivesize_GB=sprintf("%.2f", $drivesize/$actual_bytefactor/$actual_bytefactor/$actual_bytefactor);
            my $used_space=$drivesize-$drivefree;
            my $used_pc=sprintf("%.1f",$used_space/$drivesize*100);
            my $used_GB=sprintf("%.2f", $used_space/$actual_bytefactor/$actual_bytefactor/$actual_bytefactor);
            my $free_pc=sprintf("%.1f",$drivefree/$drivesize*100);
            my $free_GB=sprintf("%.2f", $drivefree/$actual_bytefactor/$actual_bytefactor/$actual_bytefactor);
            my $status_type='OK';
            
            my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$used_pc);
            
            # check for Critical/Warning
            if ($test_result==$ERRORS{'CRITICAL'}) {
               $status_type='CRITICAL';
               $num_critical++;
            } elsif ($test_result==$ERRORS{'WARNING'}) {
               $status_type='WARNING';
               $num_warning++;
            }
            $results_text.="$status_type - $driveletter Total:${drivesize_GB}GB Used:${used_GB}GB ($used_pc%) Free:${free_GB}GB ($free_pc%), ";
            $performance_data.="'${driveletter}Space'=${used_GB}GB;;;;$drivesize_GB '${driveletter}Utilisation'=${used_pc}%;$warn_perf_spec;$critical_perf_spec; ";
         } else {
            # this drive does not get included in the results size there is a problem with its data
         }
      }
   }
   
   if ($results_text) {
      # show the results
      # remove the last ", "
      $results_text=~s/, $//;
      print "$results_text|$performance_data\n";
      if ($num_critical>0) {
         exit $ERRORS{'CRITICAL'};
      } elsif ($num_warning>0) {
         exit $ERRORS{'WARNING'};
      } else {
         exit $ERRORS{'OK'};
      }
   } else {
      print "UNKNOWN: Could not find a drive matching '$opt_arguments' in $output";
      exit $ERRORS{'UNKNOWN'};
   }

} else {
   # could not find what we were looking for - some kind of error
   print "UNKNOWN: $output";
   exit $ERRORS{'UNKNOWN'};
}
}
#-------------------------------------------------------------------------
sub checkeventlog {
my %severity_level=(
   1  => "Error",
   2  => "Warning",
);   

my @arguments = split (/,/, $opt_arguments);
if (scalar @arguments != 3) {
   print "UNKNOWN: invalid number of arguments for the checkeventlog function.\n";
   short_usage();
}
use DateTime;
# the date and time are stored in GMT in the event log so we need to query it based on that
my $age = DateTime->now(time_zone => 'gmt')->subtract(hours => $arguments[2]);
$wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$opt_host \"Select SourceName,Message,TimeGenerated from Win32_NTLogEvent where Logfile='$arguments[0]' and EventType<=$arguments[1] and EventType>0 and SourceName <> 'Microsoft-Windows-PrintSpooler' and SourceName <> 'TermServDevices' and TimeGenerated > '" . $age->year . sprintf("%02d",$age->month) . sprintf("%02d",$age->day) . sprintf("%02d",$age->hour) . sprintf("%02d",$age->minute) . "00.00000000'\"";
$output = `$wmi_commandline 2>&1`;
$debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";

if ($output eq  "") {
   print "OK: No events recorded with severity level $arguments[1] (warning level = 2, error level = 1) in the last $arguments[2] hours in the $arguments[0] eventlog (excluding the TermServDevices and Microsoft-Windows-PrintSpooler sources).\n";
   exit $ERRORS{'OK'};
}

# this first regex checks for valid data and positions the regex at the start of the header line
if ($output=~/CLASS: Win32_NTLogEvent\n/sg) {
   
   # expecting output like
   #CLASS: Win32_NTLogEvent
   #Logfile|Message|RecordNumber|SourceName|TimeGenerated

   # loop through each line
   my $num_events=-1; # start at -1 since we have a header
   my $result_text='';
   while ($output=~/(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\n/sg) {
      my $logfile=$1;
      my $message=$2;
      my $recordnumber=$3;
      my $sourcename=$4;
      my $timegenerated=$5;
      my $this_message="$logfile:$timegenerated:$sourcename:$message";
      # remove any CR or LF
      $this_message=~s/\n|\r//g;
      $result_text.="$this_message\n";
      $num_events++;
   }

   my ($test_result,$warn_perf_spec,$critical_perf_spec)=test_limits($opt_warn,$opt_critical,$num_events);

   # performance data should always be in a fixed unit (we use bytes) for consistency
   my $performance_data="'Num Events'=${num_events};$warn_perf_spec;$critical_perf_spec;\n";

   print "$num_events event(s) of severity level '$severity_level{$arguments[1]}' were recorded in the last $arguments[2] hours in the $arguments[0] eventlog.|$performance_data\n$result_text";
   exit $test_result;
} else {
   print "UNKNOWN: $output";
   exit $ERRORS{'UNKNOWN'};
}
}
#-------------------------------------------------------------------------
sub apply_multiplier {
# multiply a value up using a mulitplier string value
# pass in
# a value
# a multiplier eg k, m, g etc - might be empty
my ($value,$multiplier)=@_;
if ($multiplier) {
   $debug && print "Value of $value ";
   if (defined($time_multipliers{$multiplier})) {
      # this is a time based multiplier
      # return the value in seconds 
      $value=$value * $time_multipliers{lc($multiplier)};
      $debug && print "multiplied up to $value using $multiplier * " . $time_multipliers{lc($multiplier)} . "\n";
   } else {
      # return the value in bytes
      $value=$value * $actual_bytefactor ** $multipliers{lc($multiplier)};
      $debug && print "multiplied up to $value using $multiplier ($actual_bytefactor ^ " . $multipliers{lc($multiplier)} . ")\n";
   }
}
return $value;
}
#-------------------------------------------------------------------------
sub test_single_boundary {
# test a value against a single boundary. The boundary should have already been parsed
# pass in
# less_than_boundary - set to < if test should be less than boundary
# equal - set to = if test should include an = boundary
# boundary value
# boundary multiplier character eg k, m, g etc
# the test value
# 
# return 1 if boundary exceeded or zero if not
# also return the actual mulitplied up $boundary_value
my ($less_than_boundary,$boundary_equal,$original_boundary_value,$boundary_multiplier,$test_value)=@_;

my $test_result=0;

my $boundary_value=apply_multiplier($original_boundary_value,$boundary_multiplier);

if ($less_than_boundary && $boundary_equal) {
   # TEST <=
   $debug && print "TEST1 $test_value <= $boundary_value\n";
   if ($test_value <= $boundary_value) {
      $test_result=1;
   }
} elsif ($less_than_boundary) {
   # TEST <
   $debug && print "TEST2 $test_value < $boundary_value\n";
   if ($test_value < $boundary_value) {
      $test_result=1;
   }
} elsif ($boundary_equal) {
   # TEST >=
   $debug && print "TEST3 $test_value >= $boundary_value\n";
   if ($test_value >= $boundary_value) {
      $test_result=1;
   }
} else {
   # TEST > 
   $debug && print "TEST4 $test_value > $boundary_value\n";
   if ($test_value > $boundary_value) {
      $test_result=1;
   }
}

$debug && print "Test of $less_than_boundary$boundary_equal$original_boundary_value$boundary_multiplier ($boundary_value) vs $test_value yields $test_result\n";
return $test_result,$boundary_value;
}
#-------------------------------------------------------------------------
sub parse_limits {
my ($spec,$test_value)=@_;
# we return zero if the value does not trigger the spec
$debug && print "Testing $test_value against SPEC: $spec\n";
my $test_result=0;

# we need a warning/critical value for performance data graphs
# for single values it is easy, its just the boundary value specified
# for ranges we use the max of the range - maybe this is not always right
my $perf_data_spec='';

if ($spec ne '') {
   my $at_specified='';
   my $min='';
   my $min_multiplier='';
   my $max='';
   my $max_multiplier='';

   my $format_type=0;

   if ($spec=~/(\@*)([0-9+\-\.\~]*)($multiplier_regex*):([0-9+\-\.\~]*)($multiplier_regex*)/i) {
      $at_specified=$1;
      $min=$2;
      $min_multiplier=$3;
      $max=$4;
      $max_multiplier=$5;
      $format_type=1;
      $debug && print "SPEC=$1,$2,$3,$4,$5\n";
   } elsif ($spec=~/(\@*)([0-9+\-\.\~]+)($multiplier_regex*)/i) {
      $at_specified=$1;
      $min=0;
      $min_multiplier='';
      $max=$2;
      $max_multiplier=$3;
      $format_type=2;
      $debug && print "SPEC=$1,$2,$3\n";
   } else {
      $debug && print "SPEC format for $spec, not recognised\n";
   }

   if ($format_type) {
      $debug && print "Range Spec=$at_specified,$min,$min_multiplier,:,$max,$max_multiplier\n";
      # there should always be a max value and may not be a min value
      my $lower_bound_value='';
      my $upper_bound_value='';
      my $lower_bound_check='';
      my $upper_bound_check='';

      # there is a possibility that the boundary is specified as ~
      # this means negative infinity

      # we have a range comparison and we check both bounds using < and >
      if ($min eq '~') {
         # since min is negative infinity then no point in doing this lower bound test as it will be always false
         $lower_bound_check=0;
         $lower_bound_value='~';
      } else {
         ($lower_bound_check,$lower_bound_value)=test_single_boundary('<','',$min,$min_multiplier,$test_value);
      }
      
      if ($max eq '') {
         # since max is inifinity no point in checking since result will always be false
         $upper_bound_check=0;
         $upper_bound_value='';
      } else {
         ($upper_bound_check,$upper_bound_value)=test_single_boundary('','',$max,$max_multiplier,$test_value);
      }
      # generate alert if either of these are triggered
      if ($lower_bound_check || $upper_bound_check) {
         $test_result=1;
      }

      if ($at_specified) {
         # this just reverses the results
         if ($test_result==1) {
            $test_result=0;
         } else {
            $test_result=1;
         }
         $debug && print "@ specified so reverse the result\n";
      }

      # rewrite the specification taking into account any multipliers
      if ($format_type==1) {
         if ($opt_z) {
            #  provide full spec performance warn/crit data
            $perf_data_spec="$at_specified$lower_bound_value:$upper_bound_value";
         } else {
            # provide partial spec performance warn/crit data
            # if only one number has been specified in the range spec then use that
            # otherwise use the upper bound value
            $perf_data_spec="$upper_bound_value";
            if ($upper_bound_value=~/[0-9+\-\.]+/ && $lower_bound_value=~/[0-9+\-\.]+/) {
               # stick with only upper bound data
            } elsif ($lower_bound_value=~/[0-9+\-\.]+/) {
               # no upper bound specified so use the lower bound
               $perf_data_spec="$lower_bound_value";
            }
         }
      } else {
         # for this format type the min was forced to zero, but it was not actually specified - so we only show an upper bound 
         if ($opt_z) {
            #  provide full spec performance warn/crit data
            $perf_data_spec="$at_specified$upper_bound_value";
         } else {
            # provide partial spec performance warn/crit data
            $perf_data_spec="$upper_bound_value";
         }
      }

   } else {
      # seems to be some invalid spec format
      $test_result=100;
   }
}

$debug && print "Test Result = $test_result\n";
return $test_result,$perf_data_spec;
}
#-------------------------------------------------------------------------
sub list_collected_values_from_all_rows {
# this is specifically designed for when you have an array that looks like
# ie multiple rows per query results
#$VAR1 = [
#          [
#            {
#              'Name' => 1,
#            }
#            {
#              'Name' => 2,
#            }
#          ],
#          [
#            {
#              'Name' => 3,
#            }
#            {
#              'Name' => 4,
#            }
#          ],
#        ];
# This sub will return something like "1,2,3,4"
# luckily we have an array like this hanging around - it is the array format returned by
# get_multiple_wmi_samples
my ($values_array,$which_value,$list_delimiter)=@_;
my $string='';
foreach my $result (@{$values_array}) {
   # $result is an array reference to each result
   foreach my $row (@{$result}) {
      # $row is a hash reference to each row for this result
      $string.="$$row{$which_value}$list_delimiter";
   }
}
# remove the last $list_delimiter
$string=~s/$list_delimiter$//;
return $string;
}
#-------------------------------------------------------------------------
sub test_limits {
my ($warn_spec,$critical_spec,$test_value)=@_;
$debug && print "Testing $test_value against WARN: $warn_spec and CRIT: $critical_spec\n";

my $test_result=$ERRORS{'UNKNOWN'};

$debug && print "----- Critical Check -----\n";
my ($critical_result,$critical_perf)=parse_limits($critical_spec,$test_value);
$debug && print "----- Warning Check -----\n";
my ($warn_result,$warn_perf)=parse_limits($warn_spec,$test_value);
$debug && print "-------------------------\n";

if ($critical_result>1) {
   print "Critical specification not defined correctly\n";
} elsif ($warn_result>1) {
   print "Warning specification not defined correctly\n";
} elsif ($critical_result==1) {
   $test_result=$ERRORS{'CRITICAL'};
} elsif ($warn_result==1) {
   $test_result=$ERRORS{'WARNING'};
} else {
   $test_result=$ERRORS{'OK'};
}

return $test_result,$warn_perf,$critical_perf;
}
#-------------------------------------------------------------------------
sub max {
# passed in a list of numbers
# determaxe the maximum one 
my($max_so_far) = shift @_;  # the first one is the smallest yet seen
foreach (@_) {               # look at the remaining arguments
  if ($_ > $max_so_far) {    # could this one be smaller
    $max_so_far = $_;
  }
}
return $max_so_far;
}
#-------------------------------------------------------------------------

