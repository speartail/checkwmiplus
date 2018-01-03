#!/usr/bin/perl -w
#
# check_wmi_plus.pl - nagios plugin for agentless checking of Windows
#
# Copyright (C) 2011 Matthew Jurgens
# You can email me using: mjurgens (the at goes here) edcint.co.nz
# Download link can be found at http://www.edcint.co.nz
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

#==============================================================================
#================================= DECLARATIONS ===============================
#==============================================================================

my $VERSION="1.41";

use strict;
use Getopt::Long;
use vars qw($PROGNAME);
use lib "/usr/lib/nagios/plugins"; # CHANGE THIS IF NEEDED
use utils qw ($TIMEOUT %ERRORS &print_revision &support);
use Data::Dumper;

# command line option declarations
my $opt_Version='';
my $opt_help='';
my $opt_mode='';
my $opt_submode='';
my $opt_username='';
my $opt_password='';
my $opt_warn=(); # this becomes an array reference
my $opt_critical=(); # this becomes an array reference
my $debug=0; # default value
my $opt_value='';
my $opt_z='';
my $opt_inihelp='';

# they all start with _ since later they are copied into the data array/hash and this reduces the chance they clash
# then we have consistent usage throughout
my %the_original_arguments=(); # used to store the original user specified command line arguments  - sometimes we change the arguments
my %the_arguments = (
   _arg1  => '',
   _arg2  => '',
   _arg3  => '',
   _arg4  => '',
   _arg5  => '',
   _bytefactor  => '',
   _delay       => '',
   _host        => '',
   _nodata      => '',
   _nodataexit  => '',
   _timeout     => '',
);

my ($wmi_commandline, $output);

# arrays/hashes where we will store information about warn/critical specs/checks
my %warn_perf_specs_parsed;      # list of parsed warn specs - a hash
my %critical_perf_specs_parsed;  # list of parsed critical specs - a hash
my @warn_spec_result_list;        # list of warn spec results
my @critical_spec_result_list;    # list of critical spec results

#==============================================================================
#=================================== CONFIG ===================================
#==============================================================================

$PROGNAME="check_wmi_plus";

my $default_bytefactor=1024;
my $effective_delay='';

# I have everything installed in /opt/nagios/bin/plugins
# You may want to change this to suit you

my $wmic_command='/opt/nagios/bin/plugins/wmic'; # CHANGE THIS IF NEEDED

# set the location of the ini file. Set to '' if not using it or specify using the -i parameter
my $wmi_ini_file='/opt/nagios/bin/plugins/check_wmi_plus.ini'; # CHANGE THIS IF NEEDED,


########################################################################
########################################################################
# When %valid_test_fields is fully developed it can replace %mode_list?
########################################################################
########################################################################

# list all valid modes with dedicated subroutines here
# all the modes that can take a critical/warning specification set to value of 1
my %mode_list = ( 
   checkcpu       => 1,
   checkcpuq      => 1,
   checkdrivesize => 1,
   checkeventlog  => 1,
   checkfileage   => 1,
   checkfilesize  => 1,
   checkfoldersize=> 1,
   checkgeneric   => 1,
   checkmem       => 1,
   checknetwork   => 1,
   checkprocess   => 1,
   checkservice   => 1,
   checkuptime    => 1,
   checkwsusserver=> 0,
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

# this hash contains lists of the fields that can be used in the warning/critical specs for specific modes
my %valid_test_fields = (
   # key name is the name of the mode
   # value is an array of fields names to check against
   # the first one in the list is the default if none is specified in a warn/crit specification
   # you should always specify at least one per mode that uses warning/critical checking so that it knows what to check against
   checkcpu          => [ qw(_AvgCPU) ],
   checkcpuq         => [ qw(_AvgCPUQLen) ],
   checkdrivesize    => [ qw(_Used% _UsedGB _Free% _FreeGB) ],
   checkeventlog     => [ qw(_ItemCount) ],
   checkfileage      => [ qw(_FileAge) ],
   checkfilesize     => [ qw(FileSize _ItemCount) ],
   checkfoldersize   => [ qw(_FolderSize _ItemCount) ],
   checkgeneric      => [ qw(FileControlBytesPersec FileControlOperationsPersec FileDataOperationsPersec FileReadBytesPersec FileReadOperationsPersec FileWriteBytesPersec FileWriteOperationsPersec) ],
   checkmem          => [ qw(_MemUsed% _MemFree% _MemUsed _MemFree _MemTotal) ],
   checknetwork      => [ qw(CurrentBandwidth PacketsSentPersec PacketsReceivedPersec OutputQueueLength PacketsReceivedErrors BytesSentPersec BytesReceivedPersec PacketsSentPersec) ],
   checkprocess      => [ qw(_ItemCount) ],
   checkservice      => [ qw(_NumBad _NumGood _Total) ],
   checkuptime       => [ qw(SystemUpTime) ],

);

# this hash contains lists of the fields that are displayed for specific modes
my %display_fields = (
   # key name is the name of the mode
   # value is an array of fields names to display
   # the value can be in 2 formats - 
   # 1) FIELD (where we just display this field like FIELD=xx,
   # 2) FIELD|UNITS (where we just display this field like FIELD=xxUNITS,
   # 3) FIELD|UNITS|DISPLAY|SEP|DELIM|START|END
   # where we display this FIELD like STARTDISPLAYSEPxxUNITSENDDELIM
   # the default DELIM is comma space, if DELIM is set to ~ then none will be used
   # the default SEP is =, if SEP is set to ~ then none will be used
   # DISPLAY normally shows FIELD or whatever you specify as DISPLAY. Set DISPLAY to ~ to show nothing.
   # if units is prefixed with # then we use a function to convert it to a scaled based figure using prefixes like K, M, G etc - the calculation is influenced by the BYTEFACTOR setting
   # In DISPLAY/START/END anything enclosed in {} will be substituted by the value of that item of that name eg {DeviceID} will replace by the value contained in DeviceID eg C:
   # eg BytesSentPersec will be shown as BytesSentPersec=XX, 
   # eg BytesSentPersec|BYTES will be shown as BytesSentPersec=XXBytes, 
   # eg _Used%|%|.|.||(|) will be shown as (45.2%)
   # I was going to use qw() but it makes it way harder to read. You could still use it for the most basic format
   checkcpu          => [ '_DisplayMsg||~|~| - ||', '_AvgCPU|%|Average CPU Utilisation| |~||', '_delay| sec|~|~|~| (Over approx | period)' ],
   checkcpuq         => [ '_DisplayMsg||~|~| - ||', '_AvgCPUQLen||Average CPU Queue Length| | ||', '_arg1| points|~|~|~|(| with', '_delay| sec delay|~| | ||', '_CPUQPoints||~|~|~|gives values: |)' ],
   checkdrivesize    => [ '_DisplayMsg||~|~| - ||', 'DiskDisplayName||~|~| ||', '_DriveSizeGB|GB|Total||||', '_UsedGB|GB|Used|| ||', '_Used%|%|~|~||(|)', '_FreeGB|GB|Free|| ||', '_Free%|%|~|~||(|)' ],
   checkeventlog     => [ '_DisplayMsg||~|~| - ||', '_ItemCount| event(s)|~|~| ||', '_SeverityType||~|~||of Severity Level "|"', '_arg3| hours|~|~|~|were recorded in the last |', '_arg1||~|~|~| from the | Event Log (excluding the TermServDevices and Microsoft-Windows-PrintSpooler sources).', "_EventList||~|~|~||" ],
   checkfileage      => [ '_DisplayMsg||~|~| - ||', '_arg1||Age of File| |~|| is ', '_NicelyFormattedFileAge||~|~|~|| or ', '_DisplayFileAge||~|~|~||', '_PerfDataUnit||~|~|||(s).' ], 
   checkfilesize     => [ '_DisplayMsg||~|~| - ||', '_arg1||File| |~|| is ', 'FileSize|#B|~|~|. ||', '_ItemCount| instance(s)|Found| |.||' ], 
   checkfoldersize   => [ '_DisplayMsg||~|~| - ||', '_arg1||Folder| |~|| is ', '_FolderSize|#B|~|~|. ||', '_ItemCount| files(s)|Found| |.||', '_FileList||~|~|~||' ], 
   checkgeneric      => [ '_DisplayMsg||~|~| - ||', 'FileControlBytesPersec', 'FileControlOperationsPersec', 'FileDataOperationsPersec', 'FileReadBytesPersec', 'FileReadOperationsPersec', 'FileWriteBytesPersec', 'FileWriteOperationsPersec' ], 
   checkmem          => [ '_DisplayMsg||~|~| - ||', 'MemType||~|~|~||: ', '_MemTotal|#B|Total|: | - ||', '_MemUsed|#B|Used|: | ||', '_MemUsed%|%|~|~| - |(|)', '_MemFree|#B|Free|: | ||', '_MemFree%|%|~|~||(|)' ], 
   checknetwork      => [ '_DisplayMsg||~|~| - ||', 'Name||Interface: |~| ||', 'CurrentBandwidth|#bit/s|Speed:|~| |(|)', 'BytesSentPersec|#B/sec|Byte Send Rate||||', 'BytesReceivedPersec|#B/sec|Byte Receive Rate||||', 'PacketsSentPersec||Packet Send Rate||||', 'PacketsReceivedPersec||Packet Receive Rate||||', 'OutputQueueLength||Output Queue Length||||', 'PacketsReceivedErrors||Packets Received Errors||||' ],
   checkprocess      => [ '_DisplayMsg||~|~| - ||', '_ItemCount| Instance(s)|Found |~|~|| of "{_arg1}" running.', 'ProcessList||~|~|~||' ],
   checkservice      => [ '_DisplayMsg||~|~| - ||', '_Total| Services(s)|Found |~|||', '_NumGood| OK|~|~| and ||', '_NumBad| with problems. |~|~|~||', '_ServiceList||~|~|~||' ],
   checkuptime       => [ '_DisplayMsg||~|~| - ||', '_DisplayTime||System Uptime is |~|.||' ],

);

# this hash contains lists of the fields that are used as performance data for specific modes
my %performance_data_fields = (
   # key name is the name of the mode
   # value is an array of fields names to display
   # the value can be in 2 formats - 
   # 1) FIELD
   # 2) FIELD|UNITS
   # 3) FIELD|UNITS|DISPLAY
   # In DISPLAY/UNITS anything enclosed in {} will be substituted by the value of that item of that name eg {DeviceID} will replace by the value contained in DeviceID eg C:
   checkcpu          => [ '_AvgCPU|%|Avg CPU Utilisation' ],
   checkcpuq         => [ '_AvgCPUQLen||Avg CPU Queue Length' ],
   checkdrivesize    => [ '_UsedGB|GB|{DiskDisplayName} Space', '_Used%|%|{DiskDisplayName} Utilisation' ],
   checkeventlog     => [ '_ItemCount||Event Count' ],
   checkfileage      => [ '_DisplayFileAge|{_PerfDataUnit}|{_arg1} Age' ],
   checkfilesize     => [ 'FileSize|bytes|{_arg1} Size', '_ItemCount||File Count' ],
   checkfoldersize   => [ '_FolderSize|bytes|{_arg1} Size', '_ItemCount||File Count' ],
   checkgeneric      => [ 'FileControlBytesPersec', 'FileControlOperationsPersec', 'FileDataOperationsPersec', 'FileReadBytesPersec', 'FileReadOperationsPersec', 'FileWriteBytesPersec', 'FileWriteOperationsPersec' ],
   checkmem          => [ '_MemUsed|Bytes|{MemType} Used', '_MemUsed%|%|{MemType} Utilisation' ], 
   checknetwork      => [ 'BytesSentPersec', 'BytesReceivedPersec', 'PacketsSentPersec', 'PacketsReceivedPersec', 'OutputQueueLength', 'PacketsReceivedErrors' ],
   checkprocess      => [ '_ItemCount||Process Count' ],
   checkservice      => [ '_Total||Total Service Count', '_NumGood||Service Count OK State', '_NumBad||Service Count Problem State' ],
   checkuptime       => [ '_UptimeMin|min|Uptime Minutes' ],

);


#==============================================================================
#================================== PARAMETERS ================================
#==============================================================================


Getopt::Long::Configure('no_ignore_case');
GetOptions(
   "Version"            => \$opt_Version,
   "help"               => \$opt_help,
   "mode=s"             => \$opt_mode,
   "submode=s"          => \$opt_submode,
   "Hostname=s"         => \$the_arguments{'_host'},
   "username=s"         => \$opt_username,
   "password=s"         => \$opt_password,
   "arguments=s"        => \$the_arguments{'_arg1'},
   "otheraguments=s"    => \$the_arguments{'_arg2'},
   "3arg=s"             => \$the_arguments{'_arg3'},
   "4arg=s"             => \$the_arguments{'_arg4'},
   "warning=s@"         => \$opt_warn,
   "critical=s@"        => \$opt_critical,
   "timeout=i"          => \$the_arguments{'_timeout'},
   "bytefactor=s"       => \$the_arguments{'_bytefactor'},
   "debug"              => \$debug,
   "nodata"             => \$the_arguments{'_nodata'},
   "xnodataexit=s"      => \$the_arguments{'_nodataexit'},
   "value=s"            => \$opt_value,
   "ydelay=s"           => \$the_arguments{'_delay'},
   "z"                  => \$opt_z,
   "inifile=s"          => \$wmi_ini_file,
   "inihelp"            => \$opt_inihelp,
   );

# check up on the ini file
if ($wmi_ini_file && ! -f $wmi_ini_file) {
   print "This plugin requires an INI file.\nConfigure its location by setting the \$wmi_ini_file variable in this plugin or by using the -i parameter to override the default setting.";
   exit $ERRORS{"UNKNOWN"};
} else {
   # now that we are using an ini file we need this module 
   use Config::IniFiles;
}

if ($the_arguments{'_timeout'}) {
   $TIMEOUT=$the_arguments{'_timeout'};
}
# Setup the trap for a timeout
$SIG{'ALRM'} = sub {
   print "UNKNOWN - Plugin Timed out ($TIMEOUT sec)\n";
   exit $ERRORS{"UNKNOWN"};
};
alarm($TIMEOUT);
 
if ($the_arguments{'_bytefactor'}) {
   if ($the_arguments{'_bytefactor'} ne '1024' && $the_arguments{'_bytefactor'} ne '1000') {
      print "The BYTEFACTOR option must be 1024 or 1000. '$the_arguments{'_bytefactor'}' is not valid.\n";
      short_usage();
   }
}
my $actual_bytefactor=$the_arguments{'_bytefactor'} || $default_bytefactor;

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

if (! $the_arguments{'_host'}) {
   print "No Hostname specified\n\n";
   short_usage();
}

# take a copy of the original arguments
%the_original_arguments=%the_arguments;

#==============================================================================
#===================================== MAIN ===================================
#==============================================================================

if (! -x $wmic_command) {
   print "This plugin requires the linux implementation of wmic eg from zenoss.\nOnce wmic is installed, configure its location by setting the \$wmic_command variable in this plugin.";
   exit $ERRORS{"UNKNOWN"};
}

# now run the appropriate sub for the check
if (defined($mode_list{$opt_mode})) {
   # have to set a reference to the subroutine since strict ref is set
   my $subref=\&$opt_mode;
   &$subref('');
} else {
   if ($wmi_ini_file) {
      my $ini_section='';
      my $wmi_ini;
      # maybe the mode is defined in the ini file
      # read the ini file and check
      $wmi_ini = new Config::IniFiles( -file => "$wmi_ini_file", -allowcontinue => 1 );

      # there are 2 ways a section in the ini file is matched
      # 1) [MODE] - $opt_mode matches the whole section name
      # 2) [MODE SUBMODE] = $opt_mode is a Config::IniFiles Group and $opt_submode is a MemberName
      # first see if there is a section named $opt_mode 

      if ($wmi_ini->SectionExists($opt_mode)) {
         $debug && print "Found Section $opt_mode\n";
         $ini_section=$opt_mode;
      } else {
         # now check for a group and a member
         # load the ini file groups into an array - a group is a mode
         my @ini_modes=$wmi_ini->Groups();
          # see if we have found the mode
         $debug && print "INI FILE MODES " . Dumper(\@ini_modes);
         my @found_modes=grep(/^$opt_mode$/,@ini_modes);
         if ($#found_modes==0) {
            $debug && print "Found Group $opt_mode\n";
            # now use $opt_submode to match a membername
            my @group_members=$wmi_ini->GroupMembers($opt_mode);
            $debug && print "GROUP MEMBERS " . Dumper(\@group_members);
            my @found_members=grep(/^$opt_mode +$opt_submode$/,@group_members); # could be any number of spaces between group and member
            if ($#found_members==0) {
               $debug && print "Found Member $opt_submode\n";
               $ini_section=$found_members[0];
            }
            
         }
      }
      
      if ($ini_section) {
         checkini($wmi_ini,$ini_section);
      } elsif ($opt_inihelp) {
         # here we need to list out the modes available in the ini file
         my @ini_modes=$wmi_ini->Sections();
         print "The ini file provides the following Modes and/or Submodes - \n";
         print join("\n",@ini_modes) . "\n";
         print "Add a valid Mode and/or Submode to this command line to get detailed help for that Mode.\n";
         exit;
      } else {
         print "A valid MODE and/or SUBMODE must be specified\n";
         short_usage();
      }



   }

   print "A valid MODE and/or SUBMODE must be specified\n";
   short_usage();
}

# if we get to here we default to an OK exit
exit $ERRORS{'OK'};

#==============================================================================
#================================== FUNCTIONS =================================
#==============================================================================

#-------------------------------------------------------------------------
sub short_usage {
my ($no_exit)=@_;
print <<EOT;
Usage: -H HOSTNAME -u DOMAIN/USER -p PASSWORD -m MODE [-s SUBMODE] [-b BYTEFACTOR] [-w WARN] [-c CRIT] [-a ARG1 ] [-o ARG2] [-3 ARG3] [-4 ARG4] [-t TIMEOUT] [-y DELAY] [-x NODATAEXIT] [-n] [-d] [-z] [--inifile INI]  [--inihelp] 
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

# list out the valid fields for each mode for warn/crit specifications
my %field_lists;
foreach my $mode (keys %valid_test_fields) {
   $field_lists{$mode}=join(', ',@{$valid_test_fields{$mode}});
   $field_lists{$mode}=~s/, $/./; # remove the last comma space
   # I can't work out one nice regex to do this next bit, so its 2
   # One for when there is only 1 field defined and
   # One for when there is more than 1 field defined
   # The array @{$valid_test_fields{$mode}} contains the list
   if ($#{$valid_test_fields{$mode}}>0) {
      # use the multi field regex
      $field_lists{$mode}=~s/([\w%]+)(,)*/Valid Warning\/Critical Fields are: $1 (Default)$2/; # stick (default) after the first one in the list
   } else {
      # single field only
      $field_lists{$mode}="The only valid Warning\/Critical Field is $field_lists{$mode}, so you don't even need to specify it!";
   }
    
  
}

short_usage(1);
my $ini_info='';
if ($wmi_ini_file) {
   $ini_info="\nUse --inihelp on its own to list the valid modes contained within the ini file.\n"
}

print <<EOT;

where 
BYTEFACTOR is either 1000 or 1024 and is used for conversion units eg bytes to GB. Default is 1024.
TIMEOUT is in seconds
INI is the full path of an ini file to use
-d Enable debug. Use this to see a lot more of what is going on included the exact WMI Query and results.
-z Provide full specification warning and critical values for performance data. 
   Not all performance data processing software can handle this eg PNP4Nagios
-n Controls how the plugin responds when no data is returned by the WMI query. Normally, the plugin returns an Unknown error.
   If you specify this option then you can use WARN/CRIT checking on the _ItemCount field. This is only useful for some
   check eg checkfilesize where you might get no data back from the WMI query.
NODATAEXIT is the plugin result if the WMI Query returns no data. Ignored if -n is set.
      Valid values are 0 for OK, 1 for Warning, 2 for Critical (Default) or 3 for Unknown.
      Only used for some checks. All checks from the ini file can use this.


$ini_info
MODE=checkcpu
-------------
   Some CPU checks just take whatever WMI or SNMP gives them from the precalculated values. We don't. We calculate
   our own utilisation value over a given timeperiod. This is much more accurate.

   DELAY: (optional) specifies the number of seconds over which the CPU utilisation is calculated. Default 5.
      The longer you can make this without timing out, the more accurate it will be. if specifying longer values
      you may also need to use the -t parameter to set a longer script timeout.
   WARN/CRIT can be used as described below.
   $field_lists{'checkcpu'}.

MODE=checkcpuq
-------------
   The WMI implementation of CPU Queue length is a point value.
   We try and improve this slightly by performing several checks and averaging the values.
   ARG1: (optional) specifies how many point checks are performed. Default 3.
   DELAY: (optional) specifies the number of seconds between point checks. Default 1. It can be 0 but in reality there will always 
      be some delay between checks as it takes time to perform the actual WMI query 
   WARN/CRIT can be used as described below.
      $field_lists{'checkcpuq'}.
   
   Note: Microsoft says "A sustained processor queue of greater than two threads generally indicates
   processor congestion.". However, we recommended testing your warning/critical levels to determine the
   optimal value for you.
   
MODE=checkdrivesize
-------------------
   ARG1: drive letter or volume name of the disk to check. If omitted or set to . all drives will be included.
      To include multiple drives separate them with a |. This uses a regular expression so take care to
      specify exactly what you want. eg "C" or "C:" or "C|E" or "." or "Data"
   ARG2: Set this to 1 to use volumes names (if they are defined) in plugin output and performance data ie -o 1
   ARG3: Set this to 1 to include information about the sum of all disk space on the entire system.
      If you set this you can also check warn/crit against the overall disk space.
      To show only the overall disk, set ARG3 to 1 and set ARG2 to 1 (actually to any non-existant disk)
   WARN/CRIT can be used as described below.
      $field_lists{'checkdrivesize'}.

MODE=checkeventlog
------------------
   ARG1: Name of the log eg "System" or "Application"
   ARG2: Severity, 2 = warning 1 = error
   ARG3: Number of past hours to check for events
      for example to report all errors that got logged in the past 24 hours in the System event log use: 
      -a System -o 1 -3 24
      It ignores errors from Terminal Server printers, as they occur at every RDP connection from an admin.
   WARN/CRIT can be used as described below.
      $field_lists{'checkeventlog'}.

MODE=checkfileage
----------------
   ARG1: full path to the file. Use '/' (forward slash) instead of '\\' (backslash).
   ARG2: set this to one of the time multipliers ($time_multiplier_list)
      This becomes the display unit and the unit used in the performance data. Default is hr.
      -z can not be used for this mode.
   WARN/CRIT can be used as described below.
      $field_lists{'checkfileage'}
      The warning/critical values should be specified in seconds. However you can use the time multipliers
      ($time_multiplier_list) to make it easier to use 
      eg instead of putting -w 3600 you can use -w 1hr
      eg instead of putting -w 5400 you can use -w 1.5hr
      Typically you would specify something like -w 24: -c 48:

MODE=checkfilesize
------------------
   ARG1: full path to the file. Use '/' (forward slash) instead of '\\' (backslash).
      eg "C:/pagefile.sys" or "C:/windows/winhlp32.exe"
   NODATAEXIT can be set for this check.
   WARN/CRIT can be used as described below.
   If you specify -n then you can use WARN/CRIT checking on the _ItemCount. _ItemCount should only ever be 0 or 1.
      This allows you to control how the plugin responds to non-existant files.
      $field_lists{'checkfilesize'}.

MODE=checkfoldersize
--------------------
   WARNING - This check can be slow and may timeout, especially if including subdirectories. 
      It can overload the Windows machine you are checking. Use with caution.
   ARG1: full path to the folder. Use '/' (forward slash) instead of '\\' (backslash). eg "C:/Windows"
   ARG4: Set this to s to include files from subdirectories eg -x s
   NODATAEXIT can be set for this check.
   WARN/CRIT can be used as described below.
   If you specify -n then you can use WARN/CRIT checking on the _ItemCount. _ItemCount should only ever be 0 or 1.
      This allows you to control how the plugin responds to non-existant files.
      $field_lists{'checkfoldersize'}.

MODE=checkmem
-------------
   SUBMODE: "physical" for physical memory "page" for pagefile
   WARN/CRIT can be used as described below.
      $field_lists{'checkmem'}.

MODE=checknetwork
-------------
   Shows various network parameters. Note that the BYTEFACTOR is set to 1000 by default for this mode.
   ARG1: (Recommended) Specify with network adapter the stats are collected for.
      The name of the network adaptors as seen from WMI are similar to what is seen in the output of the 
      ipconfig/all command on Windows. However, its not exactly the same. Run without -a to list the adapter
      names according to WMI. Typically you need to use '' around the adapter name when specifying.
      eg -a 'Intel[R] PRO_1000 T Server Adapter _2 - Packet Scheduler Miniport'
   WARN/CRIT can be used as described below.
      $field_lists{'checknetwork'}
   BYTEFACTOR defaults to 1000 for this mode. You can override this if you wish.
   
MODE=checkprocess
-----------------
   SUBMODE: Set this to Name or Commandline to determine if ARG1 matches against just the process name (Default) or 
      the commplete Command line used to run the process.
   ARG1: A regular expression to match against the process name or complete command line. Use . alone to count all processes.
         Typically the process command line is made up of DRIVE:PATH\\PROCESSNAME PARAMETERS
         Use '/' (forward slash) instead of '\\' (backslash). eg "C:/Windows" or "C:/windows/system32"
         Note: Any '/' in your regular expression will get converted to '\\\\'.
   ARG2: Set this to 'Name' (Default) or 'Commandline' to display the process names or the whole command line.
   WARN/CRIT can be used as described below.
      $field_lists{'checkprocess'}
   
MODE=checkservice
-----------------
   ARG1: the short or long service name that can be seen in the properties of the service in Windows
      Regular expressions can be used. Use Auto to check that all automatically started services are OK.
   WARN/CRIT can be used as described below.
      $field_lists{'checkservice'}

MODE=checkuptime
----------------
   WARN/CRIT can be used as described below.
      $field_lists{'checkuptime'}
      The warning/critical values should be specified in seconds. However you can use the time multipliers
      ($time_multiplier_list) to make it easier to use 
      eg instead of putting -w 1800 you can use -w 30min
      eg instead of putting -w 5400 you can use -w 1.5hr
      Typically you would specify something like -w 10min: -c 20min:

MODE=checkwsusserver
--------------------
   If there are any WSUS related errors in the event log in the last 24 hours a CRITICAL state is returned.

WARNING and CRITICAL Specification:
===================================

If warning or critical specifications are not provided then no checking is done and the check simply returns the value and any related performance data. If they are specified then they should be formatted as shown below.

A range is defined as a start and end point (inclusive) on a numeric scale (possibly negative or positive infinity). The theory is that the plugin will do some sort of check which returns back a numerical value, or metric, which is then compared to the warning and critical thresholds. 

Multiple warning or critical specifications can be specified. This allows for quite complex range checking and/or checking against multiple FIELDS (see below) at one time. The warning/critical is triggered if ANY of the warning/critical specifications are triggered.

This is the generalised format for ranges:
FIELD=[@]start:end

Notes:
   1. FIELD describes which value the specification is compared against. It is optional (the default is dependent on the MODE).
   2. start <= end
   3. start and ":" is not required if start=0
   4. if range is of format "start:" and end is not specified, assume end is infinity
   5. to specify negative infinity, use "~"
   6. alert is raised if metric is outside start and end range (inclusive of endpoints)
   7. if range starts with "@", then alert if inside this range (inclusive of endpoints)
   8. The start and end values can use multipliers from the following list: $multiplier_list
      eg 1G for 1 x 10^9 or 2.5k for 2500

FIELDs that start with _ eg _Used% are calculated or derived values
FIELDs that are all lower case are command line arguments eg _arg1
Other FIELDs eg PacketsSentPersec are what is returned from the WMI Query

Example ranges:

WARN/CRIT definition    Generate an alert if x...
10                      < 0 or > 10, (outside the range of {0 .. 10})
10:                     < 10, (outside {10 .. 8})
~:10                    > 10, (outside the range of {-infinity .. 10})
10:20                   < 10 or > 20, (outside the range of {10 .. 20})
\@10:20                  = 10 and = 20, (inside the range of {10 .. 20})
10                      < 0 or > 10, (outside the range of {0 .. 10})
10G                     < 0 or > 10G, (outside the range of {0 .. 10G})

FIELD examples - for MODE=checkdrivesize:
_UsedGB=10G             Check if the _UsedGB field is < 0 or > 10G, (outside the range of {0 .. 10G}) 
10                      Check if the _Used% field is < 0 or > 10, (outside the range of {0 .. 10}), since _Used% is the default
_Used%=10               Check if the _Used% field is < 0 or > 10, (outside the range of {0 .. 10}) 

FIELD examples with multiple specifications - for MODE=checkdrivesize:
eg -w _UsedGB=10G   -w 15   -w _Free%=5:  -c _UsedGB=20G   -c _Used%=25
This will generate a warning if 
   - the Used GB on the drive is more than 10G or 
   - the used % of the drive is more than 15% or
   - the free % of the drive is less than 5%
This will generate a critical if 
   - the Used GB on the drive is more than 20G or 
   - the used % of the drive is more than 25%

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
# pass a number
# from http://www.perlmonks.org/?node_id=378538
# very cool
# modified a little to protect against uninitialised variables and to remove the byte unit 
my ($incoming)=@_;
if ($incoming ne '') {
   (sort { length $a <=> length $b }
   map { sprintf '%.3g%s', $incoming/$actual_bytefactor**$_->[1], $_->[0] }
   [""=>0],[K=>1],[M=>2],[G=>3],[T=>4],[P=>5],[E=>6])[0]
} else {
   return '';
}
}
#-------------------------------------------------------------------------
sub get_multiple_wmi_samples {
# perform the same WMI query 1 or more times with a time delay in between and return the results in an array
# good for using RAW performance data and gives me a standard way to perform queries and have the results loaded into a known structure
# pass in
# number of samples to get
# the WMI query to get the values you are wanting
# the regular expression to extract the names of the values (comma list like $value_rege not supported as this parameter is not really needed or hardly ever)
# the regular expression to extract the results - we also support this being a comma delimited list of field numbers to be kept where we assume the field delimiter is | and that the field numbers start at 1 eg 1,4,5
# an array reference where the results will be placed. Index 0 will contain the first values, index 1 the second values
# the delay (passed to the sleep command) between queries. This is reference that "passed back" so that the calling sub can see what was actually used. Pass by reference using \$VARIABLE
# An array reference listing the column titles that we should provide sums for
#     There are several sums made available
#     - array index [0][ROWNUMBER] prefixed by _QuerySum_fieldname which sums up all the fieldnames across multiple queries
#     - array index [QUERYNUMBER][0] prefixed by _RowSum_fieldname which sums up all the fieldnames across multiple rows in a single query number QUERYNUMBER
# set $slash_conversion to 1 if we should replace all / in the WMI query with \\

# we return an empty string if it worked ok, a msg if it failed
my ($num_samples,$wmi_query,$column_name_regex,$value_regex,$results,$specified_delay,$provide_sums,$slash_conversion)=@_;

# the array @[$results} will look something like this when we have loaded it
# @array[INDEX1][INDEX2]{HASH1}=VALUE
# where
# INDEX1 is number of the query eg if we do 2 queries then INDEX1 will be 0 and 1
# INDEX2 is the result line, with one index per line returned in the WMI query eg if we do a query which lists 5 processes INDEX2 will be from 0 to 4
# HASH1 will contain the field names eg ProcessorQueueLength
# the value will be the value of the field eg 16
# There are some special values also stored in this structure
# @array[0][0]{'_ChecksOK'}=the number of checks that were completed OK
# @array[INDEX1][0]{'_ItemCount'}=the number of rows returned by the WMI query number INDEX1
# So if you are doing only a single query that returns a single row then INDEX1 always=0 and then INDEX always=0 as well


# extract parameters from arguments
if ($$specified_delay) {
   if ($$specified_delay ge 0) {
   # all good - we assume
   } else {
      print "Delay not specified correctly. Should be a number >= zero.\n";
      exit $ERRORS{'UNKNOWN'};
   }
}

# the WMI query may contain "variables" where we substitute values into
# a variables looks like {SOMENAME}
# if we find one of these we substitute values from the hash %the_arguments
# eg {arg1} gets replaced by the value held in $the_arguments{'_arg1'}
# this is how we pass command line arguments into the query
$wmi_query=~s/\{(.*?)\}/$the_arguments{$1}/g;

# we also need to make sure that any ' in the query are escaped
$wmi_query=~s/'/\\'/g;

if ($slash_conversion) {
   # replace any / in the WMI query \\ since \ are difficult to use in linux on the command line
   # we replace it with \\ to pass an actual \ to the command line
   # use # as the delimiter for the regex to make it more readable (still need to escape / and \ though)
   $wmi_query=~s#\/#\\\\#g;   
}

# How to use an alternate namespace using wmic
# "SELECT * From rootdse" --namespace=root/directory/ldap
$wmi_commandline = "$wmic_command -U ${opt_username}%${opt_password} //$the_arguments{'_host'} '$wmi_query'";

my $all_output=''; # this holds information if any errors are encountered

my $failure=0;
my $checks_ok=0;
my @hardcoded_field_list;

# loop through the multiple queries
for (my $i=0;$i<$num_samples;$i++) {
   $output = `$wmi_commandline 2>&1`;

   $all_output.=$output;
   $debug && print "Round #$i, looking for $column_name_regex\n";
   $debug && print "QUERY: $wmi_commandline\nOUTPUT: $output\n";

   # now we have to verify and parse the returned query
   # a valid return query comes back in the following format
   # CLASS: <WMICLASSNAME>
   # <FIELDNAMES separated by |>
   # <Row 1 DATA VALUES separated by |>
   # <Row 2 DATA VALUES separated by |>
   # <Row n DATA VALUES separated by |>
   #
   # Sometimes queries only return a single data row

   # could be something like this:
   # CLASS: Win32_PerfRawData_PerfOS_Processor
   # Name|PercentProcessorTime|Timestamp_Sys100NS
   # _Total|2530739524720|129476821059431200

   # There are 3 typical types of outputs:
   # 1) the query works fine and returns data - this looks like above
   # 2) the query worked but found no data eg you are looking for specific process names then $output will be empty
   # 3) an error occurred - the error message is returned
   
   if ($output eq '') {
      # the query probably worked but just returned no data
      # lets set some variables
      $$results[0][0]{'_ChecksOK'}++;
      $$results[$i][0]{'_ItemCount'}=0;
   } else {
      # now we have 2 possibilities left
      # 1) good results formatted nicely
      # 2) errors
      
      if ($output=~/CLASS: \w+\n/sg) {
         # looks like we have some results
         
         # now, if $column_name_regex is specified then we have to use the regex to look for the column names
         # else we just look for the next line and split it on |
         my $got_header=0;
         my @column_names=();
         # doing this check each time helps validate the results
         if ($column_name_regex) {
            if ($output=~/$column_name_regex/sg) {
               $got_header=1;
               my $j=0;
               # I'd really like to use a perl 5.10 construct here (Named Capture buffers ie the hash $+) to make it much nicer code but have decided to do it an ugly way to accomodate older versions
               # so now we have to go through $1, $2 one at a time in a hardcoded fashion (is there a better way to do this?) 
               # this places a hard limit on the number of fields we can find in our regex
               # of course this is only a problem if you need to specify a specific regex to find your field data in the WMI results
               #------------------------------------------------------
               # add more hardcoding here as needed - yuk - at some point we will use %+ - when enough people are on perl 5.10 or more
               # this is the first of 2 places you need to change this hardcoding
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
               $$results[0][0]{'_ChecksOK'}++;
            }
         } else {
            # we just do a regex that grabs the next line of output
            if ($output=~/(.*?)\n/sg) {
               $got_header=1;
               # we just use split to break out the column titles
               @column_names=split(/\|/,$1);
               $debug && print "COLUMNS:$1\n";
               $$results[0][0]{'_ChecksOK'}++;
            }
         }
         
         if ($got_header) {
            # since we have the header titles we can now look for the data
            # just like the column titles the user might have specified a regex to find the fields
            # we do this because sometimes there are queries the return a different number of fields in the titles to the data
            # eg the page file query - 3 fields in the title and 5 fields in the data!
            #CLASS: Win32_OperatingSystem
            #FreePhysicalMemory|Name|TotalVisibleMemorySize
            #515204|Microsoft Windows XP Professional|C:\WINDOWS|\Device\Harddisk0\Partition1|1228272   
            my $use_split=1;
            my $field_finding_regex='(.*?)\n'; # this is the default
            my %keep_certain_fields=();
            if ($value_regex) {
               # $value_regex has 2 possibilities
               # 1) a comma delimited list of data field numbers to be kept eg 1,2,4
               # 2) a regular express to find the fields (still needed if the data contains \n)
               if ($value_regex=~/([\d,]+)/) {
                  # we will just use this regex to break up the fields
                  # FORMAT: NUM:FIELDLIST where FIELDLIST is a comma delimited list of field numbers we want to retrieve
                  # load up the hash that tells us which fields to keep
                  foreach my $field (split(',',$value_regex)) {
                     $keep_certain_fields{$field}=1;
                  }
                  $debug && print "KEEP ONLY THESE FIELDS=$value_regex\n";
               } else {
                  # we assume that this is a regex
                  $field_finding_regex=$value_regex;
                  $use_split=0; # do not use the split
                  $debug && print "Using Custom Regex to find FIELDS\n";
               }
            }
            
            # now loop through the returned records
            $debug && print "Now looking for $field_finding_regex (use_split=$use_split)\n";
            my $found=0;
            my @field_data;
            while ($output=~/$field_finding_regex/sg) {
               # now we have matched a result row, so break it up into fields
               if ($use_split) {
                  @field_data=split(/\|/,$1);
                  my $header_field_number=0;
                  my $data_field_number=1; # these ones start from 1 since it makes it easier for the user to define - take care
                  $debug && print "FIELDS:";
                  foreach my $field (@field_data) {
                     my $use_field=1;
                     if ($value_regex && ! exists($keep_certain_fields{$data_field_number})) {
                        $debug && print "Drop Field #$data_field_number=$field\n";
                        $use_field=0;
                     }
                     if ($use_field) {
                        $debug && print "COLNAME=$column_names[$header_field_number],FIELD=$field\n";
                        # If you got the regex wrong or some fields come back with | in them you will get 
                        # "Use of uninitialized value within @column_names in hash element" error when using $column_names[$header_field_number]
                        # hence use $column_names[$header_field_number]||''
                        $$results[$i][$found]{$column_names[$header_field_number]||''}=$field;
                        # only increment the header field number when we use it 
                        $header_field_number++;
                     }
                     # always increment the data field number
                     $data_field_number++;
                  }
                  $debug && print "\n";
                  $debug && print "Row Data Found OK\n";
               } else {
                  my $j=0;
                  #------------------------------------------------------
                  # add more hardcoding here as needed - yuk - at some point we will use %+ - when enough people are on perl 5.10 or more
                  # this is the second of 2 places you need to change this hardcoding
                  # hopefully putting these to zero if they do not have any value will be ok, need a way to tell if $1 is '' or 0 really
                  @hardcoded_field_list=( $1||0,$2||0,$3||0,$4||0,$5||0,$6||0,$7||0,$8||0,$9||0 );
                  #------------------------------------------------------
                  $debug && print "FIELDS:";
                  foreach my $regex_field (@hardcoded_field_list) {
                     $debug && print "$regex_field, ";
                     if ($regex_field ne '') {
                        # If you ggot the regex wrong or some fields come back with | in them you will get 
                        # "Use of uninitialized value within @column_names in hash element" error when using $column_names[$j]
                        # hence use $column_names[$j]||''
                        $$results[$i][$found]{$column_names[$j]||''}=$regex_field;
                     }
                     $j++;
                  }
                  $debug && print "\n";
                  $debug && print "Row Data Found OK\n";
               }
               
               # provide Sums if the parameter is defined
               foreach my $field_name (@{$provide_sums}) {
                  # we have to sum up all the fields named $field_name
                  # we can assume that they are numbers
                  # and we also assume that they are valid for this WMI query! ie that the programmer got it right!
                  # this first sum, sums up all the $field_name across all the queries for the Row Number $i
                  $$results[0][$found]{"_QuerySum_$field_name"}+=$$results[$i][$found]{$field_name};
                  # this sum, sums up all the $field_names within a single query - ie where multiple rows are returned
                  $$results[$i][0]{"_RowSum_$field_name"}+=$$results[$i][$found]{$field_name};
               }
               # increment the results counter for this query
               $found++;         
               
            }
            # record the number of rows found for this query
            $$results[$i][0]{'_ItemCount'}=$found;
         } else {
            $debug && print "Could not find the column title line\n";
            $failure++;
         }
         
      } else {
         $debug && print "Could not find the CLASS: line - an error occurred\n";
         $failure++;
      }
   }
      
   if ($i+1!=$num_samples) {
      # only need to sleep the first time round and its not the last
      $debug && print "Sleeping for $$specified_delay seconds ... ($i,$num_samples)\n";
      sleep $$specified_delay;
   }
   
}

$debug && print "WMI DATA:" . Dumper($results);

my $sub_result='';
if ($failure>0) {
   $sub_result=$all_output;
}
return $sub_result;
}
#-------------------------------------------------------------------------
sub combine_display_and_perfdata {
my ($display,$perfdata)=@_;
# pass in
# a nagios display string
# a nagios performance data string
my $combined='';
# now build the combined string (we are providing multiple options for programming flexibility)
# we have to make sure that we follow these rules for performance data
# if there is a \n in the $display_string, place |PERFDATA just before it
# if there is no \n, place |PERFDATA at the end
# we'll try and improve this to make it a single regex - one day .....
#$debug && print "Building Combined Display/Perfdata ... ";
if ($display=~/\n/) {
   #$debug && print "Found LF\n";
   $combined=$display;
   # stick the perf data just before the \n
   $combined=~s/^(.*?)\n(.*)$/$1|$perfdata\n$2/s;
} else {
   #$debug && print "No LF\n";
   $combined="$display|$perfdata\n";
}

# if there is no perfdata | will be the last character - remove | if it is at the end
$combined=~s/\|$//;

#$debug && print "IN:$display|$perfdata\n";
#$debug && print "OUT:$combined\n";
return $combined;
}
#-------------------------------------------------------------------------
sub create_display_and_performance_data {
# creates a standardised display for the results and performance data
# may not be totally suitable for all checks but should get most of them
my ($values,$display_fields,$performance_data_fields,$warning_specs,$critical_specs)=@_;
# pass in
# the values in a hash ref that you want to display/ create perf data for
# a list of the fields you actually want to display
# a list of the units matching the display fields
# a list of the fields you want to create perf data for
# a list of the units matching the perf data fields
# a hash of the warning specifications by field name
# a hash of the critical specifications by field name
my $display_string='';
my $performance_data_string='';
my $delimiter=', ';

# add the arguments hash into the incoming data values
foreach my $key (keys %the_arguments) {
   # their names should already be starting with _ to reduce the chance that they clash
   $$values{$key}=$the_arguments{$key};
}


# ------------------ create display data
my $i=0;
$debug && print "---------- Building Up Display\n";
$debug && print "Incoming Data " . Dumper($values);
foreach my $field (@{$display_fields}) {
   if ($field ne '') {
      $debug && print "------- Processing $field\n";
      my $this_delimiter=$delimiter;
      my $this_real_field_name='';
      my $this_display_field_name=''; # default display name
      my $this_sep='='; # default separator
      my $this_unit=''; # default display unit
      my $this_value=''; # default display value
      my $this_enclose='';
      my $this_start_bracket='';
      my $this_end_bracket='';
   
      # the field name comes in this format
      # 1) FIELD|UNITS|DISPLAY|SEP|DELIM|START|END
      # 2) FIELD|UNITS
      # 3) FIELD
      
      if ($field=~/^(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)$/) {
         $debug && print "Complex Format:$1,$2,$3,$4,$5,$6,$7\n";
         $this_real_field_name=$1;
         $this_unit=$2;
         $this_display_field_name=$3 || $this_real_field_name;
         $this_sep=$4 || '=';
         $this_delimiter=$5 || $delimiter;
         $this_start_bracket=$6;
         $this_end_bracket=$7;
   
         # change .~ to nothing
         $this_display_field_name=~s/~//g;
         $this_sep=~s/~//g;
         $this_delimiter=~s/~//g;
   
      } elsif ($field=~/^(.*)\|(.*)$/) {
         $debug && print "Simple Format:$1,$2\n";
         $this_real_field_name=$1;
         $this_unit=$2;
         $this_display_field_name=$this_real_field_name;
         
      } elsif ($field!~/\|/) { # no | characters
         $debug && print "Field Only Format:$field\n";
         $this_real_field_name=$field;
         $this_display_field_name=$this_real_field_name;
         
      } else {
         print "Invalid Display FIELD Specification: $field\n";
      }
   
      # see if there are any "variables" in display name - they are enclosed in {} and match a key of the $value hash
      # eg this replaces {DeviceID} by the value held in $$values{'DeviceID'}
      $this_display_field_name=~s/\{(.*?)\}/$$values{$1}/g;
      $this_start_bracket=~s/\{(.*?)\}/$$values{$1}/g;
      $this_end_bracket=~s/\{(.*?)\}/$$values{$1}/g;
     
      #$debug && print "Loading up value using FIELD=$this_real_field_name\n";
      # now we can extract the value
      $this_value=$$values{$this_real_field_name};
      
      # now see if we need to change the display value/unit
      # by default we expect this just to be UNIT
      # However, if prefixed with a # ie #UNIT eg #B, then we apply scaling to the UNIT
      if ($this_unit=~/^#(.*)$/) {
         # use the function to display the value and units
         $this_value=scaled_bytes($this_value);
         $this_unit=$1;
      }
      
      $debug && print "$field ----> $this_start_bracket$this_display_field_name$this_sep$this_value$this_unit$this_end_bracket$this_delimiter\n";
      $display_string.="$this_start_bracket$this_display_field_name$this_sep$this_value$this_unit$this_end_bracket$this_delimiter";
      $i++;
   }
}
# remove the last delimiter
$display_string=~s/$delimiter$//;

# ------------------- create performance data
$i=0;
$debug && print "---------- Building Up Performance Data\n";
foreach my $field (@{$performance_data_fields}) {
   if ($field ne '') {
      $debug && print "------- Processing $field\n";
      my $this_real_field_name=$field;
      my $this_display_field_name=''; # default display name
      my $this_unit=''; # default display unit
      my $this_value=''; # default display value
   
   
      # the field name comes in this format
      # 1) FIELD|UNITS|DISPLAY
      # 2) FIELD|UNITS
      # 3) FIELD
   
      
      if ($field=~/^(.*)\|(.*)\|(.*)$/) {
         $debug && print "Complex Format:$1,$2,$3\n";
         $this_real_field_name=$1;
         $this_unit=$2;
         $this_display_field_name=$3;
         
      } elsif ($field=~/^(.*)\|(.*)$/) {
         $debug && print "Simple Format:$1,$2\n";
         $this_real_field_name=$1;
         $this_unit=$2;
         $this_display_field_name=$this_real_field_name;
         
      } elsif ($field!~/\|/) { # no | characters
         $debug && print "Field Only Format:$field\n";
         $this_real_field_name=$field;
         $this_display_field_name=$this_real_field_name;
      } else {
         print "Invalid Performance Data FIELD Specification: $field\n";
      }
   
      # see if there are any "variables" in display name - they are enclosed in {} and match a key of the $value hash
      # eg this replaces {DeviceID} by the value held in $$values{'DeviceID'}
      $this_display_field_name=~s/\{(.*?)\}/$$values{$1}/g;
      $this_unit=~s/\{(.*?)\}/$$values{$1}/g;
         
      
      # $debug && print "Loading up value using FIELD=$this_real_field_name\n";
      # now we can extract the value
      $this_value=$$values{$this_real_field_name};
      
      # now see if we need to change the display value/unit
      # by default we expect this just to be UNIT
      # However, if prefixed with a # ie #UNIT eg #B, then we apply scaling to the UNIT
      if ($this_unit=~/^#(.*)$/) {
         # use the function to display the value and units
         $this_value=scaled_bytes($this_value);
         $this_unit=$1;
      }
      
      $debug && print "$field (Field=$this_real_field_name) ----> '$this_display_field_name'=$this_value$this_unit;$$warning_specs{$this_real_field_name};$$critical_specs{$this_real_field_name}; \n";
      $performance_data_string.="'$this_display_field_name'=$this_value$this_unit;$$warning_specs{$this_real_field_name};$$critical_specs{$this_real_field_name}; ";
      $i++;
   }
}

# remove any ;; from performance data so that it contains only the minimum required
$_=$performance_data_string;
while ($performance_data_string=~s/;;/;/g) {}

$debug && print "---------- Done\n";

my $combined_string=combine_display_and_perfdata($display_string,$performance_data_string);
 
return $display_string,$performance_data_string,$combined_string;
}
#-------------------------------------------------------------------------
sub no_data_check {
# controls how the plugin responds if no data is returned from the WMI query
# the plugin can exit in this sub
# pass in
# the number of items returned in the WMI query ie the value of _ItemCount
my ($itemcount)=@_;
if ($the_arguments{'_nodata'}) {
   # this means that the users wants to test filecount using warn/crit criteria 
   # so we will not do our default behaviour
   # default behaviour is to go warning/critical if the $itemcount==0 ie no data was returned
   # this might mean that some other values might not be initialised so you will need to initialise them within each check before you call this sub eg for checkfilesize the value of FileSize will not get set if we do not find the file
} else {
   # we have to go warning/critical if the file does not exist
   if ($itemcount==0) {
      print "WMI Query returned no data. The item you were looking for may NOT exist.\n";
      # we exit with the value the user specified in $the_arguments{'_nodataexit'}, if any
      if ($the_arguments{'_nodataexit'} ge 0 && $the_arguments{'_nodataexit'} le 3) {
         $debug && print "Exit with user defined exit code $the_arguments{'_nodataexit'}\n";
         exit $the_arguments{'_nodataexit'};
      } else {
         exit $ERRORS{'CRITICAL'};
      }
   }
}
}
#-------------------------------------------------------------------------
sub checkini {
# run a check as defined in the ini file
my ($wmi_ini,$ini_section)=@_;
# pass in 
# the config::inifiles object
# the section name in the ini file we have to process
$debug && print "Processing INI Section: $ini_section\n";

# change the $opt_mode to be the same as the section name
# we need this since some things look up values by $opt_mode
$opt_mode=$ini_section;

# grab the query
my $query=$wmi_ini->val($ini_section,'query','');

if ($query) {

   # now, optionally we need some fields to check warn/crit against
   # these are in the testfield parameter(s)
   my @test_fields_list=$wmi_ini->val($ini_section,'test','');
   $debug && print "Test Fields: " . Dumper(\@test_fields_list);

   # now we need some display fields (at least one)
   my @display_fields_list=$wmi_ini->val($ini_section,'display','');
   $debug && print "Display Fields: " . Dumper(\@display_fields_list);
   
   # and optionally get some perf data fields
   my @perfdata_fields_list=$wmi_ini->val($ini_section,'perf','');
   $debug && print "Perf Fields: " . Dumper(\@perfdata_fields_list);

   if ($#display_fields_list>=0) {

      # add all the test, display and perfdata fields to the global config variables so that our functions can find them when needed
      $valid_test_fields{$opt_mode}=\@test_fields_list;
      $display_fields{$opt_mode}=\@display_fields_list;
      $performance_data_fields{$opt_mode}=\@perfdata_fields_list;
      
      my $requires_version=$wmi_ini->val($ini_section,'requires',0);
      if ($VERSION < $requires_version) {
         # this is a problem
         print "This check ($opt_mode) requires at least version $requires_version of the plugin\n";
         exit $ERRORS{'UNKNOWN'};
      }
      
      # if --inihelp has been specified then show the help for this mode
      if ($opt_inihelp) {
         my $inihelp=$wmi_ini->val($ini_section,'inihelp','');
         short_usage(1);
         if ($inihelp) {
            print "\n$inihelp\n";
         }
         print "\n";
         print "Valid Warning/Critical Fields are: " . join(", ",@test_fields_list) . "\n";
         exit;
      }
      
      my $custom_header_regex=$wmi_ini->val($ini_section,'headerregex','');
      my $custom_data_regex=$wmi_ini->val($ini_section,'dataregex','');

      my @collected_data;
      my $data_errors=get_multiple_wmi_samples(1,
         "$query",
         $custom_header_regex,$custom_data_regex,\@collected_data,\$the_arguments{'_delay'},undef,$wmi_ini->val($ini_section,'slashconversion',''));
      
      if ($data_errors) {
         print "UNKNOWN: Could not retrieve all required data. $data_errors";
         exit $ERRORS{'UNKNOWN'};
      } else {
         no_data_check($collected_data[0][0]{'_ItemCount'});

         my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
         my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
         print $this_combined_data;
      
         exit $test_result;
      }
      
   } else {
      print "UNKNOWN: No displayfield(s) specified in ini file section '$ini_section'\n";
      exit $ERRORS{'UNKNOWN'};
   }

} else {
   print "UNKNOWN: Query not specified in ini file section '$ini_section'\n";
   exit $ERRORS{'UNKNOWN'};
}

}
#-------------------------------------------------------------------------
sub checkgeneric {
# I use this when I am playing around ........
my @collected_data;
my $data_errors=get_multiple_wmi_samples(1,
   "SELECT * FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk where name = \"c:\"",
   '','',\@collected_data,\$the_arguments{'_delay'},undef,0);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;

   exit $test_result;
}

}
#-------------------------------------------------------------------------
sub checkcpu {

# set default delay for this mode
if ($the_arguments{'_delay'} eq '') {
   $the_arguments{'_delay'}=5;
}

my @collected_data;
my $data_errors=get_multiple_wmi_samples(2,
   "select PercentProcessorTime,Timestamp_Sys100NS from Win32_PerfRawData_PerfOS_Processor where Name=\"_Total\"",
   '','',\@collected_data,\$the_arguments{'_delay'},undef,0);

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

   $collected_data[0][0]{'_AvgCPU'}=sprintf("%.0f", $avg_cpu_util);

   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;

   exit $test_result;
}

}
#-------------------------------------------------------------------------
sub checknetwork {
my @collected_data;

# for network stuff we often want $actual_bytefactor to be 1000
# so lets use that unless the user has set something else
if (!$the_arguments{'_bytefactor'}) {
   $actual_bytefactor=1000;
}

my $where_bit='';
if ($the_arguments{'_arg1'} ne '') {
   $where_bit="where Name=\"$the_arguments{'_arg1'}\"";
}
my $data_errors=get_multiple_wmi_samples(1,
   "select CurrentBandwidth,BytesReceivedPerSec,BytesSentPerSec,Name,OutputQueueLength,PacketsReceivedErrors,PacketsReceivedPerSec,PacketsSentPerSec,Timestamp_Sys100NS from Win32_PerfFormattedData_Tcpip_NetworkInterface $where_bit",
   '','',\@collected_data,\$the_arguments{'_delay'},undef,0);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} elsif ($#collected_data>=0) {
   # at this point we can assume that we have all the data we need stored in @network_data
   # there is some point collected data that could be useful to average over a few samples here
   # I may do that later
   
   if ($where_bit) {
      my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
      my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
      print $this_combined_data;
      exit $test_result;
   } else {
      # no where_bit specified so just list out all the adapter names
      print "Adapter Names are:\n" . list_collected_values_from_all_rows(\@collected_data,['Name'],"\n",'',0) . "\nSpecify the -a parameter with an adapter name.";
      exit $ERRORS{'UNKNOWN'};
   }
} else {
   print "No data returned. Possibly the Network Adapter Name does not exist. Stop using the -a parameter and this will list valid adapter names.";
   exit $ERRORS{'UNKNOWN'};
}

}
#-------------------------------------------------------------------------
sub checkcpuq {
# set default delay for this mode
if ($the_arguments{'_delay'} eq '') {
   $the_arguments{'_delay'}=1;
}

# set default number of checks if not specified
if (!$the_arguments{'_arg1'}) {
   $the_arguments{'_arg1'}=3;
}

my @collected_data;
my $data_errors=get_multiple_wmi_samples($the_arguments{'_arg1'},
   "select ProcessorQueueLength from Win32_PerfRawData_PerfOS_System",
   '','',\@collected_data,\$the_arguments{'_delay'},[ 'ProcessorQueueLength' ],0);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   # at this point we can assume that we have all the data we need stored in @collected_data
   $collected_data[0][0]{'_AvgCPUQLen'}=sprintf("%.1f",$collected_data[0][0]{'_QuerySum_ProcessorQueueLength'}/$collected_data[0][0]{'_ChecksOK'});
   $collected_data[0][0]{'_CPUQPoints'}=list_collected_values_from_all_rows(\@collected_data,['ProcessorQueueLength'],', ','',0);
   
   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;
   exit $test_result;
}

}
#-------------------------------------------------------------------------
sub checkmem {
# note that for this check WMI returns data in kiobytes so we have to multiply it up to get bytes before using scaled_bytes

my @collected_data;
my $data_errors='';

my $display_type='';
# still support for the old usage of arg1
if ($the_arguments{'_arg1'}=~/phys/i || $opt_submode=~/phys/i) {
   $collected_data[0][0]{'MemType'}='Physical Memory';
   # expect output like
   #CLASS: Win32_OperatingSystem
   #FreePhysicalMemory|Name|TotalVisibleMemorySize
   #515204|Microsoft Windows XP Professional|C:\WINDOWS|\Device\Harddisk0\Partition1|1228272   
   # this means that we need to specify a regular expression to retrieve the data since there are more fields in the data than column headings
   # we only want data fields 1 4 5 so that we match the column headings
   $data_errors=get_multiple_wmi_samples(1,
   "Select Name,FreePhysicalMemory,TotalVisibleMemorySize from Win32_OperatingSystem",
   '','1,4,5',\@collected_data,\$the_arguments{'_delay'},undef,0);

   # this query returns FreePhysicalMemory,TotalVisibleMemorySize - we move them to the standard fields of _MemFreeK and _MemTotalK so that we can process them in a standard way
   # if there has been a problem with the query then they might not be set
   $collected_data[0][0]{'_MemFreeK'}=$collected_data[0][0]{'FreePhysicalMemory'}||0;
   $collected_data[0][0]{'_MemTotalK'}=$collected_data[0][0]{'TotalVisibleMemorySize'}||0;

} elsif ($the_arguments{'_arg1'}=~/page/i || $opt_submode=~/page/i) {
   $collected_data[0][0]{'MemType'}='Page File';
   # expect output like
   #CLASS: Win32_OperatingSystem
   #FreeVirtualMemory|Name|TotalVirtualMemorySize
   #2051912|Microsoft Windows XP Professional|C:\WINDOWS|\Device\Harddisk0\Partition1|2097024
   # this means that we need to specify a regular expression to retrieve the data since there are more fields in the data than column headings
   # we only want data fields 1 4 5 so that we match the column headings
   $data_errors=get_multiple_wmi_samples(1,
   "Select Name,FreeVirtualMemory,TotalVirtualMemorySize from Win32_OperatingSystem",
   '','1,4,5',\@collected_data,\$the_arguments{'_delay'},undef,0);

   # this query returns FreePhysicalMemory,TotalVisibleMemorySize - we move them to the standard fields of _MemFreeK and _MemTotalK so that we can process them in a standard way
   # if there has been a problem with the query then they might not be set
   $collected_data[0][0]{'_MemFreeK'}=$collected_data[0][0]{'FreeVirtualMemory'}||0;
   $collected_data[0][0]{'_MemTotalK'}=$collected_data[0][0]{'TotalVirtualMemorySize'}||0;

} else {
   print "UNKNOWN: invalid SUBMODE in the checkmem function - should be page or physical.\n";
   exit $ERRORS{'UNKNOWN'};
}

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   # at this point we can assume that we have all the data we need stored in @collected_data
   $collected_data[0][0]{'_MemUsedK'}=$collected_data[0][0]{'_MemTotalK'}-$collected_data[0][0]{'_MemFreeK'};
   $collected_data[0][0]{'_MemUsed%'}=sprintf("%.0f",$collected_data[0][0]{'_MemUsedK'}/$collected_data[0][0]{'_MemTotalK'}*100);
   $collected_data[0][0]{'_MemFree%'}=sprintf("%.0f",$collected_data[0][0]{'_MemFreeK'}/$collected_data[0][0]{'_MemTotalK'}*100);
   $collected_data[0][0]{'_MemFree%'}=sprintf("%.0f",$collected_data[0][0]{'_MemFreeK'}/$collected_data[0][0]{'_MemTotalK'}*100);
   $collected_data[0][0]{'_MemUsed'}=$collected_data[0][0]{'_MemUsedK'}*$actual_bytefactor;
   $collected_data[0][0]{'_MemFree'}=$collected_data[0][0]{'_MemFreeK'}*$actual_bytefactor;
   $collected_data[0][0]{'_MemTotal'}=$collected_data[0][0]{'_MemTotalK'}*$actual_bytefactor;
   
   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
      
   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;
   exit $test_result;
}
  
}
#-------------------------------------------------------------------------
sub checkfileage {
# initial idea from steav on github.com
# its a good idea and we modified to for our use using our programming techniques and 
# ensuring that the warning/critical criteria were consistently used
# this is where we also first introduced the time multipliers

use DateTime;

my $perf_data_unit='hr'; # default unit is hours
# if the user specifies it but it is not valid we silently fail
if (defined($time_multipliers{$the_arguments{'_arg2'}})) {
   # looks like the user has specified a valid time multiplier for use in the performance data
   $perf_data_unit=$the_arguments{'_arg2'};  
}
my $perf_data_divisor=$time_multipliers{$perf_data_unit};

# we can not support full performance data with warn/crit since we want to divide it by whatever units the user specifies
$opt_z=''; 

my @collected_data;

my $data_errors=get_multiple_wmi_samples(1,
   "Select name,lastmodified from CIM_DataFile where name=\"$the_arguments{'_arg1'}\"",
   '','',\@collected_data,\$the_arguments{'_delay'},undef,1);

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
         $collected_data[0][0]{'_FileAge'}=$fileage;
         
         my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
   
         $collected_data[0][0]{'_DisplayFileAge'}=sprintf("%.2f",$fileage/$perf_data_divisor);
         $collected_data[0][0]{'_NicelyFormattedFileAge'}=display_uptime($fileage);
         $collected_data[0][0]{'_PerfDataUnit'}=$perf_data_unit;
         
         # apply the /$perf_data_divisor throughout the performance data
         # have to take special care if no warn/crit specified
         # also, we want to apply these new warning/critical specs against the "_DisplayFileAge" field
         $warn_perf_specs_parsed{'_DisplayFileAge'}='';
         if ($warn_perf_specs_parsed{'_FileAge'} ne '') {
            $warn_perf_specs_parsed{'_DisplayFileAge'}=$warn_perf_specs_parsed{'_FileAge'}/$perf_data_divisor;
         }
         $critical_perf_specs_parsed{'_DisplayFileAge'}='';
         if ($critical_perf_specs_parsed{'_FileAge'} ne '') {
            $critical_perf_specs_parsed{'_DisplayFileAge'}=$critical_perf_specs_parsed{'_FileAge'}/$perf_data_divisor;
         }
         
         my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
         print $this_combined_data;
         
         exit $test_result;
      } else {
         print "UNKNOWN: Could not correct recognise the returned time format $lastmodified";
         exit $ERRORS{'UNKNOWN'};
      }
   } else {
      print "UNKNOWN: Could not find the file $the_arguments{'_arg1'}";
      exit $ERRORS{'UNKNOWN'};
   }
   
}

}
#-------------------------------------------------------------------------
sub checkfilesize {
my @collected_data;
# have to initialise this incase the file is not found
$collected_data[0][0]{'FileSize'}=0;
$collected_data[0][0]{'_FileCount'}=0;

my $data_errors=get_multiple_wmi_samples(1,
   "Select name,filesize from CIM_DataFile where name=\"$the_arguments{'_arg1'}\"",
   '','',\@collected_data,\$the_arguments{'_delay'},undef,1);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {

   no_data_check($collected_data[0][0]{'_ItemCount'});

   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;;

   exit $test_result;
      
}

}
#-------------------------------------------------------------------------
sub checkfoldersize {
# make sure the path ends with a / to make sure we only get matching folders
if ($the_arguments{'_arg1'}!~/\/$/) {
   # no slash on the end so add it
   $the_arguments{'_arg1'}="$the_arguments{'_arg1'}/";
}

# we split up the query to drive letter and path since this should be faster than a linear search for all matching filenames
my $drive_letter='';
my $path='';
if ($the_arguments{'_arg1'}=~/^(\w:)(.*)/) {
   $drive_letter=$1;
   $path=$2;
} else {
   print "Could not extract drive letter and path from $the_arguments{'_arg1'}\n";
   exit $ERRORS{'UNKNOWN'};
}

my $wildcard='';
my $operator='=';
if ($the_arguments{'_arg4'} eq 's') {
   # we want to get all sub dirs as well
   $wildcard='%';
   $operator='like';
}

my @collected_data;

# have to initialise this incase the file is not found
$collected_data[0][0]{'_FolderSize'}=0;

my $data_errors=get_multiple_wmi_samples(1,
   "Select name,filesize from CIM_DataFile where drive=\"$drive_letter\" AND path $operator \"${path}$wildcard\"",
   '','',\@collected_data,\$the_arguments{'_delay'},['FileSize'],1);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {

   no_data_check($collected_data[0][0]{'_ItemCount'});

   # Load the _FolderSize so that the user can specify warn/critical criteria
   $collected_data[0][0]{'_FolderSize'}=$collected_data[0][0]{'_RowSum_FileSize'}||0; # this was automatically calculated for us
   $collected_data[0][0]{'_FileList'}='';

   if ($collected_data[0][0]{'_ItemCount'}>0) {
      $collected_data[0][0]{'_FileList'}=" (List is on next line)\nThe file(s) found are " . list_collected_values_from_all_rows(\@collected_data,['Name'],"\n",'',0);
   }

   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;

   exit $test_result;
   
}

}
#-------------------------------------------------------------------------
sub checkwsusserver {
use DateTime;
my $age = DateTime->now(time_zone => 'local')->subtract(hours => 24);
my $where_time_part="TimeGenerated > \"" . $age->year . sprintf("%02d",$age->month) . sprintf("%02d",$age->day) . sprintf("%02d",$age->hour) . sprintf("%02d",$age->minute) . "00.00000000\""; # for clarity

my @collected_data;
my $data_errors=get_multiple_wmi_samples(1,
   "Select SourceName,Message from Win32_NTLogEvent where Logfile=\"Application\" and EventType < 2 and SourceName = \"Windows Server Update Services\" and $where_time_part",
   '','',\@collected_data,\$the_arguments{'_delay'},undef,0);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {

   if ($collected_data[0][0]{'_ItemCount'}==0) {
      # nothing returned, assume all ok
      print "OK - WSUS Database clean.\n";
      exit $ERRORS{'OK'};
   } else {
      $output =~ s/\r(Application)\|/Application\|/g;
      $output =~ s/\r//g;
      $output =~ s/\n//g;
      $output =~ s/\|/-/g;
      $output =~ s/(Application)-/\n\nApplication-/g;
      $output = substr($output, 64);
      print "CRITICAL: WSUS Server has errors, check eventlog for download failures, database may need to be purged by running the Server Cleanup Wizard.\|;\n$output";
      exit $ERRORS{'CRITICAL'};
   }
}

}
#-------------------------------------------------------------------------
sub checkprocess {

my $query_field='Name';
if ($opt_submode=~/c/i) {
   $query_field='CommandLine';
}

my $listing_field='Name';
if ($the_arguments{'_arg2'}=~/c/i) {
   $listing_field='CommandLine';
}

# arg1 might have / in it
# replace any / with . for searching purposes only
my $process_regex=$the_arguments{'_arg1'};
$process_regex=~s#\/#\\\\#g;

my @collected_data;
my $data_errors=get_multiple_wmi_samples(1,
   "select Name,CommandLine from Win32_Process",
   '','',\@collected_data,\$the_arguments{'_delay'},undef,0);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   # at this point we can assume that we have all the data we need stored in @collected_data
   my $result_text='';
   # now loop through the results, showing the ones requested
   # so we want to loop through all the rows in the first query result $collected_data[0] and keep only the ones matching the regex
   my @new_data=();
   foreach my $row (@{$collected_data[0]}) {
      # use # as the reg ex delimiter since the user might specify /
      if ( $$row{$query_field}=~/$process_regex/i ) {
         # this process should be included
         push(@new_data,$row);
      }
   }
   
   # now reload the array with the data we want to keep
   $collected_data[0]=\@new_data;
   # update the count
   $collected_data[0][0]{'_ItemCount'}=$#new_data+1;
   $debug && print "Including only the following processes " . Dumper(\@collected_data);

   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);

   $collected_data[0][0]{'ProcessList'}='';

   if ($collected_data[0][0]{'_ItemCount'}>0) {
      $collected_data[0][0]{'ProcessList'}=" (List is on next line)\nThe process(es) found are " . list_collected_values_from_all_rows(\@collected_data,[$listing_field],",   ",'',1);;
   }

   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);

   print $this_combined_data;

}
}
#-------------------------------------------------------------------------
sub checkservice {
# ------------------------ checking all services
my $where_bit='';
my $auto_mode='';
if (lc($the_arguments{'_arg1'}) eq 'auto') {
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
   '','',\@collected_data,\$the_arguments{'_delay'},undef,0);

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
      $debug && print "Service Info: " . Dumper($row);
      # in the middle of the WMI output there are lines like:
      # CLASS: Win32_Service
      # CLASS: Win32_TerminalService
      # which means DisplayName and Name might not be set so we need to test for this to stop
      # "Use of uninitialized value in pattern match" errors
      if ($$row{'DisplayName'} && $$row{'Name'}) {
         if (  $auto_mode || 
               ( !$auto_mode && ($$row{'DisplayName'}=~/$the_arguments{'_arg1'}/i || $$row{'Name'}=~/$the_arguments{'_arg1'}/i) ) 
            ) {
            if ($$row{'Started'} eq 'True' && $$row{'State'} eq 'Running' && $$row{'Status'} eq 'OK') {
               $num_ok++;
               if (!$auto_mode) {
                  # if we have using the regex mode then list out the services we find
                  $result_text.="'$$row{'DisplayName'}' ($$row{'Name'}) is $$row{'State'}, ";
               }
            } else {
               $num_bad++;
               $result_text.="'$$row{'DisplayName'}' ($$row{'Name'}) is $$row{'State'}, ";
            }
         }
      }
   }
   
   $result_text=~s/, $/./;

   # load some values to check warn/crit against
   $collected_data[0][0]{'_NumGood'}=$num_ok;
   $collected_data[0][0]{'_NumBad'}=$num_bad;
   $collected_data[0][0]{'_Total'}=$num_ok+$num_bad;
   $collected_data[0][0]{'_ServiceList'}=$result_text;

   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);

   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;

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
   '','',\@collected_data,\$the_arguments{'_delay'},undef,0);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   $collected_data[0][0]{'_UptimeMin'}=int($collected_data[0][0]{'SystemUpTime'}/60);
   $collected_data[0][0]{'_DisplayTime'}=display_uptime($collected_data[0][0]{'SystemUpTime'});

   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);

   # since we test warnings against SystemUpTime but want to show performance data for _UptimeMin we have to load the performance data for _UptimeMin
   # apply the /60 throughout the performance data - since SystemUptime is in seconds but we want to use Minutes for perf data
   # have to take special care if no warn/crit specified
   # also, we want to apply these new warning/critical specs against the "_UptimeMin" field
   $warn_perf_specs_parsed{'_UptimeMin'}='';
   if ($warn_perf_specs_parsed{'SystemUpTime'} ne '') {
      $warn_perf_specs_parsed{'_UptimeMin'}=$warn_perf_specs_parsed{'SystemUpTime'}/60;
   }
   $critical_perf_specs_parsed{'_UptimeMin'}='';
   if ($critical_perf_specs_parsed{'SystemUpTime'} ne '') {
      $critical_perf_specs_parsed{'_UptimeMin'}=$critical_perf_specs_parsed{'SystemUpTime'}/60;
   }


   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;

   exit $test_result;
}
}
#-------------------------------------------------------------------------
sub checkdrivesize {
my @collected_data;
my $data_errors=get_multiple_wmi_samples(1,
   "Select DeviceID,freespace,Size,VolumeName from Win32_LogicalDisk where DriveType=3",
   '','',\@collected_data,\$the_arguments{'_delay'},['FreeSpace','Size'],0);

#CLASS: Win32_LogicalDisk
#DeviceID|FreeSpace|Size|VolumeName
#C:|9679720448|21467947008|
#M:|2125115392|2138540032|Temp Disk 1
#N:|2125115392|2138540032|Temp Disk 2

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {
   my $results_text='';
   my $result_code=$ERRORS{'UNKNOWN'};
   my $performance_data='';
   my $num_critical=0;
   my $num_warning=0;
   my $alldisk_identifier='Overall Disk';

   if ($the_arguments{'_arg3'}) {
      # include the system totals
      # now we want to add a index before 0 so we copy everything from index 0 and unshift it to the front
      # we do it like this so that all the derived values normally stored in index 0 will remain there
      # then we overwrite the fields we want with new fake ones
      # note that the sum fields will be the orginal totals etc
      # now add this on to the existing data

      my %new_row=%{$collected_data[0][0]};
      unshift(@{$collected_data[0]},\%new_row);

      # now we have index 1 and index 0 the same data
      # add the new fake system total info
      # we make it look like WMI returned info about a disk call SystemTotalDisk
         $collected_data[0][0]{'DeviceID'}=$alldisk_identifier;
         $collected_data[0][0]{'FreeSpace'}=$collected_data[0][0]{'_RowSum_FreeSpace'};
         $collected_data[0][0]{'Size'}=$collected_data[0][0]{'_RowSum_Size'};
         $collected_data[0][0]{'VolumeName'}=$alldisk_identifier;

   }

   # now loop through the results, showing the ones requested
   foreach my $row (@{$collected_data[0]}) {
      # make sure $$row{'VolumeName'} is initialised (it won't be unless the drive has been named)
      $$row{'VolumeName'}=$$row{'VolumeName'} || '';
      # if $the_arguments{'_arg1'} is left out it will be blank and will match all drives
      if ($$row{'DeviceID'}=~/$the_arguments{'_arg1'}/i || $$row{'VolumeName'}=~/$the_arguments{'_arg1'}/i || ($$row{'DeviceID'} eq $alldisk_identifier && $the_arguments{'_arg3'}) ) {
         # include this drive in the results
         if ($$row{'Size'}>0) {
            # got valid data
            # add our calculated data to the hash
            $$row{'_DriveSizeGB'}=sprintf("%.2f", $$row{'Size'}/$actual_bytefactor/$actual_bytefactor/$actual_bytefactor);
            $$row{'_UsedSpace'}=$$row{'Size'}-$$row{'FreeSpace'};
            $$row{'_Used%'}=sprintf("%.1f",$$row{'_UsedSpace'}/$$row{'Size'}*100);
            $$row{'_UsedGB'}=sprintf("%.2f", $$row{'_UsedSpace'}/$actual_bytefactor/$actual_bytefactor/$actual_bytefactor);
            $$row{'_Free%'}=sprintf("%.1f",$$row{'FreeSpace'}/$$row{'Size'}*100);
            $$row{'_FreeGB'}=sprintf("%.2f", $$row{'FreeSpace'}/$actual_bytefactor/$actual_bytefactor/$actual_bytefactor);
            
            my $test_result=test_limits($opt_warn,$opt_critical,$row,\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
            
            # check for Critical/Warning
            if ($test_result==$ERRORS{'CRITICAL'}) {
               $num_critical++;
            } elsif ($test_result==$ERRORS{'WARNING'}) {
               $num_warning++;
            }

            # by default, in the performance data we use the drive letter to identify the drive
            # if the user has specified $other_opt_arguments=1 then we use the volume name (if it has one)
            my $drive_identifier=$$row{'DeviceID'};
            if ($the_arguments{'_arg2'} && exists($$row{'VolumeName'})) {
               if ($$row{'VolumeName'}) {
                  $drive_identifier=$$row{'VolumeName'};
               }
            }
            # stick the drive identifier into the values so it can be accessed
            $$row{'DiskDisplayName'}=$drive_identifier;
            
            my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($row,$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);

            # concatenate the per drive results together
            $results_text.="$this_display_info     ";
            $performance_data.=$this_performance_data;

         } else {
            # this drive does not get included in the results size there is a problem with its data
         }
      }
   }
   
   if ($results_text) {
      # show the results
      # remove the last ", "
      $results_text=~s/, +$//;
      # correctly combine the results and perfdata
      my $combined_string=combine_display_and_perfdata($results_text,$performance_data);
      print $combined_string;
      if ($num_critical>0) {
         exit $ERRORS{'CRITICAL'};
      } elsif ($num_warning>0) {
         exit $ERRORS{'WARNING'};
      } else {
         exit $ERRORS{'OK'};
      }
   } else {
      print "UNKNOWN: Could not find a drive matching '$the_arguments{'_arg1'}'. Available Drives are " . list_collected_values_from_all_rows(\@collected_data,['DeviceID'],', ','',0);
      exit $ERRORS{'UNKNOWN'};
   }

}

}
#-------------------------------------------------------------------------
sub checkeventlog {
my %severity_level=(
   1  => "Error",
   2  => "Warning",
);   

# set default values if not specified

# name of log
if (!$the_arguments{'_arg1'}) {
   $the_arguments{'_arg1'}='System';
}

# severity level
if (!exists($severity_level{$the_arguments{'_arg2'}})) {
   $the_arguments{'_arg2'}=1;
}

# numer of past hours to check
if (!$the_arguments{'_arg3'}) {
   $the_arguments{'_arg3'}=1;
}

use DateTime;
# the date and time are stored in GMT in the event log so we need to query it based on that
my $age = DateTime->now(time_zone => 'gmt')->subtract(hours => $the_arguments{'_arg3'});
my $where_time_part="TimeGenerated > \"" . $age->year . sprintf("%02d",$age->month) . sprintf("%02d",$age->day) . sprintf("%02d",$age->hour) . sprintf("%02d",$age->minute) . "00.00000000\""; # for clarity

my @collected_data;
# we have to use a custom regex to find these fields since the individual fields may contain \n themselves which stuffs up the standard regex
my $data_errors=get_multiple_wmi_samples(1,
   "Select SourceName,Message,TimeGenerated from Win32_NTLogEvent where Logfile=\"$the_arguments{'_arg1'}\" and EventType<=$the_arguments{'_arg2'} and EventType>0 and SourceName <> \"Microsoft-Windows-PrintSpooler\" and SourceName <> \"TermServDevices\" and $where_time_part",
   '','(.*?)\|(.*?)\|(.*?)\|(.*?)\|(.*?)\n',\@collected_data,\$the_arguments{'_delay'},undef,0);

if ($data_errors) {
   print "UNKNOWN: Could not retrieve all required data. $data_errors";
   exit $ERRORS{'UNKNOWN'};
} else {

   $collected_data[0][0]{'_SeverityType'}=$severity_level{$the_arguments{'_arg2'}};
   $collected_data[0][0]{'_EventList'}='';

   if ($collected_data[0][0]{'_ItemCount'}>0) {
      $collected_data[0][0]{'_EventList'}=" (List is on next line)\n" . list_collected_values_from_all_rows(\@collected_data,['Logfile','TimeGenerated','SourceName','Message'],"\n",':',0);;
   }

   my $test_result=test_limits($opt_warn,$opt_critical,$collected_data[0][0],\%warn_perf_specs_parsed,\%critical_perf_specs_parsed,\@warn_spec_result_list,\@critical_spec_result_list);
   my ($this_display_info,$this_performance_data,$this_combined_data)=create_display_and_performance_data($collected_data[0][0],$display_fields{$opt_mode},$performance_data_fields{$opt_mode},\%warn_perf_specs_parsed,\%critical_perf_specs_parsed);
   print $this_combined_data;

   #print "$num_events event(s) of severity level '$severity_level{$the_arguments{'_arg2'}}' were recorded in the last $the_arguments{'_arg3'} hours in the $the_arguments{'_arg1'} eventlog.|$performance_data\n$result_text";
   exit $test_result;
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

# these boundary tests have to use > >= etc and no gt ge etc since we want a real number test
# sometimes we get 

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
# pass in a single warn/crit specification
# a hash ref that contains all the possible values we might test against

$debug && print "Testing SPEC: $spec\n";
my $test_result=0;

# we need a warning/critical value for performance data graphs
# for single values it is easy, its just the boundary value specified
# for ranges we use the max of the range - maybe this is not always right
my $perf_data_spec='';

# variable to hold display info on how and what was triggered
my $trigger_display='';

my $field_name='';

if ($spec ne '') {
   my $at_specified='';
   my $min='';
   my $min_multiplier='';
   my $max='';
   my $max_multiplier='';

   my $format_type=0;

   # read the --help/usage page to see how to build a specification
   # this first spec format might look like this
   # FIELD=@1G:2G <-- we are specifically looking for a range here using a colon to separate to values
   if ($spec=~/(.*?)=*(\@*)([0-9+\-\.\~]*)($multiplier_regex*):([0-9+\-\.\~]*)($multiplier_regex*)/i) {
      $field_name=$1 || $valid_test_fields{$opt_mode}[0]; # apply the default field name if none specified
      $at_specified=$2;
      $min=$3;
      $min_multiplier=$4;
      $max=$5;
      $max_multiplier=$6;
      $format_type=1;
      $debug && print "SPEC=$field_name,$2,$3,$4,$5,$6\n";

   # this second spec might look like this
   # FIELD=@1M <--- we are specifically looking for a single value
   } elsif ($spec=~/(.*?)=*(\@*)([0-9+\-\.\~]+)($multiplier_regex*)/i) {
      $field_name=$1 || $valid_test_fields{$opt_mode}[0]; # apply the default field name if none specified
      $at_specified=$2;
      $min=0;
      $min_multiplier='';
      $max=$3;
      $max_multiplier=$4;
      $format_type=2;
      $debug && print "SPEC=$field_name,$2,$3,$4\n";
   } else {
      $debug && print "SPEC format for $spec, not recognised\n";
   }

   # check to see if we got a valid specification
   if ($format_type) {
      $debug && print "Range Spec - $field_name=$at_specified,$min,$min_multiplier,:,$max,$max_multiplier\n";
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
         # the value to test against is the field from the hash
         ($lower_bound_check,$lower_bound_value)=test_single_boundary('<','',$min,$min_multiplier,$$test_value{$field_name});
      }
      
      if ($max eq '') {
         # since max is inifinity no point in checking since result will always be false
         $upper_bound_check=0;
         $upper_bound_value='';
      } else {
         # the value to test against is the field from the hash
         ($upper_bound_check,$upper_bound_value)=test_single_boundary('','',$max,$max_multiplier,$$test_value{$field_name});
      }

      # generate alert if either lower or upper triggered
      if ($lower_bound_check) {
         $test_result=1;
         $trigger_display="$field_name<$min$min_multiplier";
      }
      if ($upper_bound_check) {
         $test_result=1;
         $trigger_display="$field_name>$max$max_multiplier";
      }

      if ($at_specified) {
         # this just reverses the results
         if ($test_result==1) {
            $test_result=0;
            $trigger_display='';
         } else {
            $test_result=1;
            $trigger_display="$field_name in the range $min$min_multiplier:$max$max_multiplier";
         }
         $debug && print "@ specified so reverse the result\n";
      }

      # rewrite the specification taking into account any multipliers
      # this is done so that we can parse consistent and recognisable values in the performance data
      # performance data does not recognise our multiplier system so we have to pre-multiply it 
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

$debug && print "Test Result = $test_result, Perf Spec=$perf_data_spec, Trigger Display=$trigger_display, Field Tested=$field_name\n";
# return the test result, the performance data spec (expanded with any multipliers), a display string of what was triggered and the field name that was used to test against
return $test_result,$perf_data_spec,$trigger_display,$field_name;
}
#-------------------------------------------------------------------------
sub list_collected_values_from_all_rows {
# this is specifically designed for when you have an array that looks like
# ie multiple rows per query results
#$VAR1 = [
#          [
#            {
#              'Name' => 1,
#              'Thing' => 10,
#            }
#            {
#              'Name' => 2,
#              'Thing' => 20,
#            }
#          ],
#          [
#            {
#              'Name' => 3,
#              'Thing' => 30,
#            }
#            {
#              'Name' => 4,
#              'Thing' => 40,
#            }
#          ],
#        ];
# This sub will return something like "1,2,3,4" or if specifying multiple fields
# 1,10
# 2,20
# 3,30
# 4,40
# luckily we have an array like this hanging around - it is the array format returned by
# get_multiple_wmi_samples
my ($values_array,$field_list,$line_delimiter,$field_delimiter,$list_unique)=@_;
# pass in
# the array of values as returned by get_multiple_wmi_samples
# an array of the hash keys you want to look up and list - these get separated by the FIELD DELIMITER
# the LINE delimiter you want to use to list out after listing the defined fields (eg at the end of the line)
# the FIELD delimiter you want to use between fields
# whether you want the list returned with unique values removed - list unique looks at whole rows
my %seen=();
my @list=();
foreach my $result (@{$values_array}) {
   # $result is an array reference to each result
   foreach my $row (@{$result}) {
      # $row is a hash reference to each row for this result
      # now loop through the list of fields wanted
      my @row_field_list=();
      foreach my $field (@{$field_list}) {
         if (exists($$row{$field})) { # it might not exist for example if you found no processes in your search
            # remove any CR or LF from the field as they stuff up the list - replace them with space
            $$row{$field}=~s/\n|\r/ /g;
            push(@row_field_list,$$row{$field});
         }
      }
      
      my $row_string=join($field_delimiter,@row_field_list);

      if ($list_unique) {
         # record the ones we have seen before and count how many of them
         $seen{$row_string}++;
         if ($seen{$row_string}==1) {
            # only add it to the array the first time
            push(@list,$row_string);
         }
      } else {
         # add to the list, preserving order
         push(@list,$row_string); 
      }
   }
}

if ($list_unique) {
   # modify each @list element to include the qty of those found
   # not sure how this will work with multiple fields
   @list=map(list_item_with_qty($_,\%seen),@list);
}
my $string=join($line_delimiter,@list);
return $string;
}
#-------------------------------------------------------------------------
sub list_item_with_qty {
my ($item,$seen_hashref)=@_;
my $qty='';
if ($$seen_hashref{$item}>1) {
   $qty="$$seen_hashref{$item}x";
}
return "$qty $item";
}
#-------------------------------------------------------------------------
sub test_multiple_limits {
# this can be used to test both warning and critical specs
# it takes a list of test values and warn/crit specs and gives you the results of them
# pass in
# a hash reference where we return the parsed specifications (multiplier multiplied up) for performance data
# a hash reference containing all the values we have that we might test against
# an array ref where we return some text telling us about what was triggered
# a hash reference where we return the parsed specifications (multiplier multiplied up) for performance data
my ($perf_specs_parsed,$test_value,$spec_result_list,$spec_list)=@_;
my $count=0;

# initialise the performance spec hash to ensure that we do not see any "Use of uninitialized value" errors if it gets used
# based the initialisation on the possible warn/crit specs defined in %valid_test_fields
foreach my $key (@{$valid_test_fields{$opt_mode}}) {
   $$perf_specs_parsed{$key}='';
}

@{$spec_result_list}=(); # ensure that this array starts empty
foreach my $spec (@{$spec_list}) {
   my ($result,$perf,$display,$test_field)=parse_limits($spec,$test_value);
   # store the performance data in a hash against the test field
   # since this is for performance data we really only want to keep one of the warn/critical specs per test field
   # since this is in a loop we will effectively just keep the last one that was defined
   $$perf_specs_parsed{$test_field}=$perf;
   # store all the information about what was triggered
   push(@{$spec_result_list},$display);
   if ($result>1) {
      print "Critical specification ($spec) not defined correctly\n";
   } elsif ($result==1) {
      $count++;
   }
}

return $count;
}
#-------------------------------------------------------------------------
sub test_limits {
my ($warn_spec_list,$critical_spec_list,$test_value,$warn_perf_specs_parsed,$critical_perf_specs_parsed,$warn_spec_result_list,$critical_spec_result_list)=@_;
# pass in
# an array containing the list of warn specifications
# an array containing the list of critical specifications
# a hash reference containing all the values we have that we might test against
# a hash reference where we return the parsed specifications (multiplier multiplied up) for performance data for warnings
# a hash reference where we return the parsed specifications (multiplier multiplied up) for performance data for criticals
# an array ref where we return some text telling us about what was triggered for warnings
# an array ref where we return some text telling us about what was triggered for criticals

# eg $test_value = {
#          '_Free%' => '99.4',
#          'VolumeName' => 'Temp Disk 2',
#          '_UsedSpace' => 13383680,
#          '_FreeGB' => '1.98',
# and $warn_spec_list = [
#          '1:',
#          ':2',
#          '3'

# most of this stuff we pass in just gets passed off to test_multiple_limits
# we call test_multiple_limits twice, once for warnings and once for criticals

$debug && print "Testing TEST VALUES " . Dumper($test_value);
$debug && print "WARNING SPECS: " . Dumper($warn_spec_list);
$debug && print "CRITICAL SPECS: " . Dumper($critical_spec_list);

# assume it is ok unless we find otherwise
my $test_result=$ERRORS{'OK'};

$debug && print "------------ Critical Check ------------\n";
my $critical_count=test_multiple_limits($critical_perf_specs_parsed,$test_value,$critical_spec_result_list,$critical_spec_list);

$debug && print "------------ Warning Check ------------\n";
my $warn_count=test_multiple_limits($warn_perf_specs_parsed,$test_value,$warn_spec_result_list,$warn_spec_list);

$debug && print "------------ End Check ------------\n";

# determine the result type, and load up some other values that can be used for display etc
if ($critical_count>0) {
   $test_result=$ERRORS{'CRITICAL'};
   $$test_value{'_StatusType'}='CRITICAL';
   $$test_value{'_Triggers'}='[Triggered by ' . join(',',grep(/.+/,@{$critical_spec_result_list})) . ']';
   $$test_value{'_DisplayMsg'}="$$test_value{'_StatusType'} - $$test_value{'_Triggers'}";
} elsif ($warn_count>0) {
   $test_result=$ERRORS{'WARNING'};
   $$test_value{'_StatusType'}='WARNING';
   $$test_value{'_Triggers'}='[Triggered by ' . join(',',grep(/.+/,@{$warn_spec_result_list})) . ']';
   $$test_value{'_DisplayMsg'}="$$test_value{'_StatusType'} - $$test_value{'_Triggers'}";
} else {
   $test_result=$ERRORS{'OK'};
   $$test_value{'_StatusType'}='OK';
   $$test_value{'_Triggers'}='';
   $$test_value{'_DisplayMsg'}="$$test_value{'_StatusType'}";
}
# only show this debug if there was any warn or crit specs
if ($#$critical_spec_list>=0 || $#$warn_spec_list>=0) {
   $debug && print "Test Results:\nWarn Perf Specs=" . Dumper($warn_perf_specs_parsed) . "Warn Results=" . Dumper($warn_spec_result_list) . "Critical Perf Spec=" . Dumper($critical_perf_specs_parsed) . "Critical Results=" . Dumper($critical_spec_result_list);
}
$debug && print "Data Passed back from check: " . Dumper($test_value);
return $test_result;
}
##-------------------------------------------------------------------------
#sub initialise_perf_specs {
## initialise a performance spec hash to ensure that we do not see any "Use of uninitialized value" errors if it gets used
## pass in 
## the hash to initialise
## the hash to copy from (but we make the values all '');
#my ($spec_hashref,$test_value)=@_;
#foreach my $key (keys %{$test_value}) {
#   $$spec_hashref{$key}='';
#}
#
#}
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

