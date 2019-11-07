***Settings***
Library         ./NVDsearch.py

***Variables***
${TARGET}       Modbus

***Test Cases***
MyTestCase1                        
    Search and display vulnerabilities

***Keywords***
Search and display vulnerabilities
    [Documentation]     Runs online search for vulnerabilities with given parameter.
    ...                 Opens website with two tabs, one for the search and one for statistics on that search.
    #[Arguments]         $(target)
    #searchVulnerabilitiesFromBrowser    ${TARGET}
    Search from NVD database             ${TARGET}

