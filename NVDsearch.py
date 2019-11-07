# Search the NVE service offered by NIST (National Institute of Standards and Technology of U.S. Department of Commerce)
# (https://nvd.nist.gov/search)
import webbrowser
from robot.api.deco import keyword

searchURL = "https://nvd.nist.gov/vuln/search/"

@keyword(name='Search from NVD database')
def searchVulnerabilitiesFromBrowser(searchterm):
    """Opens up a new default browser instance with the desired CVE search and statistics on separate tabs"""
    if not isinstance(searchterm, str):
        raise TypeError("Given searchterm is not a string, it is " + str(type(searchterm)))
    vulnURL = searchURL + "/statistics?" + "form_type=Basic" + "&results_type=statistics" + \
            "&query=" + searchterm + "&search_type=all"
    statisticsURL = searchURL + "/results?" + "form_type=Basic" + "&results_type=overview" + \
            "&query=" + searchterm + "&search_type=all"
    webbrowser.open(vulnURL, 0, True) # Open new raised browser instance with given search
    webbrowser.open(statisticsURL, 1, True)
    return
