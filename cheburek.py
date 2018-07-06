from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.io import PrintWriter
import re
import json
import httplib

base_url = 'haveibeenpwned.com'

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Cheburek")

        # handle output

        self._stdout = PrintWriter(callbacks.getStdout(), True)

        self._stdout.println("Hello 1337")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response): 
        str_response = self._helpers.bytesToString(response)
        regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                    "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                    "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
        emails = re.findall(regex, str_response)
        for email in emails:
            self._stdout.println('Found {}'.format(email[0]))
        return emails


    def _get_pointer(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def _do_online_check(self, email):
        headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0'}
        connect = httplib.HTTPSConnection(base_url)
        connect.request('GET', '/api/v2/unifiedsearch/{}'.format(email), headers = headers)
        response = connect.getresponse()
        if response.status == 200:
            html = response.read()
            self._stdout.println('OK!')
            jresp = json.loads(html)
            rez_info = ''
            for br in jresp['Breaches']:
                rez_li = ''
                for li in br['DataClasses']:
                    rez_li = '{}<li>{}</li>'.format(rez_li,li)
                rez_info = '{}<br>{} ({})<br><ul>{}</ul>'.format(rez_info, br['Title'],br['BreachDate'],rez_li)
            return rez_info
        if response.status == 404:
            self._stdout.println('Nothing :(')
            return 0


    # helper that do a request to https://haveibeenpwned.com/
    def _check_email(self, email):
        self._stdout.println('Let\'s check {}'.format(email))
        info = self._do_online_check(email)
        issue = ''
        if info:
            issue = self._reportIssue(email, info)
        return issue


    def _reportIssue(self, email, info):
        issue = CustomScanIssue(
            self._baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(self._baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(self._baseRequestResponse, None, self._get_pointer(self._baseRequestResponse.getResponse(), bytearray(email, 'utf8')))],
            "Potentially compromised account",
            "Email address <b>{}</b> potentially has been compromised in a data breach<br><br>{}".format(email,info),
            "Information")
        return issue


    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        self._baseRequestResponse = baseRequestResponse
        # look for matches of our passive check grep string
        matches = self._get_matches(self._baseRequestResponse.getResponse())
        issues = []
        if (len(matches) == 0):
            return None
        else:
            for email in matches:
                issue = self._check_email(email[0])
                if issue:
                    issues.append(issue)

        # report the issue
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService