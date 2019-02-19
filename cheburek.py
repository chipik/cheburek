from javax.swing import BoxLayout, JPanel, JTextField, JLabel, JCheckBox, Box, JOptionPane, JButton
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.awt import Dimension
from array import array
import subprocess
import httplib
import shlex
import json
import re


class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    base_url = "haveibeenpwned.com"
    cmd = "ssh dl-adm query_email ~emailhere~"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # set our extension name
        callbacks.setExtensionName("Cheburek")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stdout.println("Hello 1337")

        # add the custom tab to Burp's UI
        self.confCommand = self._callbacks.loadExtensionSetting("cheburek.command") or self.cmd

        saved_haveibeenpwnd = self._callbacks.loadExtensionSetting("cheburek.haveibeenpwnd")
        if saved_haveibeenpwnd == "True":
            self.confHaveIBeenPwnd = True
        elif saved_haveibeenpwnd == "False":
            self.confHaveIBeenPwnd = False
        else:
            self.confHaveIBeenPwnd = bool(int(saved_haveibeenpwnd or True))
        saved_localcheck = self._callbacks.loadExtensionSetting("cheburek.localcheck")

        if saved_localcheck == "True":
            self.confLocalCheck = True
        elif saved_localcheck == "False":
            self.confLocalCheck = False
        else:
            self.confLocalCheck = bool(int(saved_localcheck or False))

        callbacks.addSuiteTab(self)
        self.applyConfig()
        callbacks.registerScannerCheck(self)

    def applyConfig(self):
        self._callbacks.saveExtensionSetting("cheburek.command", self.confCommand)
        self._callbacks.saveExtensionSetting("cheburek.haveibeenpwnd", str(int(self.confHaveIBeenPwnd)))
        self._callbacks.saveExtensionSetting("cheburek.localcheck", str(int(self.confLocalCheck)))

    ### ITab ###
    def getTabCaption(self):
        return "Cheburek"

    def applyConfigUI(self, event):
        self.confCommand = self.uiCommand.getText()
        self.confHaveIBeenPwnd = self.uiHaveIBeenPwnd.isSelected()
        self.confLocalCheck = self.uiLocalCheck.isSelected()
        self.applyConfig()

    def resetConfigUI(self, event):
        self.uiCommand.setText(self.confCommand)
        self.uiHaveIBeenPwnd.setSelected(self.confHaveIBeenPwnd)
        self.uiLocalCheck.setSelected(self.confLocalCheck)

    def getUiComponent(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.PAGE_AXIS))

        self.uiCommandLine = JPanel()
        self.uiCommandLine.setLayout(BoxLayout(self.uiCommandLine, BoxLayout.LINE_AXIS))
        self.uiCommandLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        self.uiCommandLine.add(JLabel("Command line for local search: "))
        self.uiCommand = JTextField(40)
        self.uiCommand.setMaximumSize(self.uiCommand.getPreferredSize())
        self.uiCommandLine.add(self.uiCommand)
        self.panel.add(self.uiCommandLine)

        uiOptionsLine = JPanel()
        uiOptionsLine.setLayout(BoxLayout(uiOptionsLine, BoxLayout.LINE_AXIS))
        uiOptionsLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        self.uiHaveIBeenPwnd = JCheckBox("haveibeenpwned")
        uiOptionsLine.add(self.uiHaveIBeenPwnd)
        uiOptionsLine.add(Box.createRigidArea(Dimension(10, 0)))

        self.uiLocalCheck = JCheckBox("Local check")
        uiOptionsLine.add(self.uiLocalCheck)
        uiOptionsLine.add(Box.createRigidArea(Dimension(10, 0)))
        self.panel.add(uiOptionsLine)
        self.panel.add(Box.createRigidArea(Dimension(0, 10)))

        uiButtonsLine = JPanel()
        uiButtonsLine.setLayout(BoxLayout(uiButtonsLine, BoxLayout.LINE_AXIS))
        uiButtonsLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        uiButtonsLine.add(JButton("Apply", actionPerformed=self.applyConfigUI))
        uiButtonsLine.add(JButton("Reset", actionPerformed=self.resetConfigUI))
        self.panel.add(uiButtonsLine)

        self.uiAbout = JPanel()
        self.uiAbout.setLayout(BoxLayout(self.uiAbout, BoxLayout.LINE_AXIS))
        self.uiAbout.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        self.uiAbout.add(JLabel("<html><a href=\"https://twitter.com/_chipik\">https://twitter.com/_chipik</a></html>"))
        self.panel.add(self.uiAbout)

        self.resetConfigUI(None)
        return self.panel

    # END ITAB

    def _get_matches(self, response):
        str_response = self._helpers.bytesToString(response)
        # best regex winner :)
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

    # helper that do a request to https://haveibeenpwned.com/
    def _do_online_check(self, email):
        headers = {
            'User-Agent': 'Chebuzilla/5.0 (Chebuntosh; Intel Cheb-OS-Rek 13.37; rv:59.0) ChebuGeko/20100101 Cheburefox/1337.0'}
        connect = httplib.HTTPSConnection(self.base_url)
        connect.request('GET', '/api/v2/breachedaccount/{}'.format(email), headers=headers)
        response = connect.getresponse()
        if response.status == 200:
            html = response.read()
            self._stdout.println('Got {}. Status = {}'.format(email, response.status))
            jresp = json.loads(html)
            rez_info = ''
            for br in jresp['Breaches']:
                rez_li = ''
                for li in br['DataClasses']:
                    rez_li = '{}<li>{}</li>'.format(rez_li, li)
                rez_info = '{}<br>{} ({})<br><ul>{}</ul>'.format(rez_info, br['Title'], br['BreachDate'], rez_li)
            return rez_info
        if response.status == 404:
            self._stdout.println('Nothing :( Status = {}'.format(response.status))
        if response.status == 403:
            self._stdout.println('API request was blocked. Status = {}'.format(response.status))
        return 0

    # helper that do a local search
    def _do_local_check(self, email):
        self._stdout.println("Checking local db for {}".format(email))
        try:
            cmd = self.confCommand.replace("~emailhere~", email)
            self._stdout.println("Exec:{}".format(cmd))
            returned_output = subprocess.check_output(shlex.split(cmd))
            self._stdout.println("Result: {}".format(returned_output))
            returned_output = "Breached passwords:<br><br>{}".format(returned_output).replace('\n', '<br>')
        except subprocess.CalledProcessError:
            self._stdout.println("Nothing found locally for {}".format(email))
            returned_output = ''
        return returned_output

    def _check_email(self, email):
        self._stdout.println('Let\'s check {}'.format(email))
        info = info2 = issue = ''
        if self.confHaveIBeenPwnd:
            info = self._do_online_check(email)
        if self.confLocalCheck:
            info2 = self._do_local_check(email)
        if info or info2:
            issue = self._reportIssue(email, info + info2)
        return issue

    def _reportIssue(self, email, info):
        issue = CustomScanIssue(
            self._baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(self._baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(self._baseRequestResponse, None,
                                          self._get_pointer(self._baseRequestResponse.getResponse(),
                                                            bytearray(email, 'utf8')))],
            "Potentially compromised account",
            "Email address <b>{}</b> potentially has been compromised in a data breach<br><br>{}".format(email, info),
            "Information")
        return issue

    def doPassiveScan(self, baseRequestResponse):
        self._baseRequestResponse = baseRequestResponse
        matches = self._get_matches(self._baseRequestResponse.getResponse())
        issues = []
        if (len(matches) == 0):
            return None
        else:
            for email in matches:
                issue = self._check_email(email[0])
                if issue:
                    issues.append(issue)
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0


class CustomScanIssue(IScanIssue):
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
