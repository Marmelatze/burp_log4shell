package com.daimler_tss.log4shell.scan;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class Log4ShellIssue implements IScanIssue
{

    private URL url;
    private IHttpService httpService;
    private IHttpRequestResponse[] httpMessages;

    public Log4ShellIssue(URL url, IHttpService httpService, IHttpRequestResponse[] httpMessages)
    {
        this.url = url;
        this.httpService = httpService;
        this.httpMessages = httpMessages;
    }

    @Override
    public URL getUrl()
    {
        return this.url;
    }

    @Override
    public String getIssueName()
    {
        return "Log4Shell (CVE-2021-44228)";
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return "High";
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return "The application appears to be running a version of log4j vulnerable to RCE. Burp sent a reference to an external file, and received a pingback from the server.<br/><br/>" +
            "To investigate, use the manual collaborator client. It may be possible to escalate this vulnerability into RCE. Please refer to https://www.lunasec.io/docs/blog/log4j-zero-day/ for further information";
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return this.httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return this.httpService;
    }
}
