package com.daimler_tss.log4shell.scan;

import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.net.URL;

public class Log4ShellTimeoutIssue extends Log4ShellIssue
{
    public Log4ShellTimeoutIssue(URL url, IHttpService httpService, IHttpRequestResponse[] httpMessages)
    {
        super(url, httpService, httpMessages, null);
    }

    @Override
    public String getConfidence()
    {
        return "Tentative";
    }

    @Override
    public String getIssueName()
    {
        return super.getIssueName() + " (Timeout)";
    }

    @Override
    public String getIssueDetail()
    {
        return "The first request timed out, but the second request with an invalid payload was successful.";
    }
}
