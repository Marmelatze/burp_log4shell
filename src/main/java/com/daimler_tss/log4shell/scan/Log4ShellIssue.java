package com.daimler_tss.log4shell.scan;

import burp.IBurpCollaboratorInteraction;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import com.daimler_tss.log4shell.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.URL;
import java.util.Base64;
import java.util.List;

public class Log4ShellIssue implements IScanIssue
{
    private static final Logger logger = LoggerFactory.getLogger(Log4ShellIssue.class);

    private URL url;
    private IHttpService httpService;
    private IHttpRequestResponse[] httpMessages;
    private List<IBurpCollaboratorInteraction> interactions;

    public Log4ShellIssue(
        URL url,
        IHttpService httpService,
        IHttpRequestResponse[] httpMessages,
        List<IBurpCollaboratorInteraction> interactions)
    {
        this.url = url;
        this.httpService = httpService;
        this.httpMessages = httpMessages;
        this.interactions = interactions;
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
        StringBuilder message = new StringBuilder(
            "The application appears to be running a version of log4j vulnerable to RCE. Burp sent a reference to an external file, and received a pingback from the server.<br/><br/>" +
                "To investigate, use the manual collaborator client. It may be possible to escalate this vulnerability into RCE. Please refer to https://www.lunasec.io/docs/blog/log4j-zero-day/ for further information")
            ;
        if (null != interactions && !interactions.isEmpty()) {
            message.append("<br/><br/>");
            for (IBurpCollaboratorInteraction interaction : interactions) {
                message.append(String.format(
                    "A %s interaction with the collaborator client was recorded from %s:<br/>",
                    interaction.getProperty("type"),
                    interaction.getProperty("client_ip")
                ));

                try {
                    byte[] query = Utilities.helpers.base64Decode(interaction.getProperty("raw_query"));
                    String decodedDetail = new String(Utilities.helpers.base64Decode(interaction.getProperty("raw_query")));
                    String domain = interaction.getProperty("interaction_id");
                    if (query[4] == 0 && query[5] == 1) {
                        int length = query[12];
                        String subdomain = decodedDetail.substring(13, 13 + length);
                        if (!subdomain.equals(domain)) {
                            domain = decodedDetail.substring(13, 13+length) + "." + interaction.getProperty("interaction_id");
                        }
                    }
                    message
                        .append("<pre>")
                        .append(domain)
                        .append("</pre>");
                }
                catch (Exception e) {
                    logger.error("Failed to decode interaction", e);
                }
                message.append("<br /><br />");
            }
        }

        return message.toString();
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
