package com.daimler_tss.log4shell;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class InsertionPointProvider implements IScannerInsertionPointProvider
{
    private static final Logger logger = LoggerFactory.getLogger(InsertionPointProvider.class);

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse iHttpRequestResponse)
    {
        try {
            IRequestInfo requestInfo = Utilities.helpers.analyzeRequest(iHttpRequestResponse.getRequest());
            List<String> headers = requestInfo.getHeaders();
            ArrayList<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
            for (String header : headers) {
                String[] split = header.split(":", 2);
                if (split.length != 2) {
                    continue;
                }
                String name = split[0].trim();
                if (name.equalsIgnoreCase("User-Agent") || name.equalsIgnoreCase("Referer")) {
                    continue;
                }
                String value = split[1].trim();
                HeaderInsertionPoint headerInsertionPoint = new HeaderInsertionPoint(
                    name,
                    value,
                    iHttpRequestResponse.getRequest()
                );
                insertionPoints.add(headerInsertionPoint);
            }
            return insertionPoints;
        } catch (Exception e) {
            logger.error("Error while getting insertion points", e);
        }

        return Collections.emptyList();
    }
}
