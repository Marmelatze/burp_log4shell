package com.daimler_tss.log4shell;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class EarlyHttpRequestResponse implements IHttpRequestResponse
{
    private IHttpService httpService;
    private byte[] request;

    public EarlyHttpRequestResponse(IHttpService httpService, byte[] request)
    {
        this.httpService = httpService;
        this.request = request;
    }

    @Override
    public byte[] getRequest()
    {
        return this.request;
    }

    @Override
    public void setRequest(byte[] bytes)
    {

    }

    @Override
    public byte[] getResponse()
    {
        return null;
    }

    @Override
    public void setResponse(byte[] bytes)
    {

    }

    @Override
    public String getComment()
    {
        return "";
    }

    @Override
    public void setComment(String s)
    {

    }

    @Override
    public String getHighlight()
    {
        return "";
    }

    @Override
    public void setHighlight(String s)
    {

    }

    @Override
    public IHttpService getHttpService()
    {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService iHttpService)
    {

    }
}
