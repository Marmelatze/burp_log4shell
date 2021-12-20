package com.daimler_tss.log4shell;

import burp.IScannerInsertionPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class HeaderInsertionPoint implements IScannerInsertionPoint
{
    private static final Logger logger = LoggerFactory.getLogger(HeaderInsertionPoint.class);

    private String name;
    private String value;
    private byte[] request;
    private final int[] headerOffsets;

    public HeaderInsertionPoint(String name, String value, byte[] request)
    {
        this.name = name;
        this.value = value;
        this.request = request;

        this.headerOffsets = Utilities.getHeaderOffsets(request, name);
    }

    @Override
    public String getInsertionPointName()
    {
        return name;
    }

    @Override
    public String getBaseValue()
    {
        return value;
    }

    @Override
    public byte[] buildRequest(byte[] bytes)
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(Arrays.copyOfRange(this.request, 0, this.headerOffsets[1]));
            outputStream.write(bytes);
            outputStream.write(Arrays.copyOfRange(this.request, this.headerOffsets[2], this.request.length));

            return outputStream.toByteArray();
        } catch (IOException e) {
            logger.error("Failed to create request", e);
            return new byte[0];
        }
    }

    @Override
    public int[] getPayloadOffsets(byte[] bytes)
    {
        return new int[]{this.headerOffsets[1], this.headerOffsets[1]+bytes.length};
    }

    @Override
    public byte getInsertionPointType()
    {
        return IScannerInsertionPoint.INS_HEADER;
    }
}
