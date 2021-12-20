package com.daimler_tss.log4shell;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class Utilities
{
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    public Utilities(IBurpExtenderCallbacks icallbacks)
    {
        callbacks = icallbacks;
        helpers = callbacks.getHelpers();
    }

    public static String getHeader(byte[] request, String header) {
        int[] offsets = getHeaderOffsets(request, header);

        return helpers.bytesToString(Arrays.copyOfRange(request, offsets[1], offsets[2]));
    }

    public static int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ' ') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }

            String header_str = helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }
        }
        return null;
    }
}
