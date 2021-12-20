package com.daimler_tss.log4shell;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

public class Utilities
{
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    public Utilities(IBurpExtenderCallbacks icallbacks)
    {
        callbacks = icallbacks;
        helpers = callbacks.getHelpers();
    }
}
