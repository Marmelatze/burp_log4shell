package com.daimler_tss.log4shell.logappender;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;

import java.io.OutputStream;
import java.io.PrintWriter;

public class BurpLogAppender extends OutputStreamAppender<ILoggingEvent>
{
    private PrintWriter outputWriter;

    public BurpLogAppender(OutputStream os)
    {
        setOutputStream(os);
    }



}
