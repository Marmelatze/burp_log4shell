package burp;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import com.daimler_tss.log4shell.logappender.BurpLogAppender;
import com.daimler_tss.log4shell.scan.Log4ShellScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BurpExtender implements IBurpExtender
{
    private static Logger logger;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("Offsec Log4Shell (" + getClass().getPackage().getImplementationVersion() + ")");

        // configure logging
        LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
        ch.qos.logback.classic.Logger rootLogger = lc.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
        BurpLogAppender appender = new BurpLogAppender(callbacks.getStdout());
        appender.setOutputStream(callbacks.getStdout());
        appender.setContext(lc);
        PatternLayoutEncoder pl = new PatternLayoutEncoder();
        pl.setContext(lc);
        pl.setPattern("%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n");
        pl.start();
        appender.setEncoder(pl);

        appender.start();

        rootLogger.detachAppender("console");
        rootLogger.addAppender(appender);
        logger = LoggerFactory.getLogger(BurpExtender.class);
        logger.info("Starting Log4Shell extension");

        callbacks.registerScannerCheck(new Log4ShellScan(callbacks, logger));
    }
}
