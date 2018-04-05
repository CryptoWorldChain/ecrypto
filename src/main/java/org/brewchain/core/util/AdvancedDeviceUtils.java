package org.brewchain.core.util;

import java.net.URL;

import org.brewchain.core.config.SystemProperties;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;

public class AdvancedDeviceUtils {

    public static void adjustDetailedTracing(SystemProperties config, long blockNum) {
        // here we can turn on the detail tracing in the middle of the chain
        if (blockNum >= config.traceStartBlock() && config.traceStartBlock() != -1) {
            final URL configFile = ClassLoader.getSystemResource("logback-detailed.xml");
            final LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
            final ContextInitializer ci = new ContextInitializer(loggerContext);

            loggerContext.reset();
            try {
                ci.configureByResource(configFile);
            } catch (Exception e) {
                System.out.println("Error applying new config " + e.getMessage());
            }
        }
    }
}
