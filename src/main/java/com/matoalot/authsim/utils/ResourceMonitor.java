package com.matoalot.authsim.utils;

import com.sun.management.OperatingSystemMXBean;

import java.lang.management.ManagementFactory;

public class ResourceMonitor {
    private static long usedMemoryMB;
    private static long lastLoggedMemoryTime;
    private static int cpuLoadPercentage;
    private static long lastLoggedCPULoadTime;


    /*
     * Returns the used memory in MB.
     */
    public static long getUsedMemoryMB() {

        // Throttle memory logging to once per second.
        if (System.currentTimeMillis() - lastLoggedMemoryTime > 1000) {
            lastLoggedMemoryTime = System.currentTimeMillis();
            // Get memory usage in bytes.
            Runtime runtime = Runtime.getRuntime();
            long totalMemory = runtime.totalMemory();
            long freeMemory = runtime.freeMemory();

            usedMemoryMB = (totalMemory - freeMemory)/(1024 * 1024);
        }

        return usedMemoryMB;
    }

    /*
     * Returns the CPU load percentage.
     */
    public static int getCPULoadPercentage() {

        // throttle CPU load logging to once per second.
        if (System.currentTimeMillis() - lastLoggedCPULoadTime > 1000) {
            lastLoggedCPULoadTime = System.currentTimeMillis();
            OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            double CPUload = osBean.getProcessCpuLoad();
            cpuLoadPercentage = (int) (CPUload * 100); // Convert to percentage.
        }

        return cpuLoadPercentage;
    }
}
