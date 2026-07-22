#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/usb/IOUSBHostFamilyDefinitions.h>
#import <IOKit/usb/USBSpec.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static const int YTYubicoVendorID = 0x1050;

struct YTYubiKeyMonitor {
    pthread_mutex_t lock;
    IONotificationPortRef notificationPort;
    io_iterator_t addedIterator;
    io_iterator_t removedIterator;
    dispatch_queue_t queue;
    bool queueAttached;
    int writeFD;
    int count;
    int status;
    bool closed;
};

static CFMutableDictionaryRef YTYubiKeyMatchingDictionary(void) {
    CFMutableDictionaryRef matching = IOServiceMatching(kIOUSBHostDeviceClassName);
    if (matching == NULL) {
        return NULL;
    }
    int vendorID = YTYubicoVendorID;
    CFNumberRef vendor = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &vendorID);
    if (vendor == NULL) {
        CFRelease(matching);
        return NULL;
    }
    CFDictionarySetValue(matching, CFSTR(kUSBVendorID), vendor);
    CFRelease(vendor);
    return matching;
}

int YTCountYubiKeys(int *count) {
    if (count == NULL) {
        return kIOReturnBadArgument;
    }
    CFMutableDictionaryRef matching = YTYubiKeyMatchingDictionary();
    if (matching == NULL) {
        return kIOReturnNoMemory;
    }
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t status = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (status != KERN_SUCCESS) {
        return status;
    }
    int found = 0;
    io_service_t service;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        found++;
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    *count = found;
    return KERN_SUCCESS;
}

static void YTSignalMonitor(struct YTYubiKeyMonitor *monitor) {
    char signal = 1;
    ssize_t result;
    do {
        result = write(monitor->writeFD, &signal, sizeof(signal));
    } while (result < 0 && errno == EINTR);
}

static void YTRefreshMonitor(struct YTYubiKeyMonitor *monitor) {
    int count = 0;
    int status = YTCountYubiKeys(&count);
    bool changed = false;
    pthread_mutex_lock(&monitor->lock);
    if (!monitor->closed && (monitor->status != status || (status == KERN_SUCCESS && monitor->count != count))) {
        monitor->status = status;
        monitor->count = count;
        changed = true;
    }
    pthread_mutex_unlock(&monitor->lock);
    if (changed) {
        YTSignalMonitor(monitor);
    }
}

static void YTDrainDeviceNotifications(void *context, io_iterator_t iterator) {
    io_service_t service;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        IOObjectRelease(service);
    }
    YTRefreshMonitor((struct YTYubiKeyMonitor *)context);
}

static void YTDestroyMonitorResources(struct YTYubiKeyMonitor *monitor) {
    if (monitor->notificationPort != NULL && monitor->queueAttached) {
        IONotificationPortSetDispatchQueue(monitor->notificationPort, NULL);
        monitor->queueAttached = false;
    }
    if (monitor->queue != NULL) {
        dispatch_sync(monitor->queue, ^{});
    }
    if (monitor->addedIterator != IO_OBJECT_NULL) {
        IOObjectRelease(monitor->addedIterator);
        monitor->addedIterator = IO_OBJECT_NULL;
    }
    if (monitor->removedIterator != IO_OBJECT_NULL) {
        IOObjectRelease(monitor->removedIterator);
        monitor->removedIterator = IO_OBJECT_NULL;
    }
    if (monitor->notificationPort != NULL) {
        IONotificationPortDestroy(monitor->notificationPort);
        monitor->notificationPort = NULL;
    }
    if (monitor->queue != NULL) {
        dispatch_release(monitor->queue);
        monitor->queue = NULL;
    }
    if (monitor->writeFD >= 0) {
        close(monitor->writeFD);
        monitor->writeFD = -1;
    }
}

struct YTYubiKeyMonitor *YTCreateYubiKeyMonitor(int *readFD, int *count, int *status) {
    if (readFD == NULL || count == NULL || status == NULL) {
        if (status != NULL) {
            *status = kIOReturnBadArgument;
        }
        return NULL;
    }
    *readFD = -1;
    *count = 0;
    *status = KERN_SUCCESS;

    struct YTYubiKeyMonitor *monitor = calloc(1, sizeof(struct YTYubiKeyMonitor));
    if (monitor == NULL) {
        *status = kIOReturnNoMemory;
        return NULL;
    }
    monitor->writeFD = -1;
    monitor->count = 0;
    monitor->status = KERN_SUCCESS;
    if (pthread_mutex_init(&monitor->lock, NULL) != 0) {
        *status = kIOReturnNoResources;
        free(monitor);
        return NULL;
    }

    int descriptors[2];
    if (pipe(descriptors) != 0) {
        *status = errno;
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }
    *readFD = descriptors[0];
    monitor->writeFD = descriptors[1];
    int readFlags = fcntl(descriptors[0], F_GETFD);
    int writeFlags = fcntl(descriptors[1], F_GETFD);
    int statusFlags = fcntl(descriptors[1], F_GETFL);
    if (readFlags < 0 || writeFlags < 0 || statusFlags < 0 ||
        fcntl(descriptors[0], F_SETFD, readFlags | FD_CLOEXEC) < 0 ||
        fcntl(descriptors[1], F_SETFD, writeFlags | FD_CLOEXEC) < 0 ||
        fcntl(descriptors[1], F_SETFL, statusFlags | O_NONBLOCK) < 0) {
        *status = errno;
        close(descriptors[0]);
        close(descriptors[1]);
        monitor->writeFD = -1;
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }

    monitor->notificationPort = IONotificationPortCreate(kIOMainPortDefault);
    monitor->queue = dispatch_queue_create("com.github.mofelee.yubitouch.usb", DISPATCH_QUEUE_SERIAL);
    if (monitor->notificationPort == NULL || monitor->queue == NULL) {
        *status = kIOReturnNoResources;
        close(descriptors[0]);
        YTDestroyMonitorResources(monitor);
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }

    // Arm both iterators before taking the initial snapshot. The dispatch queue
    // is attached last so startup hotplug notifications cannot race that snapshot.
    CFMutableDictionaryRef removedMatching = YTYubiKeyMatchingDictionary();
    if (removedMatching == NULL) {
        *status = kIOReturnNoMemory;
        close(descriptors[0]);
        YTDestroyMonitorResources(monitor);
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }
    kern_return_t result = IOServiceAddMatchingNotification(
        monitor->notificationPort,
        kIOTerminatedNotification,
        removedMatching,
        YTDrainDeviceNotifications,
        monitor,
        &monitor->removedIterator
    );
    if (result != KERN_SUCCESS) {
        *status = result;
        close(descriptors[0]);
        YTDestroyMonitorResources(monitor);
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }
    io_service_t service;
    while ((service = IOIteratorNext(monitor->removedIterator)) != IO_OBJECT_NULL) {
        IOObjectRelease(service);
    }

    CFMutableDictionaryRef addedMatching = YTYubiKeyMatchingDictionary();
    if (addedMatching == NULL) {
        *status = kIOReturnNoMemory;
        close(descriptors[0]);
        YTDestroyMonitorResources(monitor);
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }
    result = IOServiceAddMatchingNotification(
        monitor->notificationPort,
        kIOFirstMatchNotification,
        addedMatching,
        YTDrainDeviceNotifications,
        monitor,
        &monitor->addedIterator
    );
    if (result != KERN_SUCCESS) {
        *status = result;
        close(descriptors[0]);
        YTDestroyMonitorResources(monitor);
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }
    while ((service = IOIteratorNext(monitor->addedIterator)) != IO_OBJECT_NULL) {
        IOObjectRelease(service);
    }

    result = YTCountYubiKeys(&monitor->count);
    monitor->status = result;
    if (result != KERN_SUCCESS) {
        *status = result;
        close(descriptors[0]);
        YTDestroyMonitorResources(monitor);
        pthread_mutex_destroy(&monitor->lock);
        free(monitor);
        return NULL;
    }
    *count = monitor->count;
    IONotificationPortSetDispatchQueue(monitor->notificationPort, monitor->queue);
    monitor->queueAttached = true;
    return monitor;
}

int YTYubiKeyMonitorSnapshot(struct YTYubiKeyMonitor *monitor, int *count) {
    if (monitor == NULL || count == NULL) {
        return kIOReturnBadArgument;
    }
    pthread_mutex_lock(&monitor->lock);
    int status = monitor->closed ? kIOReturnNotOpen : monitor->status;
    *count = monitor->count;
    pthread_mutex_unlock(&monitor->lock);
    return status;
}

void YTDestroyYubiKeyMonitor(struct YTYubiKeyMonitor *monitor) {
    if (monitor == NULL) {
        return;
    }
    pthread_mutex_lock(&monitor->lock);
    monitor->closed = true;
    pthread_mutex_unlock(&monitor->lock);
    YTDestroyMonitorResources(monitor);
    pthread_mutex_destroy(&monitor->lock);
    free(monitor);
}
