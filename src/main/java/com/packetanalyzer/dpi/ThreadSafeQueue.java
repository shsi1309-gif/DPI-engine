package com.packetanalyzer.dpi;

import java.util.ArrayDeque;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

final class ThreadSafeQueue<T> {
    private static final int DEFAULT_MAX_SIZE = 10_000;

    private final Queue<T> queue = new ArrayDeque<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Condition notFull = lock.newCondition();
    private final int maxSize;
    private boolean shutdown;

    ThreadSafeQueue() {
        this(DEFAULT_MAX_SIZE);
    }

    ThreadSafeQueue(int maxSize) {
        if (maxSize <= 0) {
            throw new IllegalArgumentException("maxSize must be positive");
        }
        this.maxSize = maxSize;
    }

    void push(T item) throws InterruptedException {
        lock.lock();
        try {
            while (queue.size() >= maxSize && !shutdown) {
                notFull.await();
            }
            if (shutdown) {
                return;
            }
            queue.add(item);
            notEmpty.signal();
        } finally {
            lock.unlock();
        }
    }

    boolean tryPush(T item) {
        lock.lock();
        try {
            if (queue.size() >= maxSize || shutdown) {
                return false;
            }
            queue.add(item);
            notEmpty.signal();
            return true;
        } finally {
            lock.unlock();
        }
    }

    Optional<T> pop() throws InterruptedException {
        lock.lock();
        try {
            while (queue.isEmpty() && !shutdown) {
                notEmpty.await();
            }
            if (queue.isEmpty()) {
                return Optional.empty();
            }
            T item = queue.remove();
            notFull.signal();
            return Optional.of(item);
        } finally {
            lock.unlock();
        }
    }

    Optional<T> popWithTimeout(long timeout, TimeUnit unit) throws InterruptedException {
        long nanos = unit.toNanos(timeout);
        lock.lock();
        try {
            while (queue.isEmpty() && !shutdown) {
                if (nanos <= 0L) {
                    return Optional.empty();
                }
                nanos = notEmpty.awaitNanos(nanos);
            }
            if (queue.isEmpty()) {
                return Optional.empty();
            }
            T item = queue.remove();
            notFull.signal();
            return Optional.of(item);
        } finally {
            lock.unlock();
        }
    }

    boolean empty() {
        lock.lock();
        try {
            return queue.isEmpty();
        } finally {
            lock.unlock();
        }
    }

    int size() {
        lock.lock();
        try {
            return queue.size();
        } finally {
            lock.unlock();
        }
    }

    void shutdown() {
        lock.lock();
        try {
            shutdown = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    boolean isShutdown() {
        lock.lock();
        try {
            return shutdown;
        } finally {
            lock.unlock();
        }
    }
}
