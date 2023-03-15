package com.github.justincranford.spring.model.user;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.beans.factory.ObjectFactory;

public record Uptime(long nanos, float micros, float millis, float secs) {

    public static class Factory implements ObjectFactory<Uptime> {
    	private final Instant start;
    	public Factory(final Instant start) {
    		this.start = start;
    	}
    	public Uptime getObject() {
    		final Duration duration = Duration.between(this.start, Instant.now(Clock.systemUTC()));
			final long  nanos  = duration.toNanos();
			final float micros = nanos / 1000F;
			final float millis = nanos / 1000000F;
			final float secs   = nanos / 1000000000F;
    		return new Uptime(nanos, micros, millis, secs);
    	}
    }
}