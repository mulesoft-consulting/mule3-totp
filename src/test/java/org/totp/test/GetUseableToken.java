package org.totp.test;

import static org.junit.Assert.*;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import org.totp.TOTP;

public class GetUseableToken {
	String key = "a_shared_secret";
	String algorithm = "HmacSHA1";

	@Test
	public void getToken() {
		long now = (new DateTime(DateTimeZone.UTC)).getMillis();
		String totp = TOTP.generateTOTP(key, now, algorithm);
		System.out.println(totp);
	}

}
