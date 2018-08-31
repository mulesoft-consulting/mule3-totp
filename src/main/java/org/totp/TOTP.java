package org.totp;

/**
 * 
 * Reference Implementation of RFC6238 modified to be used as a Mule Transform component
 * 
 * Copyright (c) 2011 IETF Trust and the persons identified as
 * authors of the code. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted pursuant to, and subject to the license
 * terms contained in, the Simplified BSD License set forth in Section
 * 4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
 * (http://trustee.ietf.org/license-info).
 */

import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.mule.api.MuleMessage;
import org.mule.api.transformer.TransformerException;
import org.mule.config.i18n.MessageFactory;
import org.mule.transformer.AbstractMessageTransformer;

/**
 * This is an example implementation of the OATH TOTP algorithm. Visit
 * www.openauthentication.org for more information.
 * 
 * pdd: Modified to be used as a Mule Transform component
 * 
 * @author Johan Rydell, PortWise, Inc.
 */
public class TOTP extends AbstractMessageTransformer {
	public static long SecondsOfResolution = 10;

	// validate or generate
	private String operation = "generate";
	private String key = null;
	private String resultClass = null;
	private String algorithm = "HmacSHA1";
	private String totpPropertyName = "edit_token";
	private boolean enabled = true;

	public String getOperation() {
		return operation;
	}

	public void setOperation(String operation) {
		this.operation = operation.trim().toLowerCase();
	}

	public String getResultClass() {
		return resultClass;
	}

	public void setResultClass(String resultClass) {
		this.resultClass = resultClass;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key.trim();
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getTotpPropertyName() {
		return totpPropertyName;
	}

	public void setTotpPropertyName(String totpPropertyName) {
		this.totpPropertyName = totpPropertyName;
	}

	@Override
	public Object transformMessage(MuleMessage message, String encoding)
			throws TransformerException {

		if (enabled == false) {
			return message.getPayload();
		}
		if (operation == null || operation.isEmpty()) {
			throw new TransformerException(
					MessageFactory
							.createStaticMessage("Missing operation"));
		}
		if (key == null || key.isEmpty()) {
			throw new TransformerException(
					MessageFactory
							.createStaticMessage("Empty key"));
		}
        String normalizedBase32Key = key.replace(" ", "").toUpperCase();
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(normalizedBase32Key);
        String hexKey = Hex.encodeHexString(bytes);
		try {
			if (operation.equalsIgnoreCase("generate")) {
		        long time = (System.currentTimeMillis() / 1000) / 30;
		        String hexTime = Long.toHexString(time);
		        message.setOutboundProperty(totpPropertyName, TOTP.generateTOTP(hexKey, hexTime, "6"));
				return message.getPayload();
			} else if (operation.equalsIgnoreCase("validate")) {
		        long time = (System.currentTimeMillis() / 1000) / 30;
		        String hexTime = Long.toHexString(time);
		        String totp = TOTP.generateTOTP(hexKey, hexTime, "6");
				String inbound_totp = message.getInboundProperty(totpPropertyName);
				if (inbound_totp == null || inbound_totp.isEmpty()) {
					throw new TransformerException(
							MessageFactory
									.createStaticMessage("Empty token"));
				}
				if (totp.equals(inbound_totp)) {
					return message.getPayload();
				} else {
					throw new TransformerException(
							MessageFactory
									.createStaticMessage("Invalid token"));
				}
			} else {
				throw new TransformerException(
						MessageFactory
								.createStaticMessage("Missing operation"));
			}
		} catch (TransformerException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new TransformerException(
					MessageFactory.createStaticMessage("transformMessage caught Exception: "
							+ e.toString()), e);
		}
	}

	/**
	 * This method uses the JCE to provide the crypto algorithm. HMAC computes a
	 * Hashed Message Authentication Code with the crypto hash algorithm as a
	 * parameter.
	 * 
	 * @param crypto
	 *            : the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
	 * @param keyBytes
	 *            : the bytes to use for the HMAC key
	 * @param text
	 *            : the message or text to be authenticated
	 */

	private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {
		try {
			Mac hmac;
			hmac = Mac.getInstance(crypto);
			SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
			hmac.init(macKey);
			return hmac.doFinal(text);
		} catch (GeneralSecurityException gse) {
			throw new UndeclaredThrowableException(gse);
		}
	}

	/**
	 * This method converts a HEX string to Byte[]
	 * 
	 * @param hex
	 *            : the HEX string
	 * 
	 * @return: a byte array
	 */

	private static byte[] hexStr2Bytes(String hex) {
		// Adding one byte to get the right conversion
		// Values starting with "0" can be converted
		byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

		// Copy all the REAL bytes, not the "first"
		byte[] ret = new byte[bArray.length - 1];
		for (int i = 0; i < ret.length; i++)
			ret[i] = bArray[i + 1];
		return ret;
	}

	private static final int[] DIGITS_POWER
	// 0 1 2 3 4 5 6 7 8
	= { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 * 
	 * @param key
	 *            : the shared secret, HEX encoded
	 * @param time
	 *            : a value that reflects a time
	 * @param returnDigits
	 *            : number of digits to return
	 * 
	 * @return: a numeric String in base 10 that includes
	 *          {@link truncationDigits} digits
	 */

	public static String generateTOTP(String key, String time,
			String returnDigits) {
		return generateTOTP(key, time, returnDigits, "HmacSHA1");
	}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 * 
	 * @param key
	 *            : the shared secret, HEX encoded
	 * @param time
	 *            : a value that reflects a time
	 * @param returnDigits
	 *            : number of digits to return
	 * 
	 * @return: a numeric String in base 10 that includes
	 *          {@link truncationDigits} digits
	 */

	public static String generateTOTP256(String key, String time,
			String returnDigits) {
		return generateTOTP(key, time, returnDigits, "HmacSHA256");
	}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 * 
	 * @param key
	 *            : the shared secret, HEX encoded
	 * @param time
	 *            : a value that reflects a time
	 * @param returnDigits
	 *            : number of digits to return
	 * 
	 * @return: a numeric String in base 10 that includes
	 *          {@link truncationDigits} digits
	 */

	public static String generateTOTP512(String key, String time,
			String returnDigits) {
		return generateTOTP(key, time, returnDigits, "HmacSHA512");
	}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 * 
	 * @param key
	 *            : the shared secret, HEX encoded
	 * @param time
	 *            : a value that reflects a time
	 * @param returnDigits
	 *            : number of digits to return
	 * @param crypto
	 *            : the crypto function to use
	 * 
	 * @return: a numeric String in base 10 that includes
	 *          {@link truncationDigits} digits
	 */

	public static String generateTOTP(String key, String time,
			String returnDigits, String crypto) {
		int codeDigits = Integer.decode(returnDigits).intValue();
		String result = null;

		// Using the counter
		// First 8 bytes are for the movingFactor
		// Compliant with base RFC 4226 (HOTP)
		while (time.length() < 16)
			time = "0" + time;

		// Get the HEX in a Byte[]
		byte[] msg = hexStr2Bytes(time);
		byte[] k = hexStr2Bytes(key);
		byte[] hash = hmac_sha(crypto, k, msg);

		// put selected bytes into result int
		int offset = hash[hash.length - 1] & 0xf;

		int binary = ((hash[offset] & 0x7f) << 24)
				| ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

		int otp = binary % DIGITS_POWER[codeDigits];

		result = Integer.toString(otp);
		while (result.length() < codeDigits) {
			result = "0" + result;
		}
		return result;
	}

	public static String generateTOTP(String key, long timeNow, String crypto) {
		final int codeDigits = 8;

		String result = null;
		String time = String.format("%1$-11s",
				(timeNow / (1000 * SecondsOfResolution)));

		// Using the counter
		// First 8 bytes are for the movingFactor
		// Compliant with base RFC 4226 (HOTP)
		while (time.length() < 16)
			time = "0" + time;

		// Get the HEX in a Byte[]
		byte[] hash = hmac_sha(crypto, key.getBytes(), time.getBytes());

		// put selected bytes into result int
		int offset = hash[hash.length - 1] & 0xf;

		int binary = ((hash[offset] & 0x7f) << 24)
				| ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

		int otp = binary % DIGITS_POWER[codeDigits];

		result = Integer.toString(otp);
		while (result.length() < codeDigits) {
			result = "0" + result;
		}
		return result;
	}

}
