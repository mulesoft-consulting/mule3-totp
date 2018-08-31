#TOTP Transformer for Mule 3
Used to generate a time based, one time use token that is compatible with the Google Authenticator Application and similar applications.

Useful for implementing a two-factor authentication scheme.

To validate a token, define this dependency in the pom.xml file:

```
<dependency>
	<groupId>org.totp</groupId>
	<artifactId>totp</artifactId>
	<version>1.0.0</version>
</dependency>
```

Then use the **validate** operation in the flow where token validation is to be done. For example:

```
        <custom-transformer class="org.totp.TOTP" doc:name="TOTP">
            <spring:property name="enabled" value="${totp.enabled}"/>
            <spring:property name="operation" value="validate"/>
            <spring:property name="key" value="${totp.key}"/>
            <spring:property name="totpPropertyName" value="${totp.property}"/>
        </custom-transformer>
```

A totp token can be generated using the **generate** operation. The token will be returned in the payload.

Use **enabled** set to false if you wish to skip the token validate.

**key** is required parameter value. It is the same key entered into the Google Authenicator application on you mobile device.

**totpPropertyName** will default to "edit_token".