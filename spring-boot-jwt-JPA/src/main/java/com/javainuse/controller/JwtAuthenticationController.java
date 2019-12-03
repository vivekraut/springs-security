package com.javainuse.controller;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import com.javainuse.service.JwtUserDetailsService;

//import ecryptiondecryption.AESenc;

import com.javainuse.config.JwtTokenUtil;
import com.javainuse.model.JwtRequest;
import com.javainuse.model.JwtResponse;
import com.javainuse.model.UserDTO;

@RestController
@CrossOrigin
public class JwtAuthenticationController {
	
	private static final String TOKEN = "passwd";
	private String salt;
	private int pwdIterations = 65536;
	private int keySize = 256;
	private byte[] ivBytes;
	private String keyAlgorithm = "AES";
	private String encryptAlgorithm = "AES/CBC/PKCS5Padding";
	private String secretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA1";

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private JwtUserDetailsService userDetailsService;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {
		
		//AESenc decryptPwd = new AESenc();
		//String decryptedString = decrypt(authenticationRequest.getPassword());
		//System.out.println("Decrypted Password::"+decryptedString);
		System.out.println("Username::"+authenticationRequest.getUsername());
		System.out.println("Username::"+authenticationRequest.getPassword());

		authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
		
		final UserDetails userDetails = userDetailsService
				.loadUserByUsername(authenticationRequest.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);

		return ResponseEntity.ok(new JwtResponse(token));
	}
	
	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<?> saveUser(@RequestBody UserDTO user) throws Exception {
		return ResponseEntity.ok(userDetailsService.save(user));
	}

	private void authenticate(String username, String password) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
	
	/**
	 * 
	 * @param encryptText
	 * @return decrypted text
	 * @throws Exception
	 */
	public String decrypt(String encryptText) throws Exception {
		
		byte[] ciphertext = DatatypeConverter.parseBase64Binary(encryptText);
        if (ciphertext.length < 48) {
            return null;
        }
        byte[] salt = Arrays.copyOfRange(ciphertext, 0, 16);
        byte[] iv = Arrays.copyOfRange(ciphertext, 16, 32);
        byte[] ct = Arrays.copyOfRange(ciphertext, 32, ciphertext.length);
        
        
		//byte[] saltBytes = getSalt().getBytes("UTF-8");
		//byte[] encryptTextBytes = new Base64().decode(encryptText);
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance(this.secretKeyFactoryAlgorithm);
		PBEKeySpec spec = new PBEKeySpec(TOKEN.toCharArray(), salt, this.pwdIterations, this.keySize);
		SecretKey secretKey = skf.generateSecret(spec);
		SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), keyAlgorithm);
		
		//decrypt the message
		Cipher cipher = Cipher.getInstance(encryptAlgorithm);
		//ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		//byte[] plaintext = cipher.doFinal(ct);
		
		//byte[] decyrptTextBytes = null;
		byte[] plaintext = null;
		try {
			plaintext = cipher.doFinal(ct);
			//decyrptTextBytes = cipher.doFinal(encryptTextBytes);
		} catch (IllegalBlockSizeException e) {
			// TODO: handle exception
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		String text = new String(plaintext,"UTF-8");
		return text;
	}
	
	private String getSalt(){
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[20];
		random.nextBytes(bytes);
		String text = new String(bytes);
		return text;
	}
}