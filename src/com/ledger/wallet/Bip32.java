/*
*******************************************************************************    
*   Java Card Bitcoin Hardware Wallet
*   (c) 2015 Ledger
*   
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU Affero General Public License as
*   published by the Free Software Foundation, either version 3 of the
*   License, or (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU Affero General Public License for more details.
*
*   You should have received a copy of the GNU Affero General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*******************************************************************************   
*/    

package com.ledger.wallet;

import javacard.framework.Util;
import javacard.security.Signature;

public class Bip32 {
	
	protected static final short OFFSET_DERIVATION_INDEX = (short)64;
	
	private static final byte BITCOIN_SEED[] = {
		'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'
	};
	
	private static final short OFFSET_TMP = (short)100;	
	private static final short OFFSET_BLOCK = (short)127;
	 /**
	  * @param seedLength  种子长度
	  *
	  * masterDerived =  主私钥 + 主链码
	  * **/
    // seed : scratch, offset 0 -> result in masterDerived 
    // keyHmac was duplicated because
	// depending on the implementation, if a native transient HMAC is used, the key size might be fixed
	// on the first call
	// if that's the case, power cycle / deselect between initial seed derivation and all other key derivations
	// would solve it
	public static void deriveSeed(byte seedLength) {
		if (Crypto.signatureHmac != null) {
			// 初始化HMACKey以 BITCOIN_SEED字节数组做key
			Crypto.keyHmac2.setKey(BITCOIN_SEED, (short)0, (short)BITCOIN_SEED.length);
			if ((LedgerWalletApplet.proprietaryAPI != null) && (LedgerWalletApplet.proprietaryAPI.hasHmacSHA512())) {
				LedgerWalletApplet.proprietaryAPI.hmacSHA512(Crypto.keyHmac2, LedgerWalletApplet.scratch256, (short)0, seedLength, LedgerWalletApplet.masterDerived, (short)0);
			}
			else {
				// 用初始化HMACKey初始化对象Signature
				Crypto.signatureHmac.init(Crypto.keyHmac2, Signature.MODE_SIGN);
				Crypto.signatureHmac.sign(LedgerWalletApplet.scratch256, (short)0, seedLength, LedgerWalletApplet.masterDerived, (short)0);
			}
		}
		else {
			HmacSha512.hmac(BITCOIN_SEED, (short)0, (short)BITCOIN_SEED.length, LedgerWalletApplet.scratch256, (short)0, seedLength, LedgerWalletApplet.masterDerived, (short)0, LedgerWalletApplet.scratch256, (short)64);
		}
	}
	
	// scratch255 : 0-64 : key + chain / 64-67 : derivation index / 100-165 : tmp
	// apduBuffer : block (128, starting at 127)
	// result : scratch255 0-64  contains  Key and chain code
	public static boolean derive(byte[] apduBuffer) {
		boolean isZero = true;
		byte i;
		if ((LedgerWalletApplet.scratch256[OFFSET_DERIVATION_INDEX] & (byte)0x80) == 0) { // 普通衍生 data = 33字节 compressedPublicKey
			if (LedgerWalletApplet.proprietaryAPI != null) {
				LedgerWalletApplet.proprietaryAPI.getUncompressedPublicPoint(LedgerWalletApplet.scratch256, (short)0, LedgerWalletApplet.scratch256, OFFSET_TMP);				
			}
			else {				
				if (!Bip32Cache.copyLastPublic(LedgerWalletApplet.scratch256, OFFSET_TMP)) {
					return false;
				}
			}
			AddressUtils.compressPublicKey(LedgerWalletApplet.scratch256, OFFSET_TMP);
		}
		else { // 硬衍生 data = (0x00 + pri(32字节)) 33字节data
			LedgerWalletApplet.scratch256[OFFSET_TMP] = 0;
			Util.arrayCopyNonAtomic(LedgerWalletApplet.scratch256, (short)0, LedgerWalletApplet.scratch256, (short)(OFFSET_TMP + 1), (short)32);
		}
		Util.arrayCopyNonAtomic(LedgerWalletApplet.scratch256, OFFSET_DERIVATION_INDEX, LedgerWalletApplet.scratch256, (short)(OFFSET_TMP + 33), (short)4);
		if (Crypto.signatureHmac != null) {
			/***
			 * void setKey(byte[] keyData,
			 *           short kOff,
			 *           short kLen)
			 *             throws CryptoException,
			 *                    NullPointerException,
			 *                    ArrayIndexOutOfBoundsException
			 * Sets the Key data. The data format is big-endian and right-aligned (the least significant bit is the least significant bit of last byte). Input key data is copied into the internal representation.
			 * Note:
			 *
			 * If the key object implements the javacardx.crypto.KeyEncryption interface and the Cipher object specified via setKeyCipher() is not null, keyData is decrypted using the Cipher object.
			 * Parameters:
			 * keyData - byte array containing key initialization data
			 * kOff - offset within keyData to start
			 * kLen - the byte length of the key initialization data
			 * Throws:
			 * CryptoException - with the following reason code:
			 * CryptoException.ILLEGAL_VALUE if the kLen parameter is 0 or invalid or if the keyData parameter is inconsistent with the key length or if input data decryption is required and fails.
			 * ArrayIndexOutOfBoundsException - if kOff is negative or the keyData array is too short
			 * NullPointerException - if the keyData parameter is null
			 * */
			Crypto.keyHmac.setKey(LedgerWalletApplet.scratch256, (short)32, (short)32); // 以chinCode作为key
			if ((LedgerWalletApplet.proprietaryAPI != null) && (LedgerWalletApplet.proprietaryAPI.hasHmacSHA512())) {
				LedgerWalletApplet.proprietaryAPI.hmacSHA512(Crypto.keyHmac, LedgerWalletApplet.scratch256, OFFSET_TMP, (short)37, LedgerWalletApplet.scratch256, OFFSET_TMP);
			}
			else {
				/***
				 * public abstract void init(Key theKey,
				 *         byte theMode)
				 *                    throws CryptoException
				 * Initializes the Signature object with the appropriate Key. This method should be used for algorithms which do not need initialization parameters or use default parameter values.
				 * init() must be used to update the Signature object with a new key. If the Key object is modified after invoking the init() method, the behavior of the update(), sign(), and verify() methods is unspecified.
				 *
				 * The Key is checked for consistency with the Signature algorithm. For example, the key type must be matched. For elliptic curve algorithms, the key must represent a valid point on the curve's domain parameters. Additional key component/domain parameter strength checks are implementation specific.
				 *
				 * Note:
				 *
				 * AES, DES, triple DES, and Korean SEED algorithms in CBC mode will use 0 for initial vector(IV) if this method is used.
				 * RSA algorithms using the padding scheme PKCS1_PSS will use a default salt length equal to the length of the message digest.
				 * For optimal performance, when the theKey parameter is a transient key, the implementation should, whenever possible, use transient space for internal storage.
				 * Parameters:
				 * theKey - the key object to use for signing or verifying
				 * theMode - one of MODE_SIGN or MODE_VERIFY
				 * Throws:
				 * CryptoException - with the following reason codes:
				 * CryptoException.ILLEGAL_VALUE if theMode option is an undefined value or if the Key is inconsistent with theMode or with the Signature implementation.
				 * CryptoException.UNINITIALIZED_KEY if theKey instance is uninitialized.
				 *
				 * */
				Crypto.signatureHmac.init(Crypto.keyHmac, Signature.MODE_SIGN);
				/***
				 * public abstract short sign(byte[] inBuff,
				 *          short inOffset,
				 *          short inLength,
				 *          byte[] sigBuff,
				 *          short sigOffset)
				 *                     throws CryptoException
				 * Generates the signature of all/last input data.
				 * A call to this method also resets this Signature object to the state it was in when previously initialized via a call to init(). That is, the object is reset and available to sign another message. In addition, note that the initial vector(IV) used in AES, DES and Korean SEED algorithms in CBC mode will be reset to 0.
				 *
				 * Note:
				 *
				 * AES, DES, triple DES, and Korean SEED algorithms in CBC mode reset the initial vector(IV) to 0. The initial vector(IV) can be re-initialized using the init(Key, byte, byte[], short, short) method.
				 * The input and output buffer data may overlap.
				 *
				 * In addition to returning a short result, this method sets the result in an internal state which can be rechecked using assertion methods of the SensitiveResult class, if supported by the platform.
				 *
				 * Parameters:
				 * inBuff - the input buffer of data to be signed
				 * inOffset - the offset into the input buffer at which to begin signature generation
				 * inLength - the byte length to sign
				 * sigBuff - the output buffer to store signature data
				 * sigOffset - the offset into sigBuff at which to begin signature data
				 * Returns:
				 * number of bytes of signature output in sigBuff
				 * Throws:
				 * CryptoException - with the following reason codes:
				 * CryptoException.UNINITIALIZED_KEY if key not initialized.
				 * CryptoException.INVALID_INIT if this Signature object is not initialized or initialized for signature verify mode.
				 * CryptoException.ILLEGAL_USE if one of the following conditions is met:
				 * if this Signature algorithm does not pad the message and the message is not block aligned.
				 * if this Signature algorithm does not pad the message and no input data has been provided in inBuff or via the update() method.
				 * if the message value is not supported by the Signature algorithm or if a message value consistency check failed.
				 * if this Signature algorithm includes message recovery functionality.
				 * */
				Crypto.signatureHmac.sign(LedgerWalletApplet.scratch256, OFFSET_TMP, (short)37, LedgerWalletApplet.scratch256, OFFSET_TMP); // 37 = 33（data） + 4(index)
			}
		}
		else {
			HmacSha512.hmac(LedgerWalletApplet.scratch256, (short)32, (short)32, LedgerWalletApplet.scratch256, OFFSET_TMP, (short)37, LedgerWalletApplet.scratch256, OFFSET_TMP, apduBuffer, OFFSET_BLOCK);
		}
		if (MathMod256.ucmp(LedgerWalletApplet.scratch256, OFFSET_TMP, Secp256k1.SECP256K1_R, (short)0) >= 0) { // 合法私钥 应该小于SECP256K1_R即平常所说的n
			return false;
		}
		// 子私钥 ki = (parse256(IL) + kpar) (mod n)
		MathMod256.addm(LedgerWalletApplet.scratch256, (short)0, LedgerWalletApplet.scratch256, OFFSET_TMP, LedgerWalletApplet.scratch256, (short)0, Secp256k1.SECP256K1_R, (short)0);
		// ki不能为0
		for (i=0; i<(byte)32; i++) {
			if (LedgerWalletApplet.scratch256[i] != 0) {
				isZero = false;
				break;
			}
		}
		if (isZero) {
			return false;
		}
		Util.arrayCopyNonAtomic(LedgerWalletApplet.scratch256, (short)(OFFSET_TMP + 32), LedgerWalletApplet.scratch256, (short)32, (short)32);		
		return true;
	}

}
