/*
 * Copyright (c) 2015 Yadieet SA <qts19bit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * Chipid File Encryption Decryption v1.1.0
 * Created by yadieet on 10/07/15.
 */
package yadieet;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;

public final class Chipid
{
	private Chipid()
	{
	}

	//private static BCECPublicKey publicKey;
	//private static BCECPrivateKey privateKey;

	private static final void createKeyPair( final String path ) throws Throwable
	{
		{
			final File pathF = new File(path).getAbsoluteFile();
			if( !(pathF.exists() && pathF.isDirectory() && pathF.canWrite()) )
				throw new RuntimeException("Invalid path.");
		}

		final KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
		final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
		kpGen.initialize(ecSpec, new SecureRandom());
		final KeyPair keyPair = kpGen.generateKeyPair();
		final BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
		final BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();

		try
			(
				ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path + "/puk"))
			)
		{
			oos.writeObject(publicKey);
		}

		try
			(
				ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path + "/pik"))
			)
		{
			oos.writeObject(privateKey);
		}
		System.out.println("Output directory: " + path);
	}

	private static final Key loadKey( final boolean isPuk, final String path ) throws Throwable
	{
		if( isPuk )
		{
			final File puk = new File(path).getAbsoluteFile();
			if( !(puk.exists() && puk.canRead()) )
				throw new RuntimeException("Invalid path.");
			try
				(
					ObjectInputStream ois = new ObjectInputStream(new FileInputStream(puk))
				)
			{
				return (Key) ois.readObject();
			}
		}

		final File pik = new File(path).getAbsoluteFile();
		if( !(pik.exists() && pik.canRead()) )
			throw new RuntimeException("Invalid path.");

		try
			(
				ObjectInputStream ois = new ObjectInputStream(new FileInputStream(pik))
			)
		{
			return (Key) ois.readObject();
		}

	}

	private static final void encryptFile( final BCECPublicKey publicKey, final String in, final String out, int bs ) throws Throwable
	{
		final File inFile = new File(in).getAbsoluteFile();
		if( !(inFile.exists() && inFile.canRead()) )
			throw new RuntimeException("Invalid input file.");
		final File outFile = new File(out).getAbsoluteFile();
		{
			final File parent = outFile.getParentFile();
			if( !(parent.exists() && parent.isDirectory() && parent.canWrite()) )
				throw new RuntimeException("Invalid output file");
		}

		final byte[] derivation = Hex.decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f");
		final byte[] encoding = Hex.decode("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");

		final IESParameterSpec params = new IESParameterSpec(derivation, encoding, 512, 256);
		final Cipher cipher1 = Cipher.getInstance("ECIESwithAES-CBC", "BC");
		cipher1.init(Cipher.ENCRYPT_MODE, publicKey, params, new SecureRandom());

		final int blocksize = cipher1.getBlockSize();
		final int maxread = bs;
		//final int maxread = 8388608;
		//System.out.println(cipher1.getOutputSize(maxread));
		if( (maxread % blocksize) != 0 )
			throw new RuntimeException("Please change maxread");

		try
			(
				FileInputStream fis = new FileInputStream(inFile);
				FileOutputStream fos = new FileOutputStream(outFile)
			)
		{
			int a, i, ii;
			final byte[] inbuffer = new byte[maxread];
			//final byte[] outbuffer = new byte[2097321];
			final byte[] outbuffer = new byte[maxread + 169];
			final long filesize = inFile.length();
			long tt = 0;
			while( (a = fis.available()) > 0 )
			{
				if( a > maxread )
					a = maxread;
				i = fis.read(inbuffer, 0, a);
				ii = cipher1.doFinal(inbuffer, 0, i, outbuffer);
				//System.out.print(ii+ " ");
				fos.write(outbuffer, 0, ii);
				tt += i;
				System.out.print((long) Math.floor((tt / (double) filesize) * 100) + "% ");
			}
		}
		System.out.println();
		System.out.println("Output: " + outFile);
	}

	private static final void decryptFile( final BCECPrivateKey privateKey, final String in, final String out, int bs ) throws Throwable
	{
		final File inFile = new File(in).getAbsoluteFile();
		if( !(inFile.exists() && inFile.canRead()) )
			throw new RuntimeException("Invalid input file.");
		final File outFile = new File(out).getAbsoluteFile();
		{
			final File parent = outFile.getParentFile();
			if( !(parent.exists() && parent.isDirectory() && parent.canWrite()) )
				throw new RuntimeException("Invalid output file");
		}

		final byte[] derivation = Hex.decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f");
		final byte[] encoding = Hex.decode("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");

		final IESParameterSpec params = new IESParameterSpec(derivation, encoding, 512, 256);
		final Cipher cipher2 = Cipher.getInstance("ECIESwithAES-CBC", "BC");
		cipher2.init(Cipher.DECRYPT_MODE, privateKey, params, new SecureRandom());

		try
			(
				FileInputStream fis = new FileInputStream(inFile);
				FileOutputStream fos = new FileOutputStream(outFile)
			)
		{
			int a, i, ii;
			final int maxread = bs + 169;
			final byte[] inbuffer = new byte[maxread];
			final byte[] outbuffer = new byte[bs];
			final long filesize = inFile.length();
			long tt = 0;
			while( (a = fis.available()) > 0 )
			{
				if( a > maxread )
					a = maxread;
				i = fis.read(inbuffer, 0, a);
				ii = cipher2.doFinal(inbuffer, 0, i, outbuffer);
				fos.write(outbuffer, 0, ii);
				tt += i;
				System.out.print((long) Math.floor((tt / (double) filesize) * 100) + "% ");
			}
		}
		System.out.println();
		System.out.println("Output: " + outFile);
	}

	public static void main( final String... args )
	{
		try
		{
			Security.addProvider(new BouncyCastleProvider());

			if( args.length == 0 )
				System.out.println("by yadieet sa <yadieet@gmail.com>");
			else if( (args.length == 1) && "test".equals(args[0]) )
				test();
			else if( (args.length == 2) && "create".equals(args[0]) )
				createKeyPair(args[1]);
			else if( args.length == 4 )
			{
				if( "decrypt".equals(args[0]) )
					decryptFile((BCECPrivateKey) loadKey(false, args[1]), args[2], args[3], 2097152);
				else if( "encrypt".equals(args[0]) )
					encryptFile((BCECPublicKey) loadKey(true, args[1]), args[2], args[3], 2097152);
			}
			else if( args.length == 5 )
			{
				int bs;

				try
				{
					bs = Integer.parseInt(args[4]) * 1048576;
				}
				catch( NumberFormatException nbe )
				{
					System.out.println("Invalid arguments..");
					return;
				}
				
				if( bs < 1048576 )
					bs = 1048576;

				if( "decrypt".equals(args[0]) )
					decryptFile((BCECPrivateKey) loadKey(false, args[1]), args[2], args[3], bs);
				else if( "encrypt".equals(args[0]) )
					encryptFile((BCECPublicKey) loadKey(true, args[1]), args[2], args[3], bs);
			}
			else
				System.out.println("Invalid arguments..");
		}
		catch( final Throwable throwable )
		{
			throwable.printStackTrace();
		}
	}

	private static void test() throws Throwable
	{
		createKeyPair("/tmp");
		final BCECPublicKey publicKey = (BCECPublicKey) loadKey(true, "/tmp/puk");
		encryptFile(publicKey, "/tmp/in.bin", "/tmp/out.bin", 2097152);
		final BCECPrivateKey privateKey = (BCECPrivateKey) loadKey(false, "/tmp/pik");
		decryptFile(privateKey, "/tmp/out.bin", "/tmp/in2.bin", 2097152);
	}
}
