package org.brewchain.core.crypto.jni;

import java.lang.reflect.Field;

public class IPPCrypto {
	public native void init();

	public native void genKeys(byte[]seed,byte[] pk, byte[] x, byte[] y);

	public native boolean fromPrikey(byte[] pk, byte[] x, byte[] y);

	public native boolean signMessage(byte[] pk, byte[] x, byte[] y, byte[] text, byte[] s, byte[] v);

	public native boolean verifyMessage(byte[] x, byte[] y, byte[] text, byte[] s, byte[] v);

	public static void loadLibrary() throws Throwable {
		loadLibrary(null);
	}

	/**
	 * Sets the java library path to the specified path
	 *
	 * @param path
	 *            the new library path
	 * @throws Exception
	 */
	public static void setLibraryPath(String path) throws Exception {
		System.setProperty("java.library.path", path);
		// set sys_paths to null
		final Field sysPathsField = ClassLoader.class.getDeclaredField("sys_paths");
		sysPathsField.setAccessible(true);
		sysPathsField.set(null, null);
	}

	public static void loadLibrary(String path) throws Throwable {
		if (path == null) {
			path = "./clib";
		}
		String libpath = System.getProperty("java.library.path");
		libpath = libpath + ":" + path;
		setLibraryPath(libpath);
		System.out.println("libpath=" + libpath);
		System.loadLibrary("ippcwv");
	}
}
