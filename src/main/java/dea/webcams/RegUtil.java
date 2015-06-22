package dea.webcams;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Registry updater derived from post http://stackoverflow.com/questions/62289
 * /read-write-to-windows-registry-using-java
 * 
 * @author dea
 * 
 */
public class RegUtil {
	protected static final Logger log = LoggerFactory.getLogger(RegUtil.class);

	private static final int HKEY_LOCAL_MACHINE = 0x80000002;
	private static final int REG_SUCCESS = 0;
	private static final int REG_ACCESSDENIED = 5;
	private static final String PREF_KEY = "SOFTWARE\\Perspective Software\\Blue Iris\\Cameras";

	private static final int KEY_WOW64_32KEY = 0x0200;
	private static final int KEY_WOW64_64KEY = 0x0100;
	private static int reg = 0;

	private static final int KEY_ALL_ACCESS = 0xf003f;

	private static final int KEY_READ = 0x20019;
	private static Preferences userRoot = Preferences.userRoot();
	private static Preferences systemRoot = Preferences.systemRoot();
	private static Class<? extends Preferences> userClass = userRoot.getClass();
	private static Method regOpenKey = null;
	private static Method regCloseKey = null;
	private static Method regQueryValueEx = null;
	private static Method regQueryInfoKey = null;
	private static Method regEnumKeyEx = null;
	private static Method regSetValueEx = null;

	static {
		try {
			regOpenKey = userClass.getDeclaredMethod("WindowsRegOpenKey",
					new Class[] { int.class, byte[].class, int.class });
			regOpenKey.setAccessible(true);
			regCloseKey = userClass.getDeclaredMethod("WindowsRegCloseKey",
					new Class[] { int.class });
			regCloseKey.setAccessible(true);
			regQueryValueEx = userClass.getDeclaredMethod(
					"WindowsRegQueryValueEx", new Class[] { int.class,
							byte[].class });
			regQueryValueEx.setAccessible(true);
			regQueryInfoKey = userClass.getDeclaredMethod(
					"WindowsRegQueryInfoKey1", new Class[] { int.class });
			regQueryInfoKey.setAccessible(true);
			regEnumKeyEx = userClass.getDeclaredMethod("WindowsRegEnumKeyEx",
					new Class[] { int.class, int.class, int.class });
			regEnumKeyEx.setAccessible(true);
			regSetValueEx = userClass.getDeclaredMethod("WindowsRegSetValueEx",
					new Class[] { int.class, byte[].class, byte[].class });
			regSetValueEx.setAccessible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static List<String> readStringSubKeys(Preferences root, int hkey,
			String key, int wow64) throws IllegalArgumentException,
			IllegalAccessException, InvocationTargetException {
		List<String> results = new ArrayList<String>();
		int[] handles = (int[]) regOpenKey
				.invoke(root, new Object[] { new Integer(hkey), toCstr(key),
						new Integer(KEY_READ | wow64) });

		if (handles[1] == REG_ACCESSDENIED) {
			return null;
		}
		if (handles[1] != REG_SUCCESS) {
			return null;
		}
		int[] info = (int[]) regQueryInfoKey.invoke(root,
				new Object[] { new Integer(handles[0]) });

		int count = info[0];
		int maxlen = info[3]; // value length max
		for (int index = 0; index < count; index++) {
			byte[] name = (byte[]) regEnumKeyEx.invoke(root, new Object[] {
					new Integer(handles[0]), new Integer(index),
					new Integer(maxlen + 1) });
			results.add(new String(name).trim());
		}
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
		return results;
	}

	private static void writeStringValue(Preferences root, int hkey,
			String key, String valueName, String value, int wow64)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		int[] handles = (int[]) regOpenKey.invoke(root, new Object[] {
				new Integer(hkey), toCstr(key),
				new Integer(KEY_ALL_ACCESS | wow64) });
		regSetValueEx.invoke(root, new Object[] { new Integer(handles[0]),
				toCstr(valueName), toCstr(value) });
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
	}

	private static String readString(Preferences root, int hkey, String key,
			String value, int wow64) throws IllegalArgumentException,
			IllegalAccessException, InvocationTargetException {
		int[] handles = (int[]) regOpenKey
				.invoke(root, new Object[] { new Integer(hkey), toCstr(key),
						new Integer(KEY_READ | wow64) });
		if (handles[1] != REG_SUCCESS) {
			return null;
		}
		byte[] valb = (byte[]) regQueryValueEx.invoke(root, new Object[] {
				new Integer(handles[0]), toCstr(value) });
		regCloseKey.invoke(root, new Object[] { new Integer(handles[0]) });
		return (valb != null ? new String(valb).trim() : null);
	}

	private static byte[] toCstr(String str) {
		byte[] result = new byte[str.length() + 1];

		for (int i = 0; i < str.length(); i++) {
			result[i] = (byte) str.charAt(i);
		}
		result[str.length()] = 0;
		return result;
	}

	/**
	 * Changes the video URL for the cameras with the given IP address
	 * 
	 * @param ip
	 *            address of geovision host
	 * @param newId
	 *            session ID to use in new URL
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	public static void replaceID(String ip, String newId)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException {
		List<String> keys = readStringSubKeys(systemRoot, HKEY_LOCAL_MACHINE,
				PREF_KEY, reg);
		if (keys == null) {
			// should only be 0 if we have not checked before
			if (reg == 0) {
				reg = KEY_WOW64_64KEY;
				keys = readStringSubKeys(systemRoot, HKEY_LOCAL_MACHINE,
						PREF_KEY, reg);
				if (keys == null) {
					reg = KEY_WOW64_32KEY;
					keys = readStringSubKeys(systemRoot, HKEY_LOCAL_MACHINE,
							PREF_KEY, reg);
				}

			}
		}
		if (keys == null) {
			throw new IllegalAccessException("Parent key not found:" + PREF_KEY);
		}
		for (String key : keys) {
			String camIp = readString(systemRoot, HKEY_LOCAL_MACHINE, PREF_KEY
					+ "\\" + key, "ip", reg);
			if (ip.equals(camIp)) {
				String oldurl = readString(systemRoot, HKEY_LOCAL_MACHINE,
						PREF_KEY + "\\" + key, "ip_path", reg);
				log.info("Read    " + key + ":" + camIp + ":" + oldurl);
				String newurl = oldurl.substring(0, 8) + newId;
				log.info("Writing " + key + ":" + camIp + ":" + newurl);
				writeStringValue(systemRoot, HKEY_LOCAL_MACHINE, PREF_KEY
						+ "\\" + key, "ip_path", newurl, reg);
				oldurl = readString(systemRoot, HKEY_LOCAL_MACHINE, PREF_KEY
						+ "\\" + key, "ip_path", reg);
				if (newurl.equals(oldurl)) {
					log.info("Updated    " + key + ":" + camIp + ":" + oldurl);

				} else {
					log.info("Failed     " + key + ":" + camIp + ":" + oldurl);
				}
			}
		}
	}

	public static void main(String[] args) throws BackingStoreException {
		try {
			RegUtil.replaceID("192.168.1.82",
					"v0s1b6f4a0b30fcca444-935d-4aec-86dd-68b33d267ffd");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
