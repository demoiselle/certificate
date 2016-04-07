package br.gov.frameworkdemoiselle.certificate.util;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ZipBytes {

	private static Logger logger = LoggerFactory.getLogger(ZipBytes.class);
	private final static int BUFFER_SIZE = 4096;

	public static byte[] compressing(Map<String, byte[]> files) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ZipOutputStream zipOut = new ZipOutputStream(out);

		try {
			for (String fileName : files.keySet()) {
				logger.info("Adding file "+fileName+" to ZIP");
				zipOut.putNextEntry(new ZipEntry(fileName));
				zipOut.write(files.get(fileName));
				zipOut.setLevel(0);
				zipOut.closeEntry();
			}
			zipOut.close();
			out.close();

		} catch (IOException e) {
			new CertificateUtilException(e.getMessage(), e);
		}

		return out.toByteArray();
	}

	public static Map<String, byte[]> decompressing(byte[] file) {

		BufferedOutputStream dest = null;
		ZipEntry entry = null;

		Map<String, byte[]> files = new HashMap<String, byte[]>();

		InputStream in = new ByteArrayInputStream(file);
		ZipInputStream zipStream = new ZipInputStream(in);

		try {
			while ((entry = zipStream.getNextEntry()) != null) {
				int count;
				byte buf[] = new byte[BUFFER_SIZE];
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				dest = new BufferedOutputStream(outputStream, BUFFER_SIZE);
				while ((count = zipStream.read(buf, 0, BUFFER_SIZE)) != -1) {
					dest.write(buf, 0, count);
				}
				dest.flush();
				dest.close();
				files.put(entry.getName(), outputStream.toByteArray());
				zipStream.closeEntry();
			}
		} catch (IOException e) {
			new CertificateUtilException(e.getMessage(), e);
		}

		return files;
	}

}
