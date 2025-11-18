package net.lingala.zip4j;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.io.inputstream.ZipInputStream;
import net.lingala.zip4j.io.outputstream.ZipOutputStream;
import net.lingala.zip4j.model.FileHeader;
import net.lingala.zip4j.model.LocalFileHeader;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.CompressionLevel;
import net.lingala.zip4j.model.enums.CompressionMethod;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.utils.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class FuzzTests {
    /**
     * Verifies that data compressed by ZIP returns to its original state after decompression.
     */
    @FuzzTest
    public void fuzzRoundTrip(FuzzedDataProvider data) throws IOException {
        Path tempDir = Files.createTempDirectory("zip4j_fuzz");
        Path zipPath = tempDir.resolve("fuzz.zip");

        String filename = "data.bin";
        byte[] originalContent = data.consumeBytes(data.consumeInt(100, 5000));
        char[] password = data.consumeBoolean() ? data.consumeString(20).toCharArray() : null;

        ZipParameters params = generateRandomParams(data, password != null);
        params.setFileNameInZip(filename);

        try {
            try (ZipFile zipFile = new ZipFile(zipPath.toFile(), password)) {
                zipFile.addStream(new ByteArrayInputStream(originalContent), params);
            }

            try (ZipFile zipFile = new ZipFile(zipPath.toFile(), password)) {
                FileHeader fileHeader = zipFile.getFileHeader(filename);
                if (fileHeader == null) return;

                try (InputStream is = zipFile.getInputStream(fileHeader);
                     ByteArrayOutputStream extracted = new ByteArrayOutputStream()) {

                    byte[] buffer = new byte[4096];
                    int readLen;
                    while ((readLen = is.read(buffer)) != -1) {
                        extracted.write(buffer, 0, readLen);
                    }

                    if (!Arrays.equals(originalContent, extracted.toByteArray())) {
                        throw new RuntimeException("Data corruption: Content mismatch!");
                    }
                }
            }
        } catch (ZipException ignored) {
        } finally {
            cleanupDirectory(tempDir);
        }
    }

    /**
     * Constructs ZIP files with optional password protection and performs a random sequence
     * of operations on those archives.
     */
    @FuzzTest
    public void fuzzFileOperations(FuzzedDataProvider data) throws IOException {
        Path tempDir = Files.createTempDirectory("zip4j_fuzz_ops");
        Path zipPath = tempDir.resolve("fuzz.zip");
        Path extractRoot = tempDir.resolve("extracts");

        // Optional password protection
        char[] password = data.consumeBoolean() ?
                data.consumeString(20).toCharArray() : null;
        try (ZipFile zipFile = (password != null) ?
                new ZipFile(zipPath.toFile(), password) :
                new ZipFile(zipPath.toFile())) {

            // Perform random number of operations
            int operations = data.consumeInt(1, 10);
            for (int i = 0; i < operations; i++) {
                int opType = data.consumeInt(0, 8);
                try {
                    switch (opType) {
                        case 0:
                            addRandomFiles(zipFile, data, tempDir);
                        case 1:
                            addRandomFolder(zipFile, data, tempDir);
                        case 2:
                            addRandomStream(zipFile, data);
                        case 3:
                            removeRandomFile(zipFile);
                        case 4:
                            renameRandomFile(zipFile, data);
                        case 5:
                            zipFile.setComment(data.consumeString(20));
                        case 6:
                            extractAllOrSingle(zipFile, data, extractRoot);
                        case 7:
                            tryMergeSplit(zipFile, data, tempDir);
                        case 8:
                            triggerProgressMonitor(zipFile);
                    }
                } catch (ZipException | IllegalArgumentException ignored) {
                }
            }
        } catch (ZipException ignored) {
        } finally {
            cleanupDirectory(tempDir);
        }
    }

    /**
     * Fuzzes {@link ZipInputStream } by feeding arbitrary byte sequences and
     * optional password protection into the streaming ZIP parser.
     */
    @FuzzTest
    public void fuzzInputStream(FuzzedDataProvider data) {
        // Optional password protection
        boolean usePassword = data.consumeBoolean();
        char[] password = usePassword ? data.consumeString(20).toCharArray() : null;

        // Use various read buffer sizes
        int bufferSize = data.consumeInt(1, 4096);

        byte[] bytes = data.consumeRemainingAsBytes();
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);

        try (ZipInputStream zis = new ZipInputStream(bais, password)) {
            LocalFileHeader localFileHeader;
            while ((localFileHeader = zis.getNextEntry()) != null) {

                localFileHeader.getFileName();
                localFileHeader.getEncryptionMethod();

                byte[] buffer = new byte[bufferSize];
                while (zis.read(buffer) != -1) {
                }
            }
        } catch (IOException ignored) {
        }
    }

    /**
     * Fuzzes Zip4j decompressor to detect inputs that expand to extremely large
     * outputs relative to their size.
     */
    @FuzzTest
    public void fuzzDecompressionBomb(FuzzedDataProvider data) {
        final int MAX_EXPANSION_RATIO = 80;
        byte[] inputData = data.consumeRemainingAsBytes();
        long maxAllowedSize = (long) inputData.length * MAX_EXPANSION_RATIO + (1024 * 1024);

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(inputData))) {
            while ((zis.getNextEntry()) != null) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;

                while ((read = zis.read(buffer)) != -1) {
                    baos.write(buffer, 0, read);

                    // Check during streaming
                    if (baos.size() > maxAllowedSize) {
                        throw new RuntimeException("Zip Bomb detected");
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    /**
     * Fuzzes raw ZIP file parsing and validation logic by writing the fuzzer byte input to disk
     * and invoking various operations on it (validation, header enumeration, extraction).
     * <p>
     * Found an input to trigger {@link IndexOutOfBoundsException}
     */
    @FuzzTest
    public void fuzzRawParsingAndValidation(FuzzedDataProvider data) throws IOException {
        Path tempFile = Files.createTempFile("fuzz_raw_input", ".zip");
        File fuzzedZipFile = tempFile.toFile();

        // Create archive with fuzzer data
        byte[] inputData = data.consumeRemainingAsBytes();
        if (inputData.length < 10) {
            return;
        }
        Files.write(tempFile, inputData);

        // Validate and extract ZIP file
        Path out = Files.createTempDirectory("raw_out");
        try {
            ZipFile zipFile = new ZipFile(fuzzedZipFile);
            zipFile.isValidZipFile();
            zipFile.getFileHeaders();
            zipFile.extractAll(out.toString());
            zipFile.close();

        } catch (IOException | IllegalArgumentException ignored) {
        } finally {
            try {
                cleanupDirectory(out);
            } catch (Exception ignored) {}
            Files.deleteIfExists(tempFile);
        }
    }

    /**
     * Fuzzes split-archive creation and extraction logic.
     */
    @FuzzTest
    public void fuzzSplitOperations(FuzzedDataProvider data) throws IOException {
        Path tempDir = Files.createTempDirectory("zip4j_split_fuzz");
        // Minimum allowed split length in Zip4j is usually 65536
        long splitLength = 65536;

        try {
            File zipFileRaw = tempDir.resolve("split.zip").toFile();
            ZipFile zipFile = new ZipFile(zipFileRaw);

            // Create a split archive
            ZipParameters params = new ZipParameters();
            params.setEncryptFiles(data.consumeBoolean());
            if (params.isEncryptFiles()) {
                params.setEncryptionMethod(EncryptionMethod.AES);
                params.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
                zipFile.setPassword("splitPass".toCharArray());
            }

            // Generate enough data to force a split (multiple entries)
            int numFiles = data.consumeInt(2, 5);
            java.util.ArrayList<File> filesToAdd = new java.util.ArrayList<>();
            for(int i=0; i<numFiles; i++) {
                // Ensure data is large enough to trigger split logic periodically
                // consumeBytes takes one arg (maxLength).
                byte[] fileContent = data.consumeBytes((int)(splitLength / 2));

                String name = "file_" + i + ".dat";
                filesToAdd.add(createTestFile(tempDir, name, fileContent));
            }

            // Create split zip once with all files
            if (!filesToAdd.isEmpty()) {
                zipFile.createSplitZipFile(filesToAdd, params, true, splitLength);
            }

            // Now try to read it back using the InputStream logic
            // This triggers NumberedSplitInputStream
            if (zipFile.isValidZipFile()) {
                zipFile.extractAll(tempDir.resolve("out").toString());
            }

        } catch (Exception ignored) {
        } finally {
            cleanupDirectory(tempDir);
        }
    }

    /**
     * Fuzzes cross-compatibility between the Zip4j implementation and Apache Commons
     * Compress by compressing and decompressing fuzzer generated data using
     * both libraries and verifying that they produce identical results.
     */
    @FuzzTest
    public void fuzzCrossLibraryCompatibility(FuzzedDataProvider data) throws IOException {
        String zipEntryName = "data.bin";

        byte[] originalContent = data.consumeRemainingAsBytes();
        if (originalContent.length == 0) return;

        // Zip4j writes, Commons Compress reads
        Path zip4jZip = Files.createTempFile("zip4j_write", ".zip");
        try {
            // Write using Zip4j
            ZipFile zipFile = new ZipFile(zip4jZip.toFile());
            ZipParameters params = new ZipParameters();
            params.setFileNameInZip(zipEntryName);
            params.setEncryptFiles(false);

            zipFile.addStream(new ByteArrayInputStream(originalContent), params);

            // Read using Commons Compress
            try (ZipArchiveInputStream zis =
                         new ZipArchiveInputStream(Files.newInputStream(zip4jZip))) {
                ZipArchiveEntry entry = zis.getNextZipEntry();
                if (entry != null && entry.getName().equals(zipEntryName)) {
                    byte[] extracted = IOUtils.toByteArray(zis);

                    if (!Arrays.equals(originalContent, extracted)) {
                        throw new RuntimeException("Mismatch: Zip4j-write → Commons-read");
                    }
                }
            }
        } catch (IOException | IllegalArgumentException ignored) {
        } finally {
            Files.deleteIfExists(zip4jZip);
        }

        // Commons Compress writes, Zip4j reads
        Path commonsZip = Files.createTempFile("commons_write", ".zip");
        try {
            // Write using Commons Compress
            try (ZipArchiveOutputStream zaos =
                         new ZipArchiveOutputStream(Files.newOutputStream(commonsZip))) {

                ZipArchiveEntry entry = new ZipArchiveEntry(zipEntryName);
                entry.setSize(originalContent.length);
                zaos.putArchiveEntry(entry);
                zaos.write(originalContent);
                zaos.closeArchiveEntry();
                zaos.finish();
            }

            // Read using Zip4j
            try (ZipInputStream zis =
                         new ZipInputStream(Files.newInputStream(commonsZip))) {

                LocalFileHeader header = zis.getNextEntry();
                if (header != null && zipEntryName.equals(header.getFileName())) {
                    ByteArrayOutputStream extractedStream = new ByteArrayOutputStream();
                    IOUtils.copy(zis, extractedStream);

                    if (!Arrays.equals(originalContent, extractedStream.toByteArray())) {
                        throw new RuntimeException("Mismatch: Commons-write → Zip4j-read");
                    }
                }
            }

        } catch (IOException | IllegalArgumentException ignored) {
        } finally {
            Files.deleteIfExists(commonsZip);
        }
    }

    // ------------------------------------------- helper methods --------------------------------------------------- //

    private ZipParameters generateRandomParams(FuzzedDataProvider data, boolean hasPassword) {
        ZipParameters p = new ZipParameters();
        p.setCompressionMethod(data.pickValue(CompressionMethod.values()));
        p.setCompressionLevel(data.pickValue(CompressionLevel.values()));

        if (hasPassword) {
            p.setEncryptFiles(true);
            p.setEncryptionMethod(data.pickValue(EncryptionMethod.values()));
            p.setAesKeyStrength(data.pickValue(AesKeyStrength.values()));
        }
        return p;
    }

    private File createTestFile(Path dir, String name, byte[] content) throws IOException {
        Path p = dir.resolve(name);
        Files.write(p, content);
        return p.toFile();
    }

    private void addRandomFiles(ZipFile zip, FuzzedDataProvider data, Path base) throws IOException, ZipException {
        ZipParameters params = randomZipParameters(data);
        int count = data.consumeInt(1, 5);
        List<File> files = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Path f = base.resolve("added_" + data.consumeInt(0, 100000) + ".dat");
            Files.createDirectories(f.getParent());
            Files.write(f, data.consumeBytes(data.consumeInt(0, 256 * 1024)));
            files.add(f.toFile());
        }
        if (!files.isEmpty()) zip.addFiles(files, params);
    }

    private void extractAllOrSingle(ZipFile zip, FuzzedDataProvider data, Path root) throws ZipException, IOException {
        Path out = root.resolve("ex_" + data.consumeInt(0, 100000));
        Files.createDirectories(out);
        if (data.consumeBoolean() && !zip.getFileHeaders().isEmpty()) {
            var header = zip.getFileHeaders().get(0);
            zip.extractFile(header, out.toString());
        } else {
            zip.extractAll(out.toString());
        }
    }

    private void addRandomStream(ZipFile zip, FuzzedDataProvider data) throws IOException, ZipException {
        byte[] bytes = data.consumeBytes(data.consumeInt(0, 512 * 1024));
        ZipParameters p = randomZipParameters(data);
        p.setFileNameInZip("stream_" + data.consumeInt(0, 99999) + ".bin");
        zip.addStream(new ByteArrayInputStream(bytes), p);
    }

    private void addRandomFolder(ZipFile zip, FuzzedDataProvider data, Path base) throws IOException, ZipException {
        Path folder = base.resolve("folder_" + data.consumeInt(0, 10000));
        Files.createDirectories(folder);
        createRandomTree(folder, data, data.consumeInt(1, 6), 3);
        zip.addFolder(folder.toFile(), randomZipParameters(data));
    }

    private ZipParameters randomZipParameters(FuzzedDataProvider data) {
        ZipParameters p = new ZipParameters();
        p.setCompressionMethod(data.pickValue(CompressionMethod.values()));
        p.setCompressionLevel(data.pickValue(CompressionLevel.values()));
        boolean encrypt = data.consumeBoolean();
        p.setEncryptFiles(encrypt);
        if (encrypt) {
            p.setEncryptionMethod(data.pickValue(EncryptionMethod.values()));
            p.setAesKeyStrength(data.pickValue(AesKeyStrength.values()));
        }
        return p;
    }

    private void tryMergeSplit(ZipFile zip, FuzzedDataProvider data, Path tempDir) throws ZipException, IOException {
        if (zip.isSplitArchive()) {
            Path merged = tempDir.resolve("merged.zip");
            zip.mergeSplitFiles(merged.toFile());
        }
    }

    private void triggerProgressMonitor(ZipFile zip) {
        var pm = zip.getProgressMonitor();
        pm.getPercentDone();
        pm.getResult();
        pm.getState();
        pm.getWorkCompleted();
        pm.getTotalWork();
    }

    private void createRandomTree(Path root, FuzzedDataProvider data, int files, int depth) throws IOException {
        if (depth <= 0 || files <= 0) return;
        Files.createDirectories(root);
        for (int i = 0; i < files; i++) {
            Path f = root.resolve("f" + i + ".dat");
            Files.write(f, new byte[data.consumeInt(0, 64 * 1024)]);
        }
        if (depth > 1 && data.consumeBoolean()) {
            createRandomTree(root.resolve("sub"), data, files / 2, depth - 1);
        }
    }

    private void removeRandomFile(ZipFile zipFile) throws ZipException {
        if (!zipFile.isValidZipFile() || zipFile.getFileHeaders().isEmpty()) return;
        String fileName = zipFile.getFileHeaders().get(0).getFileName();
        zipFile.removeFile(fileName);
    }

    private void renameRandomFile(ZipFile zipFile, FuzzedDataProvider data) throws ZipException {
        if (!zipFile.isValidZipFile() || zipFile.getFileHeaders().isEmpty()) return;
        String fileName = zipFile.getFileHeaders().get(0).getFileName();
        zipFile.renameFile(fileName, "renamed_" + data.consumeString(5));
    }

    private void cleanupDirectory(Path dir) {
        try {
            if (Files.exists(dir)) {
                Files.walk(dir)
                        .sorted(Comparator.reverseOrder())
                        .map(Path::toFile)
                        .forEach(File::delete);
            }
        } catch (IOException e) {
        }
    }
}
