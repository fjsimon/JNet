package com.fjsimon.java.network.programming;


import org.junit.jupiter.api.Test;

import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Looking at the common usage practices, we can see, for example, that
 *  PrintWriter is used to write formatted text,
 *  FileOutputStream to write binary data,
 *  DataOutputStream to write primitive data types,
 *  RandomAccessFile to write to a specific position,
 *  and FileChannel to write faster in larger files.
 */
class WriteToFileTests {

    @Test
    public void bufferedWritterTest() throws IOException {
        String str = "Hello";

        String fileName = "bufferedWriter.txt";

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + fileName));

        BufferedWriter writer = new BufferedWriter(new FileWriter(path.toFile()));

        writer.write(str);

        writer.close();
    }


    @Test
    public void printWriterTest() throws IOException {

        String fileName = "printWriter.txt";

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + fileName));

        FileWriter fileWriter = new FileWriter(path.toFile());

        PrintWriter printWriter = new PrintWriter(fileWriter);

        printWriter.print("Some String");
        printWriter.printf("Product name is %s and its price is %d $", "iPhone", 1000);
        printWriter.close();
    }

    @Test
    public void fileOutputStreamTest() throws IOException {

        String str = "Hello";
        String fileName = "fileOutputStream.txt";

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + fileName));

        FileOutputStream outputStream = new FileOutputStream(path.toFile());

        byte[] strToBytes = str.getBytes();
        outputStream.write(strToBytes);

        outputStream.close();
    }

    @Test
    public void dataOutputStreamTest() throws IOException {

        String value = "Hello";
        String fileName = "dataOutputStream.txt";

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + fileName));

        FileOutputStream fos = new FileOutputStream(path.toFile());

        DataOutputStream outStream = new DataOutputStream(new BufferedOutputStream(fos));

        outStream.writeUTF(value);
        outStream.close();

        // verify the results
        String result;
        FileInputStream fis = new FileInputStream(path.toFile());
        DataInputStream reader = new DataInputStream(fis);
        result = reader.readUTF();
        reader.close();

        assertEquals(value, result);
    }


    private void writeToPosition(String filename, int data, long position) throws IOException {

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + filename));

        RandomAccessFile writer = new RandomAccessFile(path.toFile(), "rw");
        writer.seek(position);
        writer.writeInt(data);
        writer.close();
    }

    private int readFromPosition(String filename, long position) throws IOException {
        int result = 0;

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + filename));

        RandomAccessFile reader = new RandomAccessFile(path.toFile(), "r");
        reader.seek(position);
        result = reader.readInt();
        reader.close();
        return result;
    }

    @Test
    public void randomAccessFileTest() throws IOException {

        int data1 = 2014;
        int data2 = 1500;

        String fileName = "randomAccessFile.txt";

        writeToPosition(fileName, data1, 4);
        assertEquals(data1, readFromPosition(fileName, 4));

        writeToPosition(fileName, data2, 4);
        assertEquals(data2, readFromPosition(fileName, 4));
    }

    @Test
    public void fileChannelTest() throws IOException {

        String fileName = "fileChannel.txt";

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + fileName));

        RandomAccessFile stream = new RandomAccessFile(path.toFile(), "rw");

        FileChannel channel = stream.getChannel();

        String value = "Hello & Bye";
        byte[] strBytes = value.getBytes();
        ByteBuffer buffer = ByteBuffer.allocate(strBytes.length);
        buffer.put(strBytes);
        buffer.flip();
        channel.write(buffer);
        stream.close();
        channel.close();

        // verify
        RandomAccessFile reader = new RandomAccessFile(path.toFile(), "r");
        assertEquals(value, reader.readLine());
        reader.close();
    }

    @Test
    public void givenUsingJava7_whenWritingToFile_thenCorrect() throws IOException {

        String str = "Hello";

        String fileName = "pathFiles.txt";

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + fileName));

        byte[] strToBytes = str.getBytes();

        Files.write(path, strToBytes);

        String read = Files.readAllLines(path).get(0);
        assertEquals(str, read);
    }

    @Test
    public void whenWriteToTmpFile_thenCorrect() throws IOException {

        String toWrite = "Hello";

        File tmpFile = File.createTempFile("tempFile" , ".tmp");

        FileWriter writer = new FileWriter(tmpFile);
        writer.write(toWrite);
        writer.close();

        BufferedReader reader = new BufferedReader(new FileReader(tmpFile));
        assertEquals(toWrite, reader.readLine());
        reader.close();
    }

    @Test
    public void whenTryToLockFile_thenItShouldBeLocked() throws IOException {

        String fileName = "pathFiles.txt";

        Path path = Paths.get(URI.create("file://" + System.getProperty("user.dir") +"/target/" + fileName));

        RandomAccessFile stream = new RandomAccessFile(path.toFile(), "rw");

        FileChannel channel = stream.getChannel();

        FileLock lock = null;
        try {
            lock = channel.tryLock();
        } catch (final OverlappingFileLockException e) {
            stream.close();
            channel.close();
        }
        stream.writeChars("test lock");
        lock.release();

        stream.close();
        channel.close();
    }


}