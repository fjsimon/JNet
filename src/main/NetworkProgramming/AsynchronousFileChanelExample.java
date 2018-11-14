package main.NetworkProgramming;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.concurrent.Future;

public class AsynchronousFileChanelExample {


    public static void readFileFuture(String fileName) throws Exception {

        Path path = Paths.get(URI.create("file://" +
                System.getProperty("user.dir") +"/resources/" + fileName));

        AsynchronousFileChannel fileChannel = AsynchronousFileChannel.open(
                path, StandardOpenOption.READ);

        ByteBuffer buffer = ByteBuffer.allocate(1024);

        Future<Integer> operation = fileChannel.read(buffer, 0);

        // run other code as operation continues in background
        operation.get();

        String fileContent = new String(buffer.array()).trim();
        System.out.println(fileContent);
        buffer.clear();
        fileChannel.close();
    }

    public static void writeAndReadFuture() throws Exception {

        String fileName = "test.txt";
        Path path = Paths.get(URI.create("file://" +
                System.getProperty("user.dir") +"/resources/"+fileName));

        AsynchronousFileChannel fileChannel = AsynchronousFileChannel.open(
                path, StandardOpenOption.WRITE, StandardOpenOption.CREATE);

        ByteBuffer buffer = ByteBuffer.allocate(1024);

        buffer.put("hello world".getBytes());
        buffer.flip();

        Future<Integer> operation = fileChannel.write(buffer, 0);
        buffer.clear();

        //run other code as operation continues in background
        operation.get();

        readFileFuture(fileName);
    }

    public static void main(String... args) throws Exception {

        readFileFuture("file.txt");

        writeAndReadFuture();
    }
}
